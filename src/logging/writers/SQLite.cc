// See the file "COPYING" in the main distribution directory for copyright.



#include "config.h"

#ifdef USE_SQLITE

#include <string>
#include <errno.h>

#include "../../NetVar.h"

#include "../../threading/SerialTypes.h"

#include <vector>

#include "SQLite.h"

using namespace logging;
using namespace writer;
using threading::Value;
using threading::Field;

SQLite::SQLite(WriterFrontend* frontend) : WriterBackend(frontend)
	{

	set_separator.assign(
			(const char*) BifConst::LogSQLite::set_separator->Bytes(),
			BifConst::LogAscii::set_separator->Len()
			);


	unset_field.assign(
			(const char*) BifConst::LogSQLite::unset_field->Bytes(),
			BifConst::LogAscii::unset_field->Len()
			);


	db = 0;

	io = new AsciiInputOutput(this, set_separator, unset_field);
	}

SQLite::~SQLite()
	{
	if ( db != 0 ) 
		{
		sqlite3_close(db);
		db = 0;
		}

	delete io;
	}

string SQLite::GetTableType(int arg_type, int arg_subtype) {

	string type;

	switch ( arg_type ) {

	case TYPE_BOOL:
		type = "boolean";
		break;

	case TYPE_INT:
	case TYPE_COUNT:
	case TYPE_COUNTER:
	case TYPE_PORT:
		type = "integer";
		break;

		/*
	case TYPE_PORT:
		type = "VARCHAR(10)";
		break;
*/

	case TYPE_SUBNET:
	case TYPE_ADDR:
		type = "text"; // sqlite3 does not have a type for internet addresses
		break;

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		type = "double precision";
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		type = "TEXT";
		break;

	case TYPE_TABLE:
	case TYPE_VECTOR:
		type = "text"; // dirty - but sqlite does not directly support arrays. so - we just roll it into a ","-separated string I guess.
		//type = GetTableType(arg_subtype, 0) + "[]";
		break;

	default:
		Error(Fmt("unsupported field format %d ", arg_type));
		return "";
	}

	return type;
}


bool SQLite::checkError( int code ) 
	{
	if ( code != SQLITE_OK && code != SQLITE_DONE )
		{
		Error(Fmt("SQLite call failed: %s", sqlite3_errmsg(db)));
		return true;
		}

	return false;	
	}

bool SQLite::DoInit(const WriterInfo& info, int num_fields,
			    const Field* const * fields)
	{

	string fullpath(info.path);
	fullpath.append(".sqlite");
	string dbname;

	map<const char*, const char*>::const_iterator it = info.config.find("dbname");
	if ( it == info.config.end() ) {
		MsgThread::Info(Fmt("dbname configuration option not found. Defaulting to path %s", info.path));
		dbname = info.path;
	} else {
		dbname = it->second;
	}


	if ( checkError(sqlite3_open_v2(
					fullpath.c_str(),
					&db,
					SQLITE_OPEN_READWRITE | 
					SQLITE_OPEN_CREATE |
					SQLITE_OPEN_FULLMUTEX // perhaps change to nomutex
					,
					NULL)) )
		return false;

	string create = "CREATE TABLE IF NOT EXISTS "+dbname+" (\n"; // yes. using path here is stupid. open for better ideas.
		//"id SERIAL UNIQUE NOT NULL"; // SQLite has rowids, we do not need a counter here.

	for ( int i = 0; i < num_fields; ++i )
		{
			const Field* field = fields[i];
			
			if ( i != 0 ) 
				create += ",\n";

			string fieldname = fields[i]->name;
			replace( fieldname.begin(), fieldname.end(), '.', '_' ); // sqlite does not like "." in row names.
			create += fieldname;

			string type = GetTableType(field->type, field->subtype);

			create += " "+type;
			/* if ( !field->optional ) {
				create += " NOT NULL";
			} */

		}

	create += "\n);";

	//printf("Create: %s\n", create.c_str());

		{
		char *errorMsg = 0;
		int res = sqlite3_exec(db, create.c_str(), NULL, NULL, &errorMsg);
		if ( res != SQLITE_OK ) 
			{
			//printf("Error executing table creation statement: %s", errorMsg);
			Error(Fmt("Error executing table creation statement: %s", errorMsg));
			sqlite3_free(errorMsg);
			return false;
			}
		}


		{
		// create the prepared statement that will be re-used forever...

		string insert = "VALUES (";
		string names = "INSERT INTO "+dbname+" ( ";
	
		for ( int i = 0; i < num_fields; i++ )
			{
			bool ac = true;

			if ( i == 0 ) {
				ac = false;
			} else {
				names += ", ";
				insert += ", ";
			}

			insert += "?";	

			string fieldname = fields[i]->name;
			replace( fieldname.begin(), fieldname.end(), '.', '_' ); // sqlite does not like "." in row names.
			names += fieldname;

		}
		insert += ");";
		names += ") ";

		insert = names + insert;
		//printf("Prepared insert: %s\n\n", insert.c_str());

		if ( checkError(sqlite3_prepare_v2( db, insert.c_str(), insert.size()+1, &st, NULL )) )
			return false;
		}

	return true;
	}

// Format String
char* SQLite::FS(const char* format, ...) {
	char * buf;

	va_list al;
	va_start(al, format);
	int n = vasprintf(&buf, format, al);
	va_end(al);

	assert(n >= 0);

	return buf;
}

int SQLite::AddParams(Value* val, int pos)
	{

	if ( ! val->present )
		{
			return sqlite3_bind_null(st, pos);
		}

	switch ( val->type ) {

	case TYPE_BOOL:
		return sqlite3_bind_int(st, pos, val->val.int_val ? 1 : 0 );

	case TYPE_INT:
		return sqlite3_bind_int(st, pos, val->val.int_val);

	case TYPE_COUNT:
	case TYPE_COUNTER:
		return sqlite3_bind_int(st, pos, val->val.uint_val);

	case TYPE_PORT:
		return sqlite3_bind_int(st, pos, val->val.port_val.port);

	case TYPE_SUBNET:
		{
		string out = io->Render(val->val.subnet_val).c_str();
		return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
		}

	case TYPE_ADDR:
		{
		string out = io->Render(val->val.addr_val).c_str();			
		return sqlite3_bind_text(st, pos, out.data(), out.size(), SQLITE_TRANSIENT);
		}

	case TYPE_TIME:
	case TYPE_INTERVAL:
	case TYPE_DOUBLE:
		return sqlite3_bind_double(st, pos, val->val.double_val);

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC:
		{
		if ( ! val->val.string_val.length || val->val.string_val.length == 0 ) 
			return sqlite3_bind_null(st, pos);

		return sqlite3_bind_text(st, pos, val->val.string_val.data, val->val.string_val.length, SQLITE_TRANSIENT); // FIXME who deletes this
		}

	case TYPE_TABLE:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator);

		for ( int j = 0; j < val->val.set_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator);

			io->ValToODesc(&desc, val->val.set_val.vals[j], NULL); 
			// yes, giving NULL here is not really really pretty....
			// it works however, because tables cannot contain tables...
			// or vectors.
			}
		desc.RemoveEscapeSequence(set_separator);		
		return sqlite3_bind_text(st, pos, (const char*) desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
		}

	case TYPE_VECTOR:
		{
		ODesc desc;
		desc.Clear();		
		desc.AddEscapeSequence(set_separator);

		for ( int j = 0; j < val->val.vector_val.size; j++ )
			{
			if ( j > 0 )
				desc.AddRaw(set_separator);

			io->ValToODesc(&desc, val->val.vector_val.vals[j], NULL);
			}

		desc.RemoveEscapeSequence(set_separator);		

		return sqlite3_bind_text(st, pos, (const char*) desc.Bytes(), desc.Len(), SQLITE_TRANSIENT);
		}



	default:
		Error(Fmt("unsupported field format %d", val->type ));
		return 0;
	}
	}

bool SQLite::DoWrite(int num_fields, const Field* const * fields, Value** vals)
	{

	// bind parameters
	for ( int i = 0; i < num_fields; i++ ) 
		{
		if ( checkError(AddParams(vals[i], i+1)) ) 
			return false;
		}

	// execute query
	if ( checkError(sqlite3_step(st)) )
		return false;

	// clean up and make ready for next query execution
	if ( checkError(sqlite3_clear_bindings(st)) ) 
		return false;

	if ( checkError(sqlite3_reset(st)) )
		return false;


	return true;
	}

#endif /* USE_SQLITE */