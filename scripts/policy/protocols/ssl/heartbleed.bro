##! Detect the TLS heartbleed attack. See http://heartbleed.com for more.

@load base/protocols/ssl
@load base/frameworks/notice

module Heartbleed;


export {
	redef enum Notice::Type += {
		## Indicates that a host performing a heartbleed attack.
		SSL_Heartbeat_Attack,
		## Indicates that a host performing a heartbleed attack was probably successful.
		SSL_Heartbeat_Attack_Success,
		## Indicates we saw heartbeat requests with odd length. Probably an attack.
		SSL_Heartbeat_Odd_Length,
		## Indicates we saw many heartbeat requests without an reply. Might be an attack.
		SSL_Heartbeat_Many_Requests,
		SSL_Heartbeat_Scan,
		SSL_Unknown_Key
	};
}

# Do not disable analyzers after detection - otherwhise we will not notice
# encrypted attacks.
redef SSL::disable_analyzer_after_detection=F;

type min_length: record {
	cipher: pattern;
	min_length: count;
};

global min_lengths: vector of min_length = vector();
global min_lengths_12: vector of min_length = vector();

redef record SSL::Info += {
	last_originator_heartbeat_request_size: count &optional;
	last_responder_heartbeat_request_size: count &optional;
	clear_originator_heartbeats: count &default=0 &log;
	clear_responder_heartbeats: count &default=0 &log;
	originator_heartbeats: count &default=0 &log;
	responder_heartbeats: count &default=0 &log;
	originator_heartbeat_bytes: count &default=0 &log;
	responder_heartbeat_bytes: count &default=0 &log;

	heartbleed_detected: bool &default=F;

	enc_appdata_packages: count &default=0;
	enc_appdata_bytes: count &default=0;
	};

# content types:
const	CHANGE_CIPHER_SPEC = 20;
const	ALERT = 21;
const	HANDSHAKE = 22;
const	APPLICATION_DATA = 23;
const	HEARTBEAT = 24;
const	V2_ERROR = 300;
const	V2_CLIENT_HELLO = 301;
const	V2_CLIENT_MASTER_KEY = 302;
const	V2_SERVER_HELLO = 304;

event bro_init()
	{
	# Minimum length a heartbeat packet must have for different cipher suites.
	# Note - tls 1.1f and 1.0 have different lengths :(
	min_lengths_12[|min_lengths_12|] = [$cipher=/_AES_256_GCM_SHA384$/, $min_length=43];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_AES_128_GCM_SHA256$/, $min_length=43];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_256_CBC_SHA384$/, $min_length=96];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_256_CBC_SHA256$/, $min_length=80];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_256_CBC_SHA$/, $min_length=64];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_128_CBC_SHA256$/, $min_length=80];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_128_CBC_SHA$/, $min_length=64];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_3DES_EDE_CBC_SHA$/, $min_length=48];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_SEED_CBC_SHA$/, $min_length=64];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_IDEA_CBC_SHA$/, $min_length=48];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_DES_CBC_SHA$/, $min_length=48];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_DES40_CBC_SHA$/, $min_length=48];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_RC4_128_SHA$/, $min_length=39];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_RC4_128_MD5$/, $min_length=35];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_RC4_40_MD5$/, $min_length=35];
	min_lengths_12[|min_lengths_12|] = [$cipher=/_RC2_CBC_40_MD5$/, $min_length=48];
	min_lengths[|min_lengths|] = [$cipher=/_256_CBC_SHA$/, $min_length=48];
	min_lengths[|min_lengths|] = [$cipher=/_128_CBC_SHA$/, $min_length=48];
	min_lengths[|min_lengths|] = [$cipher=/_3DES_EDE_CBC_SHA$/, $min_length=40];
	min_lengths[|min_lengths|] = [$cipher=/_SEED_CBC_SHA$/, $min_length=48];
	min_lengths[|min_lengths|] = [$cipher=/_IDEA_CBC_SHA$/, $min_length=40];
	min_lengths[|min_lengths|] = [$cipher=/_DES_CBC_SHA$/, $min_length=40];
	min_lengths[|min_lengths|] = [$cipher=/_DES40_CBC_SHA$/, $min_length=40];
	min_lengths[|min_lengths|] = [$cipher=/_RC4_128_SHA$/, $min_length=39];
	min_lengths[|min_lengths|] = [$cipher=/_RC4_128_MD5$/, $min_length=35];
	min_lengths[|min_lengths|] = [$cipher=/_RC4_40_MD5$/, $min_length=35];
	min_lengths[|min_lengths|] = [$cipher=/_RC2_CBC_40_MD5$/, $min_length=40];
	}

event ssl_heartbeat(c: connection, is_orig: bool, length: count, heartbeat_type: count, payload_length: count, payload: string)
	{
	local duration = network_time() - c$start_time;

	if ( is_orig )
		{
		++c$ssl$clear_originator_heartbeats;
		c$ssl$originator_heartbeat_bytes += payload_length;
		}
	else
		{
		++c$ssl$clear_responder_heartbeats;
		c$ssl$responder_heartbeat_bytes += payload_length;
		}

	if ( heartbeat_type == 1 )
		{
		local checklength: count = (length<(3+16)) ? length : (length - 3 - 16);

		if ( payload_length > checklength )
			{
			c$ssl$heartbleed_detected = T;
			NOTICE([$note=SSL_Heartbeat_Attack,
				$msg=fmt("An TLS heartbleed attack was detected! Record length %d. Payload length %d. Time: %f", length, payload_length, duration),
				$conn=c,
				$identifier=cat(c$uid, length, payload_length)
				]);
			}
		else if ( is_orig && length < 19 )
			{
			NOTICE([$note=SSL_Heartbeat_Scan,
				$msg=fmt("Heartbeat message smaller than minimum length required by protocol. Probable scan. Message length: %d. Payload length: %d. Time: %f", length, payload_length, duration),
				$conn=c,
				$n=length,
				$identifier=cat(c$uid, length)
				]);
			}
		}

	if ( heartbeat_type == 2 && c$ssl$heartbleed_detected )
		{
			NOTICE([$note=SSL_Heartbeat_Attack_Success,
				$msg=fmt("An TLS heartbleed attack detected before was probably exploited. Transmitted payload length in first packet: %d. Time: %f", payload_length, duration),
				$conn=c,
				$identifier=c$uid
				]);
		}

		NOTICE([$note=SSL_Heartbeat_Scan,
			$msg=fmt("Heartbeat message before encryption. Message length: %d. Payload length: %d. Time: %f", length, payload_length, duration),
			$conn=c,
			$identifier=c$uid
			]);

	}

event ssl_encrypted_heartbeat(c: connection, is_orig: bool, length: count)
	{
	if ( is_orig )
		{
		++c$ssl$originator_heartbeats;
		c$ssl$originator_heartbeat_bytes += length;
		}
	else
		{
		++c$ssl$responder_heartbeats;
		c$ssl$responder_heartbeat_bytes += length;
		}

	local duration = network_time() - c$start_time;

	if ( c$ssl$enc_appdata_packages == 0 )
			NOTICE([$note=SSL_Heartbeat_Scan,
				$msg=fmt("Seeing heartbeat request in connection before ciphertext was seen. Probable attack or scan. Length: %d, is_orig: %d. Time: %f", length, is_orig, duration),
				$conn=c,
				$n=length,
				$identifier=fmt("%s%s", c$uid, "early")
				]);
	else if ( duration < 1min )
			NOTICE([$note=SSL_Heartbeat_Scan,
				$msg=fmt("Seeing heartbeat request in connection within first minute. Possible attack or scan. Length: %d, is_orig: %d. Time: %f", length, is_orig, duration),
				$conn=c,
				$n=length,
				$identifier=fmt("%s%s", c$uid, "early")
				]);

	if ( c$ssl$originator_heartbeats > c$ssl$responder_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("Seeing more than 3 heartbeat requests without replies from server. Possible attack. Client count: %d, server count: %d. Time: %f", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats, duration),
				$conn=c,
				$n=(c$ssl$originator_heartbeats-c$ssl$responder_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( c$ssl$responder_heartbeats > c$ssl$originator_heartbeats + 3 )
			NOTICE([$note=SSL_Heartbeat_Many_Requests,
				$msg=fmt("Server is sending more heartbleed responsed than requests were seen. Possible attack. Client count: %d, server count: %d. Time: %f", c$ssl$originator_heartbeats, c$ssl$responder_heartbeats, duration),
				$conn=c,
				$n=(c$ssl$originator_heartbeats-c$ssl$responder_heartbeats),
				$identifier=fmt("%s%d", c$uid, c$ssl$responder_heartbeats/1000) # re-throw every 1000 heartbeats
				]);

	if ( is_orig && length < 19 )
			NOTICE([$note=SSL_Heartbeat_Odd_Length,
				$msg=fmt("Heartbeat message smaller than minimum required length. Probable attack. Message length: %d. Time: %f", length, duration),
				$conn=c,
				$n=length,
				$identifier=fmt("%s-weak-%d", c$uid, length)
				]);

	local cipherstring = SSL::cipher_desc[c$ssl$cipher];

	# Examine request lengths based on used cipher...
	local match=F;
	local min_length_choice: vector of min_length;
	if ( c$ssl$version > 769 ) # tls 1.1+ have different lengths for CBC
		min_length_choice = min_lengths_12;
	else
		min_length_choice = min_lengths;

	for ( i in min_length_choice )
		{
		if ( min_length_choice[i]$cipher in cipherstring )
			{
			match=T;

			if ( length < min_length_choice[i]$min_length )
				{
				NOTICE([$note=SSL_Heartbeat_Odd_Length,
					$msg=fmt("Heartbeat message smaller than minimum required length. Probable attack. Message length: %d. Required length: %d. Cipher match: %s. Version: %d. Time: %f", length, min_length_choice[i]$min_length, min_length_choice[i]$cipher, c$ssl$version, duration),
					$conn=c,
					$n=length,
					$identifier=fmt("%s-weak-cipher%d", c$uid, length)
					]);
				print "yes";
				}

			break;
			}

		}

	if ( match == F )
		{
		NOTICE([$note=SSL_Unknown_Key,
			$msg=fmt("Heartbeat with unknown ciphersuite, look manually. Ciphersuite: %d(%s), length: %d, Time: %f", c$ssl$cipher, cipherstring, length, duration),
			$conn=c,
			$identifier=fmt("%s-cipher-%d", c$uid, c$ssl$cipher) # re-throw every 1000 heartbeats
			]);
		}

	if ( is_orig )
		{
		if ( c$ssl?$last_responder_heartbeat_request_size )
			{
			# server originated heartbeat. Ignore & continue
			delete c$ssl$last_responder_heartbeat_request_size;
			}

		else
			c$ssl$last_originator_heartbeat_request_size = length;
		}
	else
		{
		if ( c$ssl?$last_originator_heartbeat_request_size && c$ssl$last_originator_heartbeat_request_size < length )
			{
			NOTICE([$note=SSL_Heartbeat_Attack_Success,
				$msg=fmt("An Encrypted TLS heartbleed attack was probably detected! First packet client record length %d, first packet server record length %d. Time: %f",
					c$ssl$last_originator_heartbeat_request_size, length, duration),
				$conn=c,
				$identifier=c$uid # only throw once per connection
				]);
			}

		else if ( ! c$ssl?$last_originator_heartbeat_request_size )
			c$ssl$last_responder_heartbeat_request_size = length;

		if ( c$ssl?$last_originator_heartbeat_request_size )
			delete c$ssl$last_originator_heartbeat_request_size;
		}
	}

event ssl_encrypted_data(c: connection, content_type: count, is_orig: bool, length: count)
	{
	if ( content_type == HEARTBEAT )
		event ssl_encrypted_heartbeat(c, is_orig, length);
	else if ( content_type == APPLICATION_DATA )
		{
		++c$ssl$enc_appdata_packages;
		c$ssl$enc_appdata_bytes += length;
		}
	}
