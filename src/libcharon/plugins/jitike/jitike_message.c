/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/rsa.h>

#include "jitike_crypto.h"
#include "jitike_message.h"
#include "jitike_redis.h"
#include "jitike_hiredis.h"
#include "jitike_db.h"

#include <daemon.h>

/**
 * Retrieve a keyid from the REDIS_KEYPATH hashset
 * NOTE: Memory for the returned char * needs to be freed by the caller
 *
 * @param ctx		The redisContext to use to send the message to
 * @param keyid_type	One of "previous", "current" or "future"
 * @return char *       The caller needs to free the memory
 */
static char* redis_get_keyid(redisContext *ctx, const char *keyid_type)
{
	char *keyid = NULL;
	redisReply *reply = NULL;

	reply = jitikeRedisCommand(ctx, "HGET %s %s", REDIS_KEYPATH, keyid_type);

	/**
	 * jitikeRedisCommand can return NULL if Redis is uncreachable.
	 */
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "redis_get_keyid: jitikeRedisCommand return NULL while running HGET, failing");
		goto out;
	}

	if (reply->type == REDIS_REPLY_NIL)
	{
		DBG1(DBG_CFG, "redis_get_keyid: Encryption keys not found in redis, returning NULL");
		goto out;
	}

	if (reply->type != REDIS_REPLY_STRING)
	{
		DBG1(DBG_CFG, "redis_get_keyid: Found invalid reply type for KEYID type %s: %s",
			keyid_type, reply->type);
	}
	else
	{
		keyid = malloc(reply->len+1);
		memcpy(keyid, reply->str, reply->len);
		keyid[reply->len] = '\0';
		DBG2(DBG_CFG, "redis_get_keyid: %s", keyid);
	}

out:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return keyid;
}

RSA *get_current_encryption_key(redisContext *ctx)
{
	RSA *enc_key = NULL;
	char *keyid = NULL;

	keyid = redis_get_keyid(ctx, "current");
	if (keyid != NULL)
	{
		char enc_key_path[PATH_MAX] = {};
		if (get_encryption_key_path(keyid, enc_key_path))
		{
			enc_key = get_encryption_key(enc_key_path);
		}

		free(keyid);
	}

	return enc_key;
}

/**
 * See header.
 */
void add_attribute(redisContext *ctx, char *key, char *field, jitike_message_attribute_t attribute, ...)
{
	size_t len;
	va_list args;
	redisReply *reply = NULL;

	va_start(args, attribute);
	switch (attribute)
	{
		/* ike_sa_id_t* */
		case JITIKE_IKE_ID:
		case JITIKE_IKE_REKEY_ID:
		{
			ike_sa_id_encoding_t enc;
			ike_sa_id_t *id;

			id = va_arg(args, ike_sa_id_t*);
			enc.initiator = id->is_initiator(id);
			enc.ike_version = id->get_ike_version(id);
			enc.initiator_spi = id->get_initiator_spi(id);
			enc.responder_spi = id->get_responder_spi(id);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %b", key, field,
					&enc, sizeof(ike_sa_id_encoding_t));
			}

			break;
		}
		/* identification_t* */
		case JITIKE_LOCAL_ID:
		case JITIKE_REMOTE_ID:
		case JITIKE_REMOTE_EAP_ID:
		{
			char *buf;
			identification_encoding_t *enc;
			identification_t *id;
			chunk_t data;

			id = va_arg(args, identification_t*);
			data = id->get_encoding(id);
			buf = malloc(sizeof(identification_encoding_t) + data.len);
			enc = (identification_encoding_t *)buf;
			enc->type = id->get_type(id);
			enc->len = data.len;
			memcpy(enc->encoding, data.ptr, data.len);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %b", key, field,
						enc, sizeof(identification_encoding_t)+data.len);
			}
			free(buf);

			break;
		}
		/* host_t* */
		case JITIKE_LOCAL_ADDR:
		case JITIKE_REMOTE_ADDR:
		case JITIKE_LOCAL_VIP:
		case JITIKE_REMOTE_VIP:
		case JITIKE_PEER_ADDR:
		{
			char *buf;
			host_encoding_t *enc;
			host_t *host;
			chunk_t data;

			host = va_arg(args, host_t*);
			data = host->get_address(host);
			buf = malloc(sizeof(host_encoding_t) + data.len);
			enc = (host_encoding_t *)buf;
			enc->family = host->get_family(host);
			enc->port = host->get_port(host);
			memcpy(enc->encoding, data.ptr, data.len);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %b", key, field,
					enc, sizeof(host_encoding_t)+data.len);
			}
			free(buf);

			break;
		}
		/* char* */
		case JITIKE_CONFIG_NAME:
		case JITIKE_ALLOC_ID:
		case JITIKE_JITID:
		{
			char *str;

			str = va_arg(args, char*);
			len = strlen(str) + 1;

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %s", key, field, str);
			}

			break;
		}
		/* uint8_t */
		case JITIKE_IKE_VERSION:
		case JITIKE_INITIATOR:
		case JITIKE_IPSEC_MODE:
		case JITIKE_IPCOMP:
		{
			uint8_t val;

			val = va_arg(args, u_int);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %d", key, field, val);
			}

			break;
		}
		/* uint16_t */
		case JITIKE_ALG_DH:
		case JITIKE_ALG_PRF:
		case JITIKE_ALG_OLD_PRF:
		case JITIKE_ALG_ENCR:
		case JITIKE_ALG_ENCR_LEN:
		case JITIKE_ALG_INTEG:
		case JITIKE_INBOUND_CPI:
		case JITIKE_OUTBOUND_CPI:
		case JITIKE_SEGMENT:
		case JITIKE_ESN:
		case JITIKE_AUTH_METHOD:
		{
			uint16_t val;

			val = va_arg(args, u_int);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %d", key, field, val);
			}

			break;
		}
		/** uint32_t */
		case JITIKE_CONDITIONS:
		case JITIKE_EXTENSIONS:
		case JITIKE_INBOUND_SPI:
		case JITIKE_OUTBOUND_SPI:
		case JITIKE_INIT_MID:
		case JITIKE_RESP_MID:
		{
			uint32_t val;

			val = va_arg(args, u_int);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %d", key, field, val);
			}

			break;
		}
		/** chunk_t */
		case JITIKE_NONCE_I:
		case JITIKE_NONCE_R:
		case JITIKE_SECRET:
		case JITIKE_LOCAL_DH:
		case JITIKE_REMOTE_DH:
		case JITIKE_PSK:
		case JITIKE_IV:
		case JITIKE_OLD_SKD:
		{
			chunk_t chunk;

			chunk = va_arg(args, chunk_t);

			if (ctx != NULL) {
				chunk_encoding_t *enc;
				enc = malloc(sizeof(chunk_encoding_t) + chunk.len);
				enc->len = chunk.len;
				memcpy(enc->encoding, chunk.ptr, chunk.len);

				reply = jitikeRedisCommand(ctx, "HSET %s %s %b", key, field,
					enc, sizeof(chunk_encoding_t) + enc->len);
				free(enc);
			}

			break;
		}
		/** traffic_selector_t */
		case JITIKE_LOCAL_TS:
		case JITIKE_REMOTE_TS:
		{
			char *buf;
			ts_encoding_t *enc;
			traffic_selector_t *ts;
			chunk_t data;

			ts = va_arg(args, traffic_selector_t*);
			data = chunk_cata("cc", ts->get_from_address(ts),
							  ts->get_to_address(ts));
			buf = malloc(sizeof(ts_encoding_t) + data.len);
			enc = (ts_encoding_t *)buf;
			enc->type = ts->get_type(ts);
			enc->protocol = ts->get_protocol(ts);
			enc->from_port = ts->get_from_port(ts);
			enc->to_port = ts->get_to_port(ts);
			enc->dynamic = ts->is_dynamic(ts);
			memcpy(enc->encoding, data.ptr, data.len);

			if (ctx != NULL) {
				reply = jitikeRedisCommand(ctx, "HSET %s %s %b", key, field,
					enc, sizeof(ts_encoding_t)+data.len);
			}
			free(buf);

			break;
		}
		/** crypto keys */
		case JITIKE_IN_AUTH_KEY:
		case JITIKE_OUT_AUTH_KEY:
		case JITIKE_IN_AEAD_KEY:
		case JITIKE_OUT_AEAD_KEY:
		case JITIKE_IN_CRYPTO_KEY:
		case JITIKE_OUT_CRYPTO_KEY:
		{
			if (ctx == NULL) break;

			chunk_t chunk;
			chunk = va_arg(args, chunk_t);

			chunk_t hex;
			hex = chunk_to_hex(chunk, NULL, FALSE);

			RSA *enc_key = NULL;
			enc_key = get_current_encryption_key(ctx);

			if (enc_key != NULL)
			{
				char *encrypted = NULL;
				if (encrypt_chunk(hex, enc_key, &encrypted))
				{
					add_attribute(ctx, key, JI_REDIS_ENCRYPTION_KEY_ID, JITIKE_REDIS_ENCRYPTION_KEY_ID);
					reply = jitikeRedisCommand(ctx, "HSET %s %s %s", key, field, encrypted);
					free(encrypted);
				}
				RSA_free(enc_key);
				if (reply != NULL) goto out;
			}

			/* Either enc_key is NULL, or encryption failed, or jitikeRedisCommand returned NULL */
			ike_sa_t *ike_sa = NULL;
			ike_sa = charon->bus->get_sa(charon->bus);
			if (ike_sa != NULL)
			{
				DBG0(DBG_CFG, "add_attribute: Setting fatal condition: unable to encrypt %s", field);
				ike_sa->set_condition(ike_sa, COND_FATAL, TRUE);
			}

out:
			chunk_free(&hex);
			break;
		}
		case JITIKE_REDIS_ENCRYPTION_KEY_ID:
		{
			if (ctx != NULL)
			{
				char *keyid = NULL;
				keyid = redis_get_keyid(ctx, "current");
				if (keyid != NULL)
				{
					reply = jitikeRedisCommand(ctx, "HSET %s %s %s", key, field, keyid);
					free(keyid);
				}
			}

			break;
		}

		default:
		{
			DBG1(DBG_CFG, "add_attribute: unable to encode, attribute %d / %s unknown", attribute, field);
			break;
		}
	}
	va_end(args);

	if (reply != NULL)
	{
		freeReplyObject(reply);
	}
}

/**
 * See header.
 */
void add_redis_buffer(redisContext *ctx, char * key, char *field, jitike_message_attribute_t attribute, ...)
{
	size_t len;
	va_list args;
	int ret;
	char *buf;

	va_start(args, attribute);
	switch (attribute)
	{
		/* ike_sa_id_t* */
		case JITIKE_IKE_ID:
		case JITIKE_IKE_REKEY_ID:
		{
			ike_sa_id_encoding_t enc;
			ike_sa_id_t *id;

			id = va_arg(args, ike_sa_id_t*);
			enc.initiator = id->is_initiator(id);
			enc.ike_version = id->get_ike_version(id);
			enc.initiator_spi = id->get_initiator_spi(id);
			enc.responder_spi = id->get_responder_spi(id);

			ret = redisFormatCommand(&buf, "HSET %s %s %b", key, field, &enc, sizeof(ike_sa_id_encoding_t));

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			break;
		}
		/* identification_t* */
		case JITIKE_LOCAL_ID:
		case JITIKE_REMOTE_ID:
		case JITIKE_REMOTE_EAP_ID:
		{
			char *tbuf;
			identification_encoding_t *enc;
			identification_t *id;
			chunk_t data;

			id = va_arg(args, identification_t*);
			data = id->get_encoding(id);
			tbuf = malloc(sizeof(identification_encoding_t) + data.len);
			enc = (identification_encoding_t *)tbuf;
			enc->type = id->get_type(id);
			enc->len = data.len;
			memcpy(enc->encoding, data.ptr, data.len);

			ret = redisFormatCommand(&buf, "HSET %s %s %b", key, field, enc, sizeof(identification_encoding_t)+data.len);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			free(tbuf);

			break;
		}
		/* host_t* */
		case JITIKE_LOCAL_ADDR:
		case JITIKE_REMOTE_ADDR:
		case JITIKE_LOCAL_VIP:
		case JITIKE_REMOTE_VIP:
		case JITIKE_PEER_ADDR:
		{
			char *tbuf;
			host_encoding_t *enc;
			host_t *host;
			chunk_t data;

			host = va_arg(args, host_t*);
			data = host->get_address(host);
			tbuf = malloc(sizeof(host_encoding_t) + data.len);
			enc = (host_encoding_t *)tbuf;
			enc->family = host->get_family(host);
			enc->port = host->get_port(host);
			memcpy(enc->encoding, data.ptr, data.len);

			ret = redisFormatCommand(&buf, "HSET %s %s %b", key, field, enc, sizeof(host_encoding_t)+data.len);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			free(tbuf);

			break;
		}
		/* char* */
		case JITIKE_CONFIG_NAME:
		case JITIKE_ALLOC_ID:
		case JITIKE_JITID:
		{
			char *str;

			str = va_arg(args, char*);
			len = strlen(str) + 1;

			ret = redisFormatCommand(&buf, "HSET %s %s %s", key, field, str);

			if (ret != 1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			break;
		}
		/* uint8_t */
		case JITIKE_IKE_VERSION:
		case JITIKE_INITIATOR:
		case JITIKE_IPSEC_MODE:
		case JITIKE_IPCOMP:
		{
			uint8_t val;

			val = va_arg(args, u_int);

			ret = redisFormatCommand(&buf, "HSET %s %s %d", key, field, val);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			break;
		}
		/* uint16_t */
		case JITIKE_ALG_DH:
		case JITIKE_ALG_PRF:
		case JITIKE_ALG_OLD_PRF:
		case JITIKE_ALG_ENCR:
		case JITIKE_ALG_ENCR_LEN:
		case JITIKE_ALG_INTEG:
		case JITIKE_INBOUND_CPI:
		case JITIKE_OUTBOUND_CPI:
		case JITIKE_SEGMENT:
		case JITIKE_ESN:
		case JITIKE_AUTH_METHOD:
		{
			uint16_t val;

			val = va_arg(args, u_int);

			ret = redisFormatCommand(&buf, "HSET %s %s %d", key, field, val);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			break;
		}
		/** uint32_t */
		case JITIKE_CONDITIONS:
		case JITIKE_EXTENSIONS:
		case JITIKE_INBOUND_SPI:
		case JITIKE_OUTBOUND_SPI:
		case JITIKE_INIT_MID:
		case JITIKE_RESP_MID:
		{
			uint32_t val;

			val = va_arg(args, u_int);

			ret = redisFormatCommand(&buf, "HSET %s %s %d", key, field, val);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			break;
		}
		/** chunk_t */
		case JITIKE_NONCE_I:
		case JITIKE_NONCE_R:
		case JITIKE_SECRET:
		case JITIKE_LOCAL_DH:
		case JITIKE_REMOTE_DH:
		case JITIKE_PSK:
		case JITIKE_IV:
		case JITIKE_OLD_SKD:
		{
			chunk_t chunk;
			chunk_encoding_t *enc;

			chunk = va_arg(args, chunk_t);

			enc = malloc(sizeof(chunk_encoding_t) + chunk.len);
			enc->len = chunk.len;
			memcpy(enc->encoding, chunk.ptr, chunk.len);

			ret = redisFormatCommand(&buf, "HSET %s %s %b", key, field, enc, sizeof(chunk_encoding_t) + enc->len);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			free(enc);

			break;
		}
		/** traffic_selector_t */
		case JITIKE_LOCAL_TS:
		case JITIKE_REMOTE_TS:
		{
			char *tbuf;
			ts_encoding_t *enc;
			traffic_selector_t *ts;
			chunk_t data;

			ts = va_arg(args, traffic_selector_t*);
			data = chunk_cata("cc", ts->get_from_address(ts),
							  ts->get_to_address(ts));
			tbuf = malloc(sizeof(ts_encoding_t) + data.len);
			enc = (ts_encoding_t *)tbuf;
			enc->type = ts->get_type(ts);
			enc->protocol = ts->get_protocol(ts);
			enc->from_port = ts->get_from_port(ts);
			enc->to_port = ts->get_to_port(ts);
			enc->dynamic = ts->is_dynamic(ts);
			memcpy(enc->encoding, data.ptr, data.len);

			ret = redisFormatCommand(&buf, "HSET %s %s %b", key, field, enc, sizeof(ts_encoding_t)+data.len);

			if (ret != -1)
			{
				if (redisAppendFormattedCommand(ctx, buf, ret) == REDIS_ERR)
				{
					DBG1(DBG_CFG, "add_redis_buffer: Error adding command to context buffer: [%s]", buf);
				}
				free(buf);
			}

			free(tbuf);

			break;
		}

		default:
		{
			DBG1(DBG_CFG, "add_redis_buffer: unable to encode, attribute %d / %s unknown", attribute, field);
			break;
		}
	}
	va_end(args);
}
