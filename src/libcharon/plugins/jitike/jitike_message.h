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

/**
 * @defgroup jitike_message jitike_message
 * @{ @ingroup jitike
 */

#ifndef JITIKE_MESSAGE_H_
#define JITIKE_MESSAGE_H_

#include <openssl/rsa.h>

#include <library.h>
#include <networking/host.h>
#include <utils/identification.h>
#include <sa/ike_sa_id.h>
#include <selectors/traffic_selector.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

/** Hashset that stores the current, previous and future KEYID */
#define REDIS_KEYPATH   "redis_encryption_keys"

typedef enum jitike_message_attribute_t jitike_message_attribute_t;

/**
 * Type of attributes contained in a message
 */
enum jitike_message_attribute_t {
	/** ike_sa_id_t*, to identify IKE_SA */
	JITIKE_IKE_ID = 1,
	/** ike_sa_id_t*, identifies IKE_SA which gets rekeyed */
	JITIKE_IKE_REKEY_ID,
	/** identification_t*, local identity */
	JITIKE_LOCAL_ID,
	/** identification_t*, remote identity */
	JITIKE_REMOTE_ID,
	/** identification_t*, remote EAP identity */
	JITIKE_REMOTE_EAP_ID,
	/** host_t*, local address */
	JITIKE_LOCAL_ADDR,
	/** host_t*, remote address */
	JITIKE_REMOTE_ADDR,
	/** char*, name of configuration */
	JITIKE_CONFIG_NAME,
	/** uint32_t, bitset of ike_condition_t */
	JITIKE_CONDITIONS,
	/** uint32_t, bitset of ike_extension_t */
	JITIKE_EXTENSIONS,
	/** host_t*, local virtual IP */
	JITIKE_LOCAL_VIP,
	/** host_t*, remote virtual IP */
	JITIKE_REMOTE_VIP,
	/** host_t*, known peer addresses (used for MOBIKE) */
	JITIKE_PEER_ADDR,
	/** uint8_t, initiator of an exchange, TRUE for local */
	JITIKE_INITIATOR,
	/** chunk_t, initiators nonce */
	JITIKE_NONCE_I,
	/** chunk_t, responders nonce */
	JITIKE_NONCE_R,
	/** chunk_t, diffie hellman shared secret */
	JITIKE_SECRET,
	/** chunk_t, SKd of old SA if rekeying */
	JITIKE_OLD_SKD,
	/** uint16_t, pseudo random function */
	JITIKE_ALG_PRF,
	/** uint16_t, old pseudo random function if rekeying */
	JITIKE_ALG_OLD_PRF,
	/** uint16_t, encryption algorithm */
	JITIKE_ALG_ENCR,
	/** uint16_t, encryption key size in bytes */
	JITIKE_ALG_ENCR_LEN,
	/** uint16_t, integrity protection algorithm */
	JITIKE_ALG_INTEG,
	/** uint16_t, DH group */
	JITIKE_ALG_DH,
	/** uint8_t, IPsec mode, TUNNEL|TRANSPORT|... */
	JITIKE_IPSEC_MODE,
	/** uint8_t, IPComp protocol */
	JITIKE_IPCOMP,
	/** uint32_t, inbound security parameter index */
	JITIKE_INBOUND_SPI,
	/** uint32_t, outbound security parameter index */
	JITIKE_OUTBOUND_SPI,
	/** uint16_t, inbound security parameter index */
	JITIKE_INBOUND_CPI,
	/** uint16_t, outbound security parameter index */
	JITIKE_OUTBOUND_CPI,
	/** traffic_selector_t*, local traffic selector */
	JITIKE_LOCAL_TS,
	/** traffic_selector_t*, remote traffic selector */
	JITIKE_REMOTE_TS,
	/** uint32_t, initiator message ID */
	JITIKE_INIT_MID,
	/** uint32_t, responder message ID */
	JITIKE_RESP_MID,
	/** uint16_t, HA segment */
	JITIKE_SEGMENT,
	/** uint16_t, Extended Sequence numbers */
	JITIKE_ESN,
	/** uint8_t, IKE version */
	JITIKE_IKE_VERSION,
	/** chunk_t, own DH public value */
	JITIKE_LOCAL_DH,
	/** chunk_t, remote DH public value */
	JITIKE_REMOTE_DH,
	/** chunk_t, shared secret for IKEv1 key derivation */
	JITIKE_PSK,
	/** chunk_t, IV for next IKEv1 message */
	JITIKE_IV,
	/** uint16_t, auth_method_t for IKEv1 key derivation */
	JITIKE_AUTH_METHOD,
	/** string, the ESP initiator authentication key */
	JITIKE_IN_AUTH_KEY,
	/** string, the ESP responder authentication key */
	JITIKE_OUT_AUTH_KEY,
	/** string, the ESP initiator AEAD key */
	JITIKE_IN_AEAD_KEY,
	/** string, the ESP responder AEAD key */
	JITIKE_OUT_AEAD_KEY,
	/** string, the ESP initiator crypto key */
	JITIKE_IN_CRYPTO_KEY,
	/** string, the ESP responder crypto key */
	JITIKE_OUT_CRYPTO_KEY,
	/** string, the owner of the hashset in redis */
	JITIKE_ALLOC_ID,
	/** string, ID of the keys used for encrypting fields in redis */
	JITIKE_REDIS_ENCRYPTION_KEY_ID,
	/** string, the JITID for this JITIKE hashset */
	JITIKE_JITID
};

/**
 * Retrieve ID of "current" encryption key from redis, read the key and return it
 *
 * @param ctx		The redisContext to use to send the message to
 * @return			RSA struct containing pubkey that will be used for encryption
 */
RSA *get_current_encryption_key(redisContext *ctx);

/**
 * This is used to add an attribute to a key in redis.
 *
 * @param ctx		The redisContext to use to send the message to
 * @param key		The key to store the field on
 * @param field		The field we are updating in redis
 * @param attribute	Easy enum to key off
 * @param ...		The data we're storing with the field
 */
void add_attribute(redisContext *ctx, char *key, char *field, jitike_message_attribute_t attribute, ...);

/**
 * This adds an attribute into a character array. Useful for sending multiple fields on
 * a key at a single time to Redis in an HMSET call.
 *
 * @param ctx		The redisContext to use to send the message to
 * @param key		The key to store the field on
 * @param field		The field we are updating in redis
 * @param attribute	Easy enum to key off
 * @param ...		The data we're storing with the field
 */
void add_redis_buffer(redisContext *ctx, char *key, char *field, jitike_message_attribute_t attribute, ...);

#endif /** JITIKE_MESSAGE_ @}*/
