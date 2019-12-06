/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * @defgroup jitike_redis jitike_redis
 * @{ @ingroup jitike
 */

#ifndef JITIKE_REDIS_H_
#define JITIKE_REDIS_H_

#include <daemon.h>
#include <threading/mutex.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

/**
 * Which DB to select.
 *
 * The code in jitike_hiredis.h needs to know the DB, and while globals are
 * never good, this makes it more efficient to store the DB as a global here
 * and then use it in the jitikeRedisCommand() code.
 */
extern int jitike_db;

/**
 * The mutex protecting access to jitikeRedisCommand.
 */
extern mutex_t *jrc_mutex;

/**
 * The maximum size of a redis-key for an IKEv2 session.
 */
#define JITIKE_MAX_KEY_SIZE	512

/**
 * The maximum size of an individual field identifier in redis.
 */
#define JITIKE_MAX_REDIS_KEY_SIZE 128

/**
 * The prefix of the channel we use to communicate.
 *
 * NOTE: This channel has a DB number added at the end.
 */
#define JITIKE_REDIS_CHANNEL	"jitike"

/**
 * Fields we set in redis
 **/
/** ike_sa_id_t*, to identify IKE_SA */
#define JI_IKE_ID "IKE_ID"
/** ike_sa_id_t*, identifies IKE_SA which gets rekeyed */
#define JI_IKE_REKEY_ID "IKE_REKEY_ID"
/** identification_t*, local identity */
#define JI_LOCAL_ID "LOCAL_ID"
/** identification_t*, remote identity */
#define JI_REMOTE_ID "REMOTE_ID"
/** identification_t*, remote EAP identity */
#define JI_REMOTE_EAP_ID "REMOTE_EAP_ID"
/** host_t*, local address */
#define JI_LOCAL_ADDR "LOCAL_ADDR"
/** host_t*, remote address */
#define JI_REMOTE_ADDR "REMOTE_ADDR"
/** char*, name of configuration */
#define JI_CONFIG_NAME "CONFIG_NAME"
/** char*, name of child configuration */
#define JI_CONFIG_NAME_CHILD "CONFIG_NAME_CHILD"
/** uint32_t, bitset of ike_condition_t */
#define JI_CONDITIONS "CONDITIONS"
/** uint32_t, bitset of ike_extension_t */
#define JI_EXTENSIONS "EXTENSIONS"
/** host_t*, local virtual IP */
#define JI_LOCAL_VIP "LOCAL_VIP"
/** host_t*, remote virtual IP */
#define JI_REMOTE_VIP "REMOTE_VIP"
/** host_t*, known peer addresses (used for MOBIKE) */
#define JI_PEER_ADDR "PEER_ADDR"
/** uint8_t, initiator of an exchange, TRUE for local */
#define JI_INITIATOR "INITIATOR"
/** chunk_t, initiators nonce */
#define JI_NONCE_I "NONCE_I"
/** chunk_t, responders nonce */
#define JI_NONCE_R "NONCE_R"
/** chunk_t, initiators child nonce */
#define JI_NONCE_I_CHILD "NONCE_I_CHILD"
/** chunk_t, responders child nonce */
#define JI_NONCE_R_CHILD "NONCE_R_CHILD"
/** chunk_t, diffie hellman shared secret */
#define JI_SECRET "SECRET"
/** chunk_t, diffie hellman shared secret for CHILD_SA */
#define JI_SECRET_CHILD "SECRET_CHILD"
/** chunk_t, SKd of old SA if rekeying */
#define JI_OLD_SKD "OLD_SKD"
/** uint16_t, pseudo random function */
#define JI_ALG_PRF "ALG_PRF"
/** uint16_t, old pseudo random function if rekeying */
#define JI_ALG_OLD_PRF "ALG_OLD_PRF"
/** uint16_t, encryption algorithm */
#define JI_ALG_ENCR "ALG_ENCR"
/** uint16_t, encryption key size in bytes */
#define JI_ALG_ENCR_LEN "ALG_ENCR_LEN"
/** uint16_t, integrity protection algorithm */
#define JI_ALG_INTEG "ALG_INTEG"
/** uint16_t, DH group */
#define JI_ALG_DH "ALG_DH"
/** uint8_t, IPsec mode, TUNNEL|TRANSPORT|... */
#define JI_IPSEC_MODE "IPSEC_MODE"
/** uint8_t, IPComp protocol */
#define JI_IPCOMP "IPCOMP"
/** uint32_t, inbound security parameter index */
#define JI_INBOUND_SPI "INBOUND_SPI"
/** uint32_t, outbound security parameter index */
#define JI_OUTBOUND_SPI "OUTBOUND_SPI"
/** uint16_t, inbound security parameter index */
#define JI_INBOUND_CPI "INBOUND_CPI"
/** uint16_t, outbound security parameter index */
#define JI_OUTBOUND_CPI "OUTBOUND_CPI"
/** traffic_selector_t*, local traffic selector */
#define JI_LOCAL_TS "LOCAL_TS"
/** traffic_selector_t*, remote traffic selector */
#define JI_REMOTE_TS "REMOTE_TS"
/** uint32_t, initiator message ID */
#define JI_INIT_MID "INIT_MID"
/** uint32_t, responder message ID */
#define JI_RESP_MID "RESP_MID"
/** uint16_t, HA segment */
#define JI_SEGMENT "SEGMENT"
/** uint16_t, Extended Sequence numbers */
#define JI_ESN "ESN"
/** uint8_t, IKE version */
#define JI_IKE_VERSION "IKE_VERSION"
/** chunk_t, own DH public value */
#define JI_LOCAL_DH "LOCAL_DH"
/** chunk_t, remote DH public value */
#define JI_REMOTE_DH "REMOTE_DH"
/** chunk_t, shared secret for IKEv1 key derivation */
#define JI_PSK "PSK"
/** chunk_t, IV for next IKEv1 message */
#define JI_IV "IV"
/** uint16_t, auth_method_t for IKEv1 key derivation */
#define JI_AUTH_METHOD "AUTH_METHOD"
/** uint16_t, integrity protection algorithm for CHILD SA */
#define JI_ALG_INTEG_CHILD "ALG_INTEG_CHILD"
/** uint16_t, DH group for CHILD SA */
#define JI_ALG_DH_CHILD "ALG_DH_CHILD"
/** uint16_t, encryption algorithm for CHILD SA*/
#define JI_ALG_ENCR_CHILD "ALG_ENCR_CHILD"
/** uint16_t, CHILD SA encryption key size in bytes */
#define JI_ALG_ENCR_LEN_CHILD "ALG_ENCR_LEN_CHILD"
/** uint16_t, Extended Sequence numbers for CHILD SA*/
#define JI_ESN_CHILD "ESN_CHILD"
/** string, the ESP initiator authentication key */
#define JI_IN_AUTH_KEY "IN_AUTH_KEY"
/** string, the ESP responder authentication key */
#define JI_OUT_AUTH_KEY "OUT_AUTH_KEY"
/** string, the ESP initiator AEAD key */
#define JI_IN_AEAD_KEY "IN_AEAD_KEY"
/** string, the ESP responder AEAD key */
#define JI_OUT_AEAD_KEY "OUT_AEAD_KEY"
/** string, the ESP initiator crypto key */
#define JI_IN_CRYPTO_KEY "IN_CRYPTO_KEY"
/** string, the ESP responder crypto key */
#define JI_OUT_CRYPTO_KEY "OUT_CRYPTO_KEY"
/** string, the node which owns this IKE's allocation ID */
#define JI_ALLOC_ID "ALLOC_ID"
/** ID of the key used for encrypting private fields */
#define JI_REDIS_ENCRYPTION_KEY_ID "REDIS_ENCRYPTION_KEY_ID"
/** The JITID for this JITIKE hashset */
#define JI_JITID "JITID"

typedef struct jitike_redis_t jitike_redis_t;

/**
 * Access to redis
 */
struct jitike_redis_t {

	/**
	 * Implements bus listener interface.
	 */
	listener_t listener;

	/**
	 * Transfer an IKE session to another node.
	 */
	int (*transfer_ike)(jitike_redis_t *this, const char *command);

	/**
	 * Handle FIFO commands for redis testing/debugging.
	 */
	int (*handle_redis_fifo)(jitike_redis_t *this, const char *command);

	/**
	 * Get the redisContext
	 */
	redisContext *(*get_redis_ctx)(jitike_redis_t *this);

	/**
	 * Reconnect to a master, taking into account Redis Sentinel
	 */
	redisContext* (*redis_sentinel_reconnect_master)(jitike_redis_t *this);

        /**
         * Destroy a jitike_redis_t.
         */
        void (*destroy)(jitike_redis_t *this);
};

/**
 * Used to reconnect to Redis via Sentinel by jitikeRedisCommand()
 */
extern jitike_redis_t *jrc_redis;

/**
 * Create a jitike_redis_t instance.
 *
 * @return            Listens for IKE messages and plumbs them into redis.
 */
jitike_redis_t *jitike_redis_create(void);

#endif /** JITIKE_REDIS_H_ @}*/
