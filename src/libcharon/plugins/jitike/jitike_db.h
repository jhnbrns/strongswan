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
 * @defgroup jitike_db jitike_db
 * @{ @ingroup jitike
 */

#ifndef JITIKE_DB_H_
#define JITIKE_DB_H_

#include <string.h>
#include <inttypes.h>
#include <openssl/sha.h>

#include "jitike_redis.h"
#include "jitike_message.h"
#include <utils/debug.h>
#include <daemon.h>

#define MAX_REDIS_ADDR_SIZE     128

/**
 * This is the default TTL for a key in Redis, set when we first create the
 * key, before we know the actual time we want for the key. Used to prevent
 * oddities with other parts of the system which look at the TTL on the keys.
 * This is in seconds.
 */
#define JITIKE_DEFAULT_TTL	600

typedef struct chunk_encoding_t chunk_encoding_t;

struct chunk_encoding_t {
	uint32_t len;
	char encoding[];
} __attribute__((packed));

typedef struct host_encoding_t host_encoding_t;

/**
 * encoding of a host_t
 */
struct host_encoding_t {
	uint16_t port;
	uint8_t family;
	char encoding[];
} __attribute__((packed));

typedef struct ike_sa_id_encoding_t ike_sa_id_encoding_t;

/**
 * Encoding if an ike_sa_id_t
 */
struct ike_sa_id_encoding_t {
	uint8_t ike_version;
	uint64_t initiator_spi;
	uint64_t responder_spi;
	uint8_t initiator;
} __attribute__((packed));

typedef struct identification_encoding_t identification_encoding_t;

/**
 * Encoding of a identification_t
 */
struct identification_encoding_t {
	uint8_t type;
	uint8_t len;
	char encoding[];
} __attribute__((packed));

typedef struct ts_encoding_t ts_encoding_t;

/**
 * encoding of a traffic_selector_t
 */
struct ts_encoding_t {
	uint8_t type;
	uint8_t protocol;
	uint16_t from_port;
	uint16_t to_port;
	uint8_t dynamic;
	char encoding[];
} __attribute__((packed));

/**
 * Message types we pass over the channel.
 */
enum cb_radio_message_t {
	/** Transfer an IKE, passes a ike_channel_sa_id_encoding_t */
	CB_JITIKE = 1,

	/** Signal an IKE SA rekey, passes an ike_rekey_t */
	CB_REKEY_IKE_SA,

	/** Signal a child SA rekey, passes a child_rekey_t */
	CB_REKEY_CHILD_SA,
};

typedef struct cb_radio_t cb_radio_t;

/**
 * Used to pass information across a redis channel between nodes
 */
struct cb_radio_t {
	uint32_t message_type;
	char encoding[];
} __attribute__((packed));

typedef struct ike_channel_sa_id_encoding_t ike_channel_sa_id_encoding_t;

/**
 * Encoding if an ike_channel_sa_id_t
 */
struct ike_channel_sa_id_encoding_t {
	uint8_t ike_version;
	uint64_t initiator_spi;
	uint64_t responder_spi;
	uint8_t initiator;
	uint32_t alloc_id_len;
	uint32_t hostname_len;
	char encoding[];
} __attribute__((packed));

typedef struct ike_rekey_t ike_rekey_t;

/**
 * Used to rekey an IKE SA
 */
struct ike_rekey_t {
	uint8_t reauth;
	uint64_t spi_i;
	uint64_t spi_r;
	/* We assume we are the responder and we only support IKEV2 */
} __attribute__((packed));

typedef struct child_rekey_t child_rekey_t;

/**
 * Encoding for a child rekey event
 */
struct child_rekey_t {
	uint64_t spi_i;
	uint64_t spi_r;
	uint32_t ike_id;
	uint32_t ike_name_len;
	uint32_t child_id;
	uint32_t child_name_len;
	char encoding[];
} __attribute__((packed));

/**
 * Populate redis with IKE_SA data. This should be called after we receive
 * an IKE_UPDATE message from the HA master node.
 *
 * @param ike_sa	The IKE_SA to build the key for
 * @param key		Where to store the key
 * @return		0 for success, -1 for error
 */
static inline int redis_get_key(ike_sa_t *ike_sa, char *key)
{
	ike_sa_id_t *id;
	int ret = 0;

	if ((id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis process_ike_add Error getting ike_sa, failing");
		ret = -1;
		goto ikeout;
	}

	/* We'll use this as the key for storing the information in redis */
	snprintf(key, JITIKE_MAX_KEY_SIZE, "%.16"PRIx64"_i-%.16"PRIx64"_r",
			be64toh(id->get_initiator_spi(id)), be64toh(id->get_responder_spi(id)));

ikeout:
	return ret;
}

static inline int redis_get_key_with_child(ike_sa_t *ike_sa, child_sa_t *child_sa, char *key)
{
	ike_sa_id_t *id;
	int ret = 0;

	if ((ike_sa == NULL) || (child_sa == NULL))
	{
		DBG1(DBG_CFG, "redis_get_key_with_child: ike_sa or child_sa is NULL");
		ret = -1;
		goto ikeout;
	}

	if ((id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "redis_get_key_with_child: Error getting ike_sa, failing");
		ret = -1;
		goto ikeout;
	}

	/* We'll use this as the key for storing the information in redis */
	snprintf(key, JITIKE_MAX_KEY_SIZE, "%.16"PRIx64"_i-%.16"PRIx64"_r-%08x_i-%08x_r",
			be64toh(id->get_initiator_spi(id)), be64toh(id->get_responder_spi(id)),
			ntohl(child_sa->get_spi(child_sa, TRUE)), ntohl(child_sa->get_spi(child_sa, FALSE)));

ikeout:
	return ret;
}

/**
 * get_jitid(): Used to get a JITID from the 5-tuple.
 *
 * NOTE: Callers of this inline function are responsible for free'ing the memory allocated here.
 *
 * To decode the return hash correctly, you need to do the following:
 *
 *      for (int i=0; i < SHA_DIGEST_LENGTH; i++)
 *      {
 *              printf("%02x", hash[i]);
 *      }
 *
 * This function will decode the hash and return a string representation of the jitid. The caller
 * should free this memory.
 *
 */
static inline char *get_jitid(const char *srcAddr, uint16_t srcPort, const char *dstAddr, uint16_t dstPort)
{
	char *five_tuple = NULL;
	uint32_t proto;
	size_t length = 0, five_tuple_len = 0;
	unsigned char hash[SHA_DIGEST_LENGTH];
	char *jitid = NULL;
	const uint32_t protocolUDP = 17;
	const uint32_t protocolESP = 50;

	memset(&hash[0], 0, SHA_DIGEST_LENGTH);

	jitid = malloc(SHA_DIGEST_LENGTH*2+1);
	if (jitid == NULL)
	{
		goto out;
	}

	if ((srcPort == 0) && (dstPort == 0))
	{
		proto = protocolESP;
	}
	else
	{
		proto = protocolUDP;
	}

	/**
	 * Formatted like this:
	 *
	 * %s_%s_%s_%s_%d"
	 *
	 * So make sure to account for the underscores.
	 *
	 * Extra bytes: 4 underscores + up to 5 characters for each port.
	 */
	five_tuple_len = strlen(srcAddr)+strlen(dstAddr)+17;
	five_tuple = malloc(five_tuple_len);
	if (five_tuple == NULL)
	{
		DBG1(DBG_CFG, "get_jitid: Cannot allocate memory");
		goto out;
	}

	snprintf(five_tuple, five_tuple_len, "%s_%d_%s_%d_%d", srcAddr, srcPort, dstAddr, dstPort, proto);

	DBG2(DBG_CFG, "get_jitid: Hashing string %s", five_tuple);

	/**
	 * Now hash it.
	 */
	SHA1((unsigned char *)five_tuple, strlen(five_tuple), (unsigned char *)hash);

	/**
	 * Convert into a string representation of JITID.
	 */
	for (int i=0; i < SHA_DIGEST_LENGTH; i++)
	{
		sprintf(jitid+(i*2), "%02x", hash[i]);
	}
	jitid[SHA_DIGEST_LENGTH*2] = '\0';

	/**
	 * Free the memory now.
	 */
	free(five_tuple);

	DBG2(DBG_CFG, "get_jitid: Storing JITID of %s", jitid);

out:
	return jitid;
}

/**
 * Rekey a redis-key to use the local HA pair IP addresses.
 * Called after a JITIKE IKE node takes over a key from a downed IKE node.
 *
 * @param local		Local hostname (host relative)
 * @param remote	Remote hostname (host relative)
 * @return		0 for success, -1 for error
 */
static inline int redis_rekey(ike_sa_t *ike_sa, const char *oldkey, char *newkey)
{
	ike_sa_id_t *id;
	int count = 0, second = 0;
	int ret = 0;

	while ((strncmp(&oldkey[count], "-", 1) != 0) || (second != 1)) {
		if (strncmp(&oldkey[count], "-", 1) == 0) {
			second++;
		}
		count++;
	}

	if ((id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis redis_rekey Error getting ike_sa, failing");
		ret = -1;
		goto ikeout;
	}

	/* We'll use this as the key for storing the information in redis */
	snprintf(newkey, JITIKE_MAX_KEY_SIZE, "%.16"PRIx64"_i-%.16"PRIx64"_r",
			be64toh(id->get_initiator_spi(id)), be64toh(id->get_responder_spi(id)));

ikeout:
	return ret;
}

/**
 * Apply a condition flag to the IKE_SA if it is in set
 */
static inline void set_condition(ike_sa_t *ike_sa, ike_condition_t set,
                                                  ike_condition_t flag)
{
        ike_sa->set_condition(ike_sa, flag, flag & set);
}

/**
 * Apply a extension flag to the IKE_SA if it is in set
 */
static inline void set_extension(ike_sa_t *ike_sa, ike_extension_t set,
                                                  ike_extension_t flag)
{
        if (flag & set)
        {
                ike_sa->enable_extension(ike_sa, flag);
        }
}

#endif /** JITIKE_DB_H_ @}*/
