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

#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>

#include <processing/jobs/delete_ike_sa_job.h>
#include <processing/jobs/initiate_tasks_job.h>
#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev1/keymat_v1.h>
#include <threading/mutex.h>

#include "jitike_redis.h"
#include "jitike_redis_sentinel.h"
#include "jitike_hiredis.h"
#include "jitike_message.h"
#include "jitike_db.h"
#include "jitike_async_job.h"
#include "jitike_spi_generator.h"
#include "redis_dh.h"

#define DEFAULT_REDIS_HOSTNAME		"127.0.0.1"
#define DEFAULT_REDIS_PORT		6379
#define DEFAULT_REDIS_DB		"0"
#define DEFAULT_REDIS_TIMEOUT_SEC	1
#define DEFAULT_REDIS_TIMEOUT_USEC	500000
#define DEFAULT_REDIS_ALLOC_ID		"d3ad-833f-d3ad-833f"

#define JITIKE_WRITE_INACTIVE	0
#define JITIKE_WRITE_ACTIVE	1

/**
 * How many times to retry pipeline errors.
 */
#define JITIKE_PIPELINE_RETRY_MAX	2

/**
 * Extra key expiration time, in seconds
 */
#define JITIKE_KEY_GRACE_PERIOD 300

/**
 * Which Redis DB we are connected to.
 */
int jitike_db = 0;

/**
 * Mutex used to protect access to redisContext in the private_jitike_redis_t
 * structure.
 */
mutex_t *jrc_mutex;

/**
 * Used by jitikeRedisCommand() to reconnect to Redis via Sentinel
 */
jitike_redis_t *jrc_redis;

typedef struct private_jitike_redis_t private_jitike_redis_t;

/**
 * Redis variables
 */
struct private_jitike_redis_t {

	/**
	 * Public jitike_redis_t interface.
	 */
	jitike_redis_t public;

	/**
	 * Redis connection context.
	 *
	 * NOTE: a redisContext structure is not thread safe. In jitike_hiredis.h, we
	 * protect access to this structure with a mutex. However, we also pass a pointer
	 * to this exact redisContext pointer around. The fact that in jitikeRedisCommand
	 * we use redisReconnect is what allows this to happen. redisReconnect uses the
	 * existing structure to reconnect to redis. If this ever changes such that a new
	 * pointer is acquired, we'll need to update the copy across the code, or move to
	 * not sharing the pointer to begin with.
	 *
	 * Note that the easiest and simplest solution may be to move the redisContext
	 * pointer out of the private_jitike_redis_t structure found here and make it a
	 * global somewhere else, protecting access to it with a mutex.
	 */
	redisContext *ctx;

	/**
	 * DB to connect to.
	 */
	char *db;

	/**
	 * The node's unique allocation ID
	 */
	char *alloc_id;

	/**
	 * Connection timeout.
	 */
	struct timeval timeout;

	/**
	 * Sentinel configuration
	 */
	redis_sentinel_cfg_t sentinel_cfg;

	/**
	 * The omniscient Sentinel
	 */
	redis_sentinel_t *sentinel;

	/**
	 * The local Redis instance
	 */
	char *local_redis;

	/**
	 * Extra timeout value for keys in Redis. This is added to STAT_DELETE - STAT_ESTABLISHED.
	 */
	time_t expire;
};

/**
 * Return condition if it is set on ike_sa
 */
static ike_condition_t copy_condition(ike_sa_t *ike_sa, ike_condition_t cond)
{
	if (ike_sa->has_condition(ike_sa, cond))
	{
		return cond;
	}
	return 0;
}

/**
 * Return extension if it is supported by peers IKE_SA
 */
static ike_extension_t copy_extension(ike_sa_t *ike_sa, ike_extension_t ext)
{
	if (ike_sa->supports_extension(ike_sa, ext))
	{
		return ext;
	}
	return 0;
}

static int store_jitid(redisContext *ctx, ike_sa_t *ike_sa, char *key)
{
	int ret = 0;
	host_t *local_host = ike_sa->get_my_host(ike_sa);;
	host_t *remote_host = ike_sa->get_other_host(ike_sa);
	int local_family = local_host->get_family(local_host);
	int remote_family = remote_host->get_family(remote_host);
	sockaddr_t *local_sockaddr = local_host->get_sockaddr(local_host);
	sockaddr_t *remote_sockaddr = remote_host->get_sockaddr(remote_host);
	uint16_t localport = local_host->get_port(local_host);
	uint16_t remoteport = remote_host->get_port(remote_host);
	char *tmp = NULL, *localip = NULL, *remoteip = NULL;
	char *jitid = NULL;

	switch (local_family)
	{
		case AF_INET:
			{
				/**
				 * Note that inet_ntoa() stores it's result in a static buffer inside the kernel.
				 * This means we have to save the result away, otherwise a subsequent call will
				 */
				struct sockaddr_in *local_sockin = (struct sockaddr_in *)local_sockaddr;
				tmp = inet_ntoa(local_sockin->sin_addr);
				localip = strndup(tmp, strlen(tmp));
				DBG2(DBG_CFG, "store_jitid: Found localip: %s", localip);
				break;
			}
		case AF_INET6:
			{
				/** Not supported for now */
				DBG2(DBG_CFG, "store_jitid: IPv6 source address not supported");
				ret = -1;
				goto out;
			}
		default:
			break;
	}

	switch (remote_family)
	{
		case AF_INET:
			{
				/**
				 * Note that inet_ntoa() stores it's result in a static buffer inside the kernel.
				 * This means we have to save the result away, otherwise a subsequent call will
				 */
				struct sockaddr_in *remote_sockin = (struct sockaddr_in *)remote_sockaddr;
				tmp = inet_ntoa(remote_sockin->sin_addr);
				remoteip = strndup(tmp, strlen(tmp));
				DBG2(DBG_CFG, "store_jitid: Found remoteip : %s", remoteip);
				break;
			}
		case AF_INET6:
			{
				/** Not supported for now */
				DBG2(DBG_CFG, "store_jitid: IPv6 remote address not supported");
				ret = -1;
				goto out;
			}
		default:
			break;
	}

	jitid = get_jitid(localip, localport, remoteip, remoteport);

	if (jitid == NULL)
	{
		DBG1(DBG_CFG, "store_jitid: Error getting jitid, failing");
		ret = -1;
		goto out;
	}

	DBG2(DBG_CFG, "store_jitid: Found jitid of %s", jitid);

	add_attribute(ctx, key, JI_JITID, JITIKE_JITID, jitid);

out:
	if (localip != NULL)
	{
		free(localip);
	}
	if (remoteip != NULL)
	{
		free(remoteip);
	}
	if (jitid != NULL)
	{
		free(jitid);
	}

	return ret;
}

METHOD(listener_t, ike_keys, bool,
	private_jitike_redis_t *this, ike_sa_t *ike_sa, diffie_hellman_t *dh,
	chunk_t dh_other, chunk_t nonce_i, chunk_t nonce_r, ike_sa_t *rekey,
	shared_key_t *shared, auth_method_t method)
{
	ike_sa_id_t *ike_sa_id;
	char key[JITIKE_MAX_KEY_SIZE];
	chunk_t secret;
	proposal_t *proposal;
	uint16_t alg, len;
	redisReply *reply = NULL;
	unsigned int cmd_count = 0;
	int format_ret = 0;
	char *buf = NULL;
	bool pipeline_error = FALSE;
	int pipeline_retry_count = 0;

	if ((ike_sa_id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis ike_keys Error getting ike_sa, failing");
		goto jitike;
	}

	DBG2(DBG_CFG, "jitike_redis ike_keys received ike_keys for SPI %.16"PRIx64"_i %.16"PRIx64"_r",
		be64toh(ike_sa_id->get_initiator_spi(ike_sa_id)),
		be64toh(ike_sa_id->get_responder_spi(ike_sa_id)));

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key(ike_sa, key) != 0) {
		DBG1(DBG_CFG, "jitike_redis Error getting key");
		goto jitike;
	}

repipeline:
	if (!dh->get_shared_secret(dh, &secret))
	{
		return TRUE;
	}

	/**
	 * Lock the context before we begin pipeling commands.
	 * NOTE: If this becomes an issue, we can move to a per-thread Redis context to move away
	 * from locks.
	 */
	jrc_mutex->lock(jrc_mutex);

	add_redis_buffer(this->ctx, key, JI_ALLOC_ID, JITIKE_ALLOC_ID, this->alloc_id);
	cmd_count++;
	/**
	 * We want to set a TTL on the key right away.
	 */
	format_ret = redisFormatCommand(&buf, "EXPIRE %s %d", key, JITIKE_DEFAULT_TTL);
	if (format_ret != -1)
	{
		if (redisAppendFormattedCommand(this->ctx, buf, format_ret) == REDIS_ERR)
		{
			DBG1(DBG_CFG, "ike_keys: Failed expiring keys for hashset %s", key);
		}
		else
		{
			cmd_count++;
		}
		free(buf);
	}
	add_redis_buffer(this->ctx, key, JI_IKE_VERSION, JITIKE_IKE_VERSION, ike_sa->get_version(ike_sa));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_IKE_ID, JITIKE_IKE_ID, ike_sa->get_id(ike_sa));
	cmd_count++;

	if (rekey && rekey->get_version(rekey) == IKEV2)
	{
		chunk_t skd;
		keymat_v2_t *keymat;

		keymat = (keymat_v2_t*)rekey->get_keymat(rekey);
		add_redis_buffer(this->ctx, key, JI_IKE_REKEY_ID, JITIKE_IKE_REKEY_ID, rekey->get_id(rekey));
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_ALG_OLD_PRF, JITIKE_ALG_OLD_PRF, keymat->get_skd(keymat, &skd));
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_OLD_SKD, JITIKE_OLD_SKD, skd);
		cmd_count++;
	}

	proposal = ike_sa->get_proposal(ike_sa);
	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		add_redis_buffer(this->ctx, key, JI_ALG_ENCR, JITIKE_ALG_ENCR, alg);
		cmd_count++;
		if (len)
		{
			add_redis_buffer(this->ctx, key, JI_ALG_ENCR_LEN, JITIKE_ALG_ENCR_LEN, len);
			cmd_count++;
		}
	}
	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL))
	{
		add_redis_buffer(this->ctx, key, JI_ALG_INTEG, JITIKE_ALG_INTEG, alg);
		cmd_count++;
	}
	if (proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{
		add_redis_buffer(this->ctx, key, JI_ALG_PRF, JITIKE_ALG_PRF, alg);
		cmd_count++;
	}
	if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &alg, NULL))
	{
		add_redis_buffer(this->ctx, key, JI_ALG_DH, JITIKE_ALG_DH, alg);
		cmd_count++;
	}

	add_redis_buffer(this->ctx, key, JI_NONCE_I, JITIKE_NONCE_I, nonce_i);
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_NONCE_R, JITIKE_NONCE_R, nonce_r);
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_SECRET, JITIKE_SECRET, secret);
	cmd_count++;
	chunk_clear(&secret);
	if (ike_sa->get_version(ike_sa) == IKEV1)
	{
		if (dh->get_my_public_value(dh, &secret))
		{
			add_redis_buffer(this->ctx, key, JI_LOCAL_DH, JITIKE_LOCAL_DH, secret);
			cmd_count++;
			chunk_free(&secret);
		}
		add_redis_buffer(this->ctx, key, JI_REMOTE_DH, JITIKE_REMOTE_DH, dh_other);
		cmd_count++;
		if (shared)
		{
			add_redis_buffer(this->ctx, key, JI_PSK, JITIKE_PSK, shared->get_key(shared));
			cmd_count++;
		}
		else
		{
			add_redis_buffer(this->ctx, key, JI_AUTH_METHOD, JITIKE_AUTH_METHOD, method);
			cmd_count++;
		}
	}
	add_redis_buffer(this->ctx, key, JI_REMOTE_ADDR, JITIKE_REMOTE_ADDR, ike_sa->get_other_host(ike_sa));
	cmd_count++;

	/**
	 * Pipeline the commands here by calling jitikeRedisPipelineReadReply for each
	 * of the commands we sent. Then unlock the context.
	 */
	while (cmd_count-- > 0)
	{
		reply = jitikeRedisPipelineReadReply(this->ctx);

		if (reply != NULL)
		{
			freeReplyObject(reply);
		}
		else
		{
			/** Signal an error */
			pipeline_error = TRUE;
			goto out_of_loop;
		}
	}
out_of_loop:
	jrc_mutex->unlock(jrc_mutex);

	if (pipeline_error == TRUE && (pipeline_retry_count < JITIKE_PIPELINE_RETRY_MAX))
	{
		DBG1(DBG_CFG, "ike_keys: pipeline error received, retrying hashset store in Redis for key %s", key);

		/**
		 * Recover from a pipeline error. This means we should delete the (potentially)
		 * partially complete hashset in Redis, reset the cmd_count variable, and try
		 * again. However, we can only do this retry JITIKE_PIPELINE_RETRY_MAX times or
		 * we'll loop here forever. Be cautious.
		 */
		redisReply *pipeReply = NULL;

		pipeReply = jitikeRedisCommand(this->ctx, "DEL %s", key);
		if (pipeReply != NULL)
		{
			freeReplyObject(pipeReply);
		}
		else
		{
			DBG1(DBG_CFG, "ike_keys: Error trying to delete hashset %s", key);
		}
		pipeline_error = FALSE;
		cmd_count = 0;
		pipeline_retry_count++;
		goto repipeline;
	}

jitike:
	return TRUE;
}

METHOD(listener_t, ike_updown, bool,
	private_jitike_redis_t *this, ike_sa_t *ike_sa, bool up)
{
	char key[JITIKE_MAX_KEY_SIZE];
	ike_sa_id_t *ike_sa_id;

	if (ike_sa->get_state(ike_sa) == IKE_PASSIVE)
	{       /* only sync active IKE_SAs */
		return TRUE;
	}

	if ((ike_sa_id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis ike_updown Error getting ike_sa");
		goto jitike;
	}

	DBG2(DBG_CFG, "jitike_redis ike_upddown received ike_updown (%d) for SPI %.16"PRIx64"_i %.16"PRIx64"_r", up,
		be64toh(ike_sa_id->get_initiator_spi(ike_sa_id)),
		be64toh(ike_sa_id->get_responder_spi(ike_sa_id)));

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key(ike_sa, key) != 0) {
		DBG1(DBG_CFG, "jitike_redis Error getting key");
		goto jitike;
	}

	if (up)
	{
		enumerator_t *enumerator;
		peer_cfg_t *peer_cfg = NULL;
		uint32_t extension, condition;
		host_t *addr;
		ike_sa_id_t *id;
		identification_t *eap_id;
		redisReply *reply = NULL;
		unsigned int cmd_count = 0;
		bool pipeline_error = FALSE;
		int pipeline_retry_count = 0;

		peer_cfg = ike_sa->get_peer_cfg(ike_sa);

		condition = copy_condition(ike_sa, COND_NAT_ANY)
			| copy_condition(ike_sa, COND_NAT_HERE)
			| copy_condition(ike_sa, COND_NAT_THERE)
			| copy_condition(ike_sa, COND_NAT_FAKE)
			| copy_condition(ike_sa, COND_EAP_AUTHENTICATED)
			| copy_condition(ike_sa, COND_CERTREQ_SEEN)
			| copy_condition(ike_sa, COND_ORIGINAL_INITIATOR)
			| copy_condition(ike_sa, COND_STALE)
			| copy_condition(ike_sa, COND_INIT_CONTACT_SEEN)
			| copy_condition(ike_sa, COND_XAUTH_AUTHENTICATED);

		extension = copy_extension(ike_sa, EXT_NATT)
			| copy_extension(ike_sa, EXT_MOBIKE)
			| copy_extension(ike_sa, EXT_HASH_AND_URL)
			| copy_extension(ike_sa, EXT_MULTIPLE_AUTH)
			| copy_extension(ike_sa, EXT_STRONGSWAN)
			| copy_extension(ike_sa, EXT_EAP_ONLY_AUTHENTICATION)
			| copy_extension(ike_sa, EXT_MS_WINDOWS)
			| copy_extension(ike_sa, EXT_XAUTH)
			| copy_extension(ike_sa, EXT_DPD);

		id = ike_sa->get_id(ike_sa);

repipeline:
		/**
		 * Lock the context before we begin pipeling commands.
		 * NOTE: If this becomes an issue, we can move to a per-thread Redis context to move away
		 * from locks.
		 */
		jrc_mutex->lock(jrc_mutex);

		add_redis_buffer(this->ctx, key, JI_ALLOC_ID, JITIKE_ALLOC_ID, this->alloc_id);
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_IKE_ID, JITIKE_IKE_ID, id);
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_LOCAL_ID, JITIKE_LOCAL_ID, ike_sa->get_my_id(ike_sa));
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_REMOTE_ID, JITIKE_REMOTE_ID, ike_sa->get_other_id(ike_sa));
		cmd_count++;
		eap_id = ike_sa->get_other_eap_id(ike_sa);
		if (!eap_id->equals(eap_id, ike_sa->get_other_id(ike_sa)))
		{
			add_redis_buffer(this->ctx, key, JI_REMOTE_EAP_ID, JITIKE_REMOTE_EAP_ID, eap_id);
			cmd_count++;
		}
		add_redis_buffer(this->ctx, key, JI_LOCAL_ADDR, JITIKE_LOCAL_ADDR, ike_sa->get_my_host(ike_sa));
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_REMOTE_ADDR, JITIKE_REMOTE_ADDR, ike_sa->get_other_host(ike_sa));
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_CONDITIONS, JITIKE_CONDITIONS, condition);
		cmd_count++;
		add_redis_buffer(this->ctx, key, JI_EXTENSIONS, JITIKE_EXTENSIONS, extension);
		cmd_count++;
		if (peer_cfg != NULL)
		{
			add_redis_buffer(this->ctx, key, JI_CONFIG_NAME, JITIKE_CONFIG_NAME, peer_cfg->get_name(peer_cfg));
			cmd_count++;
		}
		enumerator = ike_sa->create_peer_address_enumerator(ike_sa);
		while (enumerator->enumerate(enumerator, (void**)&addr))
		{
			add_redis_buffer(this->ctx, key, JI_PEER_ADDR, JITIKE_PEER_ADDR, addr);
			cmd_count++;
		}
		enumerator->destroy(enumerator);

		/**
		 * Pipeline the commands here by calling jitikeRedisPipelineReadReply for each
		 * of the commands we sent. Then unlock the context.
		 */
		while (cmd_count-- > 0)
		{
			reply = jitikeRedisPipelineReadReply(this->ctx);

			if (reply != NULL)
			{
				freeReplyObject(reply);
			}
			else
			{
				/** Signal an error */
				pipeline_error = TRUE;
				goto out_of_loop;
			}
		}
out_of_loop:
		jrc_mutex->unlock(jrc_mutex);

		if (pipeline_error == TRUE && (pipeline_retry_count < JITIKE_PIPELINE_RETRY_MAX))
		{
			DBG1(DBG_CFG, "ike_updown: pipeline error received, retrying hashset store in Redis for key %s", key);
			/**
			 * Recover from a pipeline error. This means we should delete the (potentially)
			 * partially complete hashset in Redis, reset the cmd_count variable, and try
			 * again. However, we can only do this retry a single time or we'll loop here
			 * forever. Be cautious.
			 */
			redisReply *pipeReply = NULL;

			pipeReply = jitikeRedisCommand(this->ctx, "DEL %s", key);
			if (pipeReply != NULL)
			{
				freeReplyObject(pipeReply);
			}
			else
			{
				DBG1(DBG_CFG, "ike_updown: Error trying to delete hashset %s", key);
			}
			pipeline_error = FALSE;
			cmd_count = 0;
			pipeline_retry_count++;
			goto repipeline;
		}
	}
	else
	{
		if (redis_expire_jitike_keys(this->ctx, key, JITIKE_EXPIRE_TIME, true) != 0)
		{
			DBG1(DBG_CFG, "ike_updown: Failed expiring keys for hashset %s", key);
		}
	}

jitike:

	return TRUE;
}

METHOD(listener_t, alert, bool,
	private_jitike_redis_t *this, ike_sa_t *ike_sa, alert_t alert, va_list args)
{
	DBG2(DBG_CFG, "jitike alert: Received alert: %d for SPIs", alert);

	switch (alert)
	{
		case ALERT_HALF_OPEN_TIMEOUT:
			ike_updown(this, ike_sa, FALSE);
			break;
	default:
		break;
	}

out:
	return TRUE;
}

METHOD(listener_t, ike_state_change, bool,
	private_jitike_redis_t *this, ike_sa_t *ike_sa, ike_sa_state_t new)
{
	char key[JITIKE_MAX_KEY_SIZE];

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key(ike_sa, key) != 0) {
		DBG1(DBG_CFG, "ike_state_change: Error getting key");
		goto out;
	}

	DBG2(DBG_CFG, "ike_state_change: Received message for SPI %s : State moved to %d", key, new);

	if (new == IKE_ESTABLISHED)
	{
		time_t delete, established, t;
		redisReply *reply = NULL;

		/**
		 * Set a key expiration based on DELET-ESTABLISHED.
		 */
		delete = ike_sa->get_statistic(ike_sa, STAT_DELETE);
		established = ike_sa->get_statistic(ike_sa, STAT_ESTABLISHED);
		t = delete - established;
		if (t)
		{
			DBG2(DBG_CFG, "ike_state_change: Setting key expiration for %s to %d seconds", key, t+this->expire);

			if (redis_expire_jitike_keys(this->ctx, key, t+this->expire, false) != 0)
			{
				DBG1(DBG_CFG, "ike_state_change: Failed expiring keys for hashset %s", key);
			}
		}
		else
		{
			DBG1(DBG_CFG, "ike_state_change: t was invalid: %d", t);
		}

		if (store_jitid(this->ctx, ike_sa, key) != 0)
		{
			DBG1(DBG_CFG, "ike_keys: Error trying to store JITID for key %s", key);
		}

		/**
		 * Delete the IKE_REKEY_ID and friends from the hashset, if it exists.
		 */
		reply = jitikeRedisCommand(this->ctx, "HDEL %s %s %s %s", key,
			JI_IKE_REKEY_ID, JI_ALG_OLD_PRF, JI_OLD_SKD);
		if (reply == NULL)
		{
			DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL, cannot delete IKE_REKEY_ID");
		}
		else
		{
			/* Delete the previous reply */
			freeReplyObject(reply);
		}
	}
out:
	return TRUE;
}

/**
 * This will delete all traffic selector keys from the JITIKE hashset.
 */
int clean_ts_from_hashset(private_jitike_redis_t *this, char *key, char *field)
{
	int ret = 0;
	redisReply *reply = NULL, *pReply = NULL;
	char scan_str[30];
	size_t k = 0;
	unsigned int count = 0;
	bool pipeline_error = FALSE;
	int pipeline_retry_count = 0;

	if ((this == NULL) || (key == NULL) || (field == NULL))
	{
		DBG1(DBG_CFG, "clean_ts_from_hashset: Invalid input parameters");
		ret = -1;
		goto out;
	}

	snprintf(scan_str, 30, "%s*", field);

	/* Scan for all fields on the hashset */
	reply = jitikeRedisCommand(this->ctx, "HSCAN %s 0 MATCH %s COUNT 1000", key, scan_str);

	if (reply == NULL)
	{
		DBG1(DBG_CFG, "clean_ts_from_hashset: jitikeRedisCommand returned NULL while running HGET, failing");
		ret = -1;
		goto out;
	}

	if (reply->type != REDIS_REPLY_ARRAY)
	{
		DBG1(DBG_CFG, "clean_ts_from_hashset: Found invalid reply type %d",
				reply->type);
		ret = -1;
		if (reply == NULL)
		{
			freeReplyObject(reply);
		}
		goto out;
	}

repipeline:
	/**
	 * Lock access to the context .
	 */
	jrc_mutex->lock(jrc_mutex);

	for (k=0; k < reply->elements; k+=2)
	{
		ret = redisAppendCommand(this->ctx, "HDEL %s %s", key, reply->element[k]->str);
		if (ret != REDIS_OK)
		{
			DBG1(DBG_CFG, "clean_ts_from_hashset: jitikeRedisCommand returned NULL while running HDEL, failing");
		}
		else
		{
			count++;
		}
	}

	while (count-- > 0)
	{
		pReply = jitikeRedisPipelineReadReply(this->ctx);

		if (pReply != NULL)
		{
			freeReplyObject(pReply);
		}
		else
		{
			/** Signal an error */
			pipeline_error = TRUE;
			goto out_of_loop;
		}
	}
out_of_loop:
	/**
	 * Unlock access to the context .
	 */
	jrc_mutex->unlock(jrc_mutex);

	if (pipeline_error == TRUE && (pipeline_retry_count < JITIKE_PIPELINE_RETRY_MAX))
	{
		DBG1(DBG_CFG, "clean_ts_from_hashset: pipeline error received, retrying cleaning in Redis for key %s", key);
		/**
		 * Recover from a pipeline error. In this case, we want to reset the counter
		 * variable and try again. However, we can only do this retry JITIKE_PIPELINE_RETRY_MAX
		 * times or we'll loop here forever in the case of Redis really being down. Be
		 * cautious.
		 */
		pipeline_error = FALSE;
		count = 0;
		pipeline_retry_count++;
		goto repipeline;
	}

out:
	/**
	 * We have already freed reply above before getting here.
	 */

	return ret;
}

METHOD(listener_t, child_keys, bool,
        private_jitike_redis_t *this, ike_sa_t *ike_sa, child_sa_t *child_sa,
        bool initiator, diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r)
{
	chunk_t secret;
	proposal_t *proposal;
	uint16_t alg, len;
	linked_list_t *local_ts, *remote_ts;
	enumerator_t *enumerator;
	traffic_selector_t *ts;
	u_int seg_i, seg_o;
	ike_sa_id_t *ike_sa_id;
	char key[JITIKE_MAX_KEY_SIZE];
	bool found_integrity = FALSE;
	int local_count = 0, remote_count = 0;
	char local_str[strlen(JI_LOCAL_TS)+6];
	char remote_str[strlen(JI_REMOTE_TS)+6];
	redisReply *reply = NULL;
	unsigned int cmd_count = 0;
	int format_ret = 0;
	char *buf = NULL;
	bool pipeline_error = FALSE;
	int pipeline_retry_count = 0;

	if (this->ctx == NULL) {
		DBG1(DBG_CFG, "jitike_redis child_keys Error getting redis context, failing");
		return TRUE;
	}

	if ((ike_sa_id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis child_keys Error getting ike_sa, failing");
		/* do not sync SA between nodes */
		return TRUE;
	}

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key_with_child(ike_sa, child_sa, key) != 0) {
		DBG1(DBG_CFG, "jitike_redis Error getting key");
		return TRUE;
	}

	DBG2(DBG_CFG, "jitike child_keys: Received keys for SPI %s", key);

	/**
	 * Before adding new traffic selectors into the JITIKE hashset, we simply remove
	 * all of the existing ones. We do this because the traffic selectors may have
	 * changed, and it's easier to simply remove them all and then re-add them when we
	 * receive child keys.
	 */
	if (clean_ts_from_hashset(this, key, JI_LOCAL_TS) != 0)
	{
		DBG1(DBG_CFG, "child_keys: Error deleting %s fields from hashset", JI_LOCAL_TS);
	}
	if (clean_ts_from_hashset(this, key, JI_REMOTE_TS) != 0)
	{
		DBG1(DBG_CFG, "child_keys: Error deleting %s fields from hashset", JI_REMOTE_TS);
	}

repipeline:
	/**
	 * Lock the context before we begin pipeling commands.
	 * NOTE: If this becomes an issue, we can move to a per-thread Redis context to move away
	 * from locks.
	 */
	jrc_mutex->lock(jrc_mutex);

	add_redis_buffer(this->ctx, key, JI_ALLOC_ID, JITIKE_ALLOC_ID, this->alloc_id);
	cmd_count++;
	/**
	 * We want to set a TTL on the key right away.
	 */
	format_ret = redisFormatCommand(&buf, "EXPIRE %s %d", key, JITIKE_DEFAULT_TTL);
	if (format_ret != -1)
	{
		if (redisAppendFormattedCommand(this->ctx, buf, format_ret) == REDIS_ERR)
		{
			DBG1(DBG_CFG, "child_keys: Failed expiring keys for hashset %s", key);
		}
		else
		{
			cmd_count++;
		}
		free(buf);
	}
	add_redis_buffer(this->ctx, key, JI_IKE_ID, JITIKE_IKE_ID, ike_sa->get_id(ike_sa));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_INITIATOR, JITIKE_INITIATOR, (uint8_t)initiator);
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_INBOUND_SPI, JITIKE_INBOUND_SPI, ntohl(child_sa->get_spi(child_sa, TRUE)));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_OUTBOUND_SPI, JITIKE_OUTBOUND_SPI, ntohl(child_sa->get_spi(child_sa, FALSE)));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_INBOUND_CPI, JITIKE_INBOUND_CPI, ntohs(child_sa->get_cpi(child_sa, TRUE)));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_OUTBOUND_CPI, JITIKE_OUTBOUND_CPI, ntohs(child_sa->get_cpi(child_sa, FALSE)));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_IPSEC_MODE, JITIKE_IPSEC_MODE, child_sa->get_mode(child_sa));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_IPCOMP, JITIKE_IPCOMP, child_sa->get_ipcomp(child_sa));
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_CONFIG_NAME_CHILD, JITIKE_CONFIG_NAME, child_sa->get_name(child_sa));
	cmd_count++;

	proposal = child_sa->get_proposal(child_sa);
	found_integrity = proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &alg, NULL);
	if (found_integrity == TRUE)
	{
		add_redis_buffer(this->ctx, key, JI_ALG_INTEG_CHILD, JITIKE_ALG_INTEG, alg);
		cmd_count++;
	}
	if (proposal->get_algorithm(proposal, DIFFIE_HELLMAN_GROUP, &alg, NULL))
	{
		add_redis_buffer(this->ctx, key, JI_ALG_DH_CHILD, JITIKE_ALG_DH, alg);
		cmd_count++;
	}
	if (proposal->get_algorithm(proposal, EXTENDED_SEQUENCE_NUMBERS, &alg, NULL))
	{
		add_redis_buffer(this->ctx, key, JI_ESN_CHILD, JITIKE_ESN, alg);
		cmd_count++;
	}
	add_redis_buffer(this->ctx, key, JI_NONCE_I_CHILD, JITIKE_NONCE_I, nonce_i);
	cmd_count++;
	add_redis_buffer(this->ctx, key, JI_NONCE_R_CHILD, JITIKE_NONCE_R, nonce_r);
	cmd_count++;
	if (dh && dh->get_shared_secret(dh, &secret))
	{
		add_redis_buffer(this->ctx, key, JI_SECRET_CHILD, JITIKE_SECRET, secret);
		cmd_count++;
		chunk_clear(&secret);
	}

	local_ts = linked_list_create();
	remote_ts = linked_list_create();

	/**
	 * NOTE: The +6 in each of the local and remote traffic selector keys on the hashset means
	 * this code currently supports up to 9999 traffic selectors per CHILD_SA. This seems like
	 * a reasonable number.
	 */
	enumerator = child_sa->create_ts_enumerator(child_sa, TRUE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		snprintf(local_str, strlen(JI_LOCAL_TS)+6, "%s_%03d", JI_LOCAL_TS, local_count);
		add_redis_buffer(this->ctx, key, local_str, JITIKE_LOCAL_TS, ts);
		cmd_count++;
		local_ts->insert_last(local_ts, ts);
		local_count++;
	}
	enumerator->destroy(enumerator);

	enumerator = child_sa->create_ts_enumerator(child_sa, FALSE);
	while (enumerator->enumerate(enumerator, &ts))
	{
		snprintf(remote_str, strlen(JI_REMOTE_TS)+6, "%s_%03d", JI_REMOTE_TS, remote_count);
		add_redis_buffer(this->ctx, key, remote_str, JITIKE_REMOTE_TS, ts);
		cmd_count++;
		remote_ts->insert_last(remote_ts, ts);
		remote_count++;
	}
	enumerator->destroy(enumerator);

	local_ts->destroy(local_ts);
	remote_ts->destroy(remote_ts);

	/**
	 * Pipeline the commands here by calling jitikeRedisPipelineReadReply for each
	 * of the commands we sent. Then unlock the context.
	 */
	while (cmd_count-- > 0)
	{
		reply = jitikeRedisPipelineReadReply(this->ctx);

		if (reply != NULL)
		{
			freeReplyObject(reply);
		}
		else
		{
			/** Signal an error */
			pipeline_error = TRUE;
			goto out_of_loop;
		}
	}
out_of_loop:
	jrc_mutex->unlock(jrc_mutex);

	if (pipeline_error == TRUE && (pipeline_retry_count < JITIKE_PIPELINE_RETRY_MAX))
	{
		DBG1(DBG_CFG, "child_keys: pipeline error received, retrying storing of hashset in Redis for key %s", key);
		/**
		 * Recover from a pipeline error. This means we should delete the (potentially)
		 * partially complete hashset in Redis, reset the cmd_count variable, and try
		 * again. However, we can only do this retry JITIKE_PIPELINE_RETRY_MAX times or
		 * we'll loop here forever. Be cautious.
		 */
		redisReply *pipeReply = NULL;

		pipeReply = jitikeRedisCommand(this->ctx, "DEL %s", key);
		if (pipeReply != NULL)
		{
			freeReplyObject(pipeReply);
		}
		else
		{
			DBG1(DBG_CFG, "ike_keys: Error trying to delete hashset %s", key);
		}
		pipeline_error = FALSE;
		cmd_count = 0;
		pipeline_retry_count++;
		goto repipeline;
	}

	/**
	 * If pipeline_error is true, it means we've reached the retry limit and we should just move on
	 * and not try to store keys.
	 */
	if (pipeline_error == TRUE)
	{
		goto out;
	}

	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &alg, &len))
	{
		chunk_t encr_i, integ_i, encr_r, integ_r;
		keymat_v2_t *keymat_v2 = (keymat_v2_t*)ike_sa->get_keymat(ike_sa);
		bool ok = FALSE;

		add_attribute(this->ctx, key, JI_ALG_ENCR_CHILD, JITIKE_ALG_ENCR, alg);
		if (len)
		{
			add_attribute(this->ctx, key, JI_ALG_ENCR_LEN_CHILD, JITIKE_ALG_ENCR_LEN, len);
		}

		/* Get us some keys! */
		ok = keymat_v2->derive_child_keys(keymat_v2, proposal, dh, nonce_i, nonce_r,
				&encr_i, &integ_i, &encr_r, &integ_r);

		switch(alg) {
			case ENCR_UNDEFINED:
				/* no encryption */
				break;
			case ENCR_AES_CCM_ICV16:
			case ENCR_AES_GCM_ICV16:
			case ENCR_NULL_AUTH_AES_GMAC:
			case ENCR_CAMELLIA_CCM_ICV16:
			case ENCR_CHACHA20_POLY1305:
			case ENCR_AES_CCM_ICV12:
			case ENCR_AES_GCM_ICV12:
			case ENCR_CAMELLIA_CCM_ICV12:
			case ENCR_AES_CCM_ICV8:
			case ENCR_AES_GCM_ICV8:
			case ENCR_CAMELLIA_CCM_ICV8:
				if (encr_i.len != 0)
				{
					if (initiator)
					{
						add_attribute(this->ctx, key, JI_IN_AEAD_KEY, JITIKE_IN_AEAD_KEY, encr_i);
					}
					else
					{
						add_attribute(this->ctx, key, JI_OUT_AEAD_KEY, JITIKE_OUT_AEAD_KEY, encr_i);
					}
				}
				if (encr_r.len != 0)
				{
					if (initiator)
					{
						add_attribute(this->ctx, key, JI_OUT_AEAD_KEY, JITIKE_OUT_AEAD_KEY, encr_r);
					}
					else
					{
						add_attribute(this->ctx, key, JI_IN_AEAD_KEY, JITIKE_IN_AEAD_KEY, encr_r);
					}
				}
				if (found_integrity)
				{
					if (integ_i.len != 0)
					{
						if (initiator)
						{
							add_attribute(this->ctx, key, JI_IN_AUTH_KEY, JITIKE_IN_AUTH_KEY, integ_i);
						}
						else
						{
							add_attribute(this->ctx, key, JI_OUT_AUTH_KEY, JITIKE_OUT_AUTH_KEY, integ_i);
						}
					}
					if (integ_r.len != 0)
					{
						if (initiator)
						{
							add_attribute(this->ctx, key, JI_OUT_AUTH_KEY, JITIKE_OUT_AUTH_KEY, integ_r);
						}
						else
						{
							add_attribute(this->ctx, key, JI_IN_AUTH_KEY, JITIKE_IN_AUTH_KEY, integ_r);
						}
					}
				}
				break;
			default:
				if (encr_i.len != 0)
				{
					if (initiator)
					{
						add_attribute(this->ctx, key, JI_IN_CRYPTO_KEY, JITIKE_IN_CRYPTO_KEY, encr_i);
					}
					else
					{
						add_attribute(this->ctx, key, JI_OUT_CRYPTO_KEY, JITIKE_OUT_CRYPTO_KEY, encr_i);
					}
				}
				if (encr_r.len != 0)
				{
					if (initiator)
					{
						add_attribute(this->ctx, key, JI_OUT_CRYPTO_KEY, JITIKE_OUT_CRYPTO_KEY, encr_r);
					}
					else
					{
						add_attribute(this->ctx, key, JI_IN_CRYPTO_KEY, JITIKE_IN_CRYPTO_KEY, encr_r);
					}
				}
				if (found_integrity)
				{
					if (integ_i.len != 0)
					{
						if (initiator)
						{
							add_attribute(this->ctx, key, JI_IN_AUTH_KEY, JITIKE_IN_AUTH_KEY, integ_i);
						}
						else
						{
							add_attribute(this->ctx, key, JI_OUT_AUTH_KEY, JITIKE_OUT_AUTH_KEY, integ_i);
						}
					}
					if (integ_r.len != 0)
					{
						if (initiator)
						{
							add_attribute(this->ctx, key, JI_OUT_AUTH_KEY, JITIKE_OUT_AUTH_KEY, integ_r);
						}
						else
						{
							add_attribute(this->ctx, key, JI_IN_AUTH_KEY, JITIKE_IN_AUTH_KEY, integ_r);
						}
					}
				}
				break;
		}

	}

out:
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool,
	private_jitike_redis_t *this, ike_sa_t *old, ike_sa_t *new)
{
	enumerator_t *csas;
	child_sa_t *child_sa;

	DBG2(DBG_CFG, "jitike ike_rekey: Received event");

	/* Move child keys to new IKE */
	csas = new->create_child_sa_enumerator(new);
	while (csas->enumerate(csas, &child_sa))
	{
		char key[JITIKE_MAX_KEY_SIZE];
		char newkey[JITIKE_MAX_KEY_SIZE];
		redisReply *reply = NULL;
		ike_sa_id_t *ike_sa_id;

		/* We'll use this as the key for storing the information in redis */
		if (redis_get_key_with_child(old, child_sa, key) != 0) {
			DBG1(DBG_CFG, "jitike ike_rekey: Error getting child_sa key");
			goto out_loop;
		}

		/* We'll use this as the key for storing the information in redis */
		if (redis_get_key_with_child(new, child_sa, newkey) != 0) {
			DBG1(DBG_CFG, "jitike ike_rekey: Error getting new child_sa key");
			goto out_loop;
		}

		if ((ike_sa_id = new->get_id(new)) == NULL) {
			DBG1(DBG_CFG, "jitike ike_rekey: Error getting ike_sa, failing");
			goto out_loop;
		}

		/* Get the data we need from redis */
		reply = jitikeRedisCommand(this->ctx, "RENAME %s %s", key, newkey);

		/**
		 * jitikeRedisCommand can return NULL if Redis is unreachable.
		 */
		if (reply == NULL)
		{
			DBG1(DBG_CFG, "jitike ike_rekey: jitikeRedisCommand returned NULL while running RENAME, failing");
		}

		/* Set the IKE_ID */
		add_attribute(this->ctx, newkey, JI_IKE_ID, JITIKE_IKE_ID, ike_sa_id);

out_loop:
		DBG2(DBG_CFG, "jitike ike_rekey: Successfully renamed %s key to %s", key, newkey);
	}
	csas->destroy(csas);

	ike_updown(this, old, FALSE);
	ike_updown(this, new, TRUE);

out:

	return TRUE;
}

METHOD(listener_t, child_state_change, bool,
        private_jitike_redis_t *this, ike_sa_t *ike_sa,
        child_sa_t *child_sa, child_sa_state_t state)
{
	char key[JITIKE_MAX_KEY_SIZE];

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key_with_child(ike_sa, child_sa, key) != 0) {
		DBG1(DBG_CFG, "jitike_redis Error getting key");
		return TRUE;
	}

	switch (state)
	{
		case CHILD_CREATED:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_CREATED for SPI %s", key);
			break;
		case CHILD_ROUTED:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_ROUTED for SPI %s", key);
			break;
		case CHILD_INSTALLING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_INSTALLING for SPI %s", key);
			break;
		case CHILD_INSTALLED:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_INSTALLED for SPI %s", key);
			break;
		case CHILD_UPDATING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_UPDATING for SPI %s", key);
			break;
		case CHILD_REKEYING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_REKEYING for SPI %s", key);
			break;
		case CHILD_REKEYED:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_REKEYED for SPI %s", key);
			break;
		case CHILD_RETRYING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_RETRYING for SPI %s", key);
			break;
		case CHILD_DELETING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_DELETING for SPI %s", key);
			break;
		case CHILD_DELETED:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_DELETED for SPI %s", key);
			break;
		case CHILD_DESTROYING:
			DBG2(DBG_CFG, "jitike child_state_change: Received CHILD_DESTROYING for SPI %s", key);
			break;
		default:
			DBG2(DBG_CFG, "jitike child_state_change: Received UNKNOWN for SPI %s", key);
			break;
	}

	if (state == CHILD_INSTALLED && ike_sa->has_condition(ike_sa, COND_FATAL))
	{
		DBG2(DBG_CFG, "jitike child_state_change: processing fatal condition");
		lib->scheduler->schedule_job_ms(lib->scheduler, (job_t*)
			delete_ike_sa_job_create(ike_sa->get_id(ike_sa), TRUE), 100);
		return TRUE;
	}

	if (state == CHILD_INSTALLED)
	{
		time_t t;
		time_t current;

		current = time_monotonic(NULL);

		/**
		 * Use the hard limit first, then the soft limit as a fallback.
		 */
		t = child_sa->get_lifetime(child_sa, TRUE);
		if (t == 0)
		{
			t = child_sa->get_lifetime(child_sa, FALSE);
		}

		if (t)
		{
			DBG2(DBG_CFG, "child_state_change: Setting key expiration for %s to %d seconds", key, t+this->expire-current);

			if (redis_expire_jitike_keys(this->ctx, key, t+this->expire-current, false) != 0)
			{
				DBG1(DBG_CFG, "child_state_change: Failed expiring keys for hashset %s", key);
			}
		}
		else
		{
			DBG1(DBG_CFG, "child_state_change: t was invalid: %d", t);
		}
	}

	if (state == CHILD_DELETED)
	{
		redisReply *reply = NULL;

		DBG2(DBG_CFG, "child_state_change: Expiring CHILD_SA hashset %s", key);

		/**
		 * Delete the CHILD_SA hashset now.
		 */
		reply = jitikeRedisCommand(this->ctx, "DEL %s", key);

		if (reply != NULL)
		{
			freeReplyObject(reply);
		}
	}

	return TRUE;
}

METHOD(listener_t, message_hook, bool,
	private_jitike_redis_t *this, ike_sa_t *ike_sa, message_t *message,
	bool incoming, bool plain)
{
	ike_sa_id_t *ike_sa_id;
	char key[JITIKE_MAX_KEY_SIZE];
	ike_sa_state_t ike_state = ike_sa->get_state(ike_sa);
	redisReply *reply = NULL;

	/* We'll use this as the key for storing the information in redis */
	if (redis_get_key(ike_sa, key) != 0) {
		DBG1(DBG_CFG, "jitike_redis Error getting key");
		return TRUE;
	}

	if ((ike_sa_id = ike_sa->get_id(ike_sa)) == NULL) {
		DBG1(DBG_CFG, "jitike_redis message_hook Error getting ike_sa_id");
		goto jitike;
	}

	DBG2(DBG_CFG, "message_hook: exchange (%d) with ID (%d, remember, we add one to this) incoming (%s) for SPI %.16"PRIx64"_i %.16"PRIx64"_r, plain (%d), version %d, state (%d)",
			message->get_exchange_type(message),
			message->get_message_id(message),
			incoming ? "true": "false",
			be64toh(ike_sa_id->get_initiator_spi(ike_sa_id)),
			be64toh(ike_sa_id->get_responder_spi(ike_sa_id)),
			plain, ike_sa->get_version(ike_sa), ike_state);

	if ((ike_state == IKE_REKEYED) || (ike_state == IKE_DELETING) || (ike_state == IKE_DESTROYING))
	{
		DBG2(DBG_CFG, "jitike_redis message_hook: Skipping storing MID as state is %d", ike_state);
		goto jitike;
	}

	if (plain && ike_sa->get_version(ike_sa) == IKEV2)
	{
		if (message->get_exchange_type(message) != IKE_SA_INIT &&
				message->get_request(message))
		{       /* we sync on requests, but skip it on IKE_SA_INIT */

			reply = jitikeRedisCommand(this->ctx, "EXISTS %s", key);
			if (reply == NULL)
			{
				DBG1(DBG_CFG, "message_hook: Error checking if hashset %s exists", key);
				goto jitike;
			}
			if (reply->type != REDIS_REPLY_INTEGER)
			{
				DBG1(DBG_CFG, "message_hook: Invalid reply type (%d) when checking key %s", reply->type, key);
				goto jitike;
			}
			if (reply->integer == 0)
			{
				DBG1(DBG_CFG, "message_hook: We have a problem: Trying to save %s message ID for hashset %s, skipping save",
					incoming ? "responder" : "initiator", key);
				goto jitike;
			}

			if (incoming)
			{
				DBG2(DBG_CFG, "message_hook: Saving responder message ID (MID) of %d", message->get_message_id(message));
				add_attribute(this->ctx, key, JI_RESP_MID, JITIKE_RESP_MID, message->get_message_id(message) + 1);
			}
			else
			{
				DBG2(DBG_CFG, "message_hook: Saving initiator message ID (MID) of %d", message->get_message_id(message));
				add_attribute(this->ctx, key, JI_INIT_MID, JITIKE_INIT_MID, message->get_message_id(message) + 1);
			}
		}
	}
	if (ike_sa->get_version(ike_sa) == IKEV1)
	{
		keymat_v1_t *keymat;
		chunk_t iv;

		/* we need the last block (or expected next IV) of Phase 1, which gets
		 * updated after successful en-/decryption depending on direction */
		if (incoming == plain)
		{
			if (message->get_message_id(message) == 0)
			{
				keymat = (keymat_v1_t*)ike_sa->get_keymat(ike_sa);
				if (keymat->get_iv(keymat, 0, &iv))
				{
					add_attribute(this->ctx, key, JI_IV, JITIKE_IV, iv);
				}
			}
		}
	}
	if (plain && ike_sa->get_version(ike_sa) == IKEV1 &&
			message->get_exchange_type(message) == INFORMATIONAL_V1)
	{
		notify_payload_t *notify;
		chunk_t data;
		uint32_t seq;

		notify = message->get_notify(message, DPD_R_U_THERE);
		if (notify)
		{
			data = notify->get_notification_data(notify);
			if (data.len == 4)
			{
				seq = untoh32(data.ptr);
				if (incoming)
				{
					add_attribute(this->ctx, key, JI_RESP_MID, JITIKE_RESP_MID, seq + 1);
				}
				else
				{
					add_attribute(this->ctx, key, JI_INIT_MID, JITIKE_INIT_MID, seq + 1);
				}
			}
		}
	}

jitike:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return TRUE;
}

void subCallback(redisAsyncContext *c, void *reply, void *privdata)
{
	int j = 0;
	redisReply *r = (redisReply *)reply;
	private_jitike_redis_t *pjr = (private_jitike_redis_t *)privdata;
	char key[JITIKE_MAX_KEY_SIZE];

	DBG2(DBG_CFG, "jitike_redis PRIVATE DATA is %p", pjr);

	if (reply == NULL) {
		DBG1(DBG_CFG, "jitike_redis Error receiving published information");
		return;
	}

	if (pjr == NULL) {
		DBG1(DBG_CFG, "jitike_redis private data is NULL");
		return;
	}

	/*
	 * The format of what we received looks like this:
	 *
	 * r->element[0].type == REDIS_REPLY_STRING
	 * r->element[0].str  == "message"
	 * r->element[1].type == REDIS_REPLY_STRING
	 * r->element[1].str  == JITIKE_REDIS_CHANNEL
	 * r->element[2].type == REDIS_REPLY_STRING
	 * r->element[2].str  == "unique key we generated and stored in redis"
	 */
	if (r->type != REDIS_REPLY_ARRAY || r->elements != 3) {
		DBG1(DBG_CFG, "jitike_redis Found invalid type (%d)  or element count (%d)",
			r->type, r->elements);
		return;
	}

	/* Do stuff with the data */
	DBG2(DBG_CFG, "jitike_redis received published information with %d items", r->elements);

	for (j=2; j<r->elements; j++) {
		if (r->element[j]->type == REDIS_REPLY_STRING) {
			DBG2(DBG_CFG, "jitike_redis Received reply string %s", r->element[j]->str);

			snprintf(key, JITIKE_MAX_KEY_SIZE, "%s", r->element[j]->str);

			return;
		}
	}

	return;
}

/**
 * See header file.
 */
METHOD(jitike_redis_t, transfer_ike, int,
	private_jitike_redis_t *this, const char *command)
{
	int ret = 0;
	redisReply *reply = NULL;

	if (!command) {
		ret = -1;
		goto out;
	}

	DBG2(DBG_CFG, "jitike_redis Transferring IKE %s", command);

	if ((reply = jitikeRedisCommand(this->ctx, "PUBLISH %s %s", JITIKE_REDIS_CHANNEL, command)) != REDIS_OK) {
		DBG1(DBG_CFG, "transfer_ike Failed subscribing to shared redis channel");
		ret = -1;
		goto out;
	}

	/**
	 * jitikeRedisCommand can return NULL if Redis is unreachable.
	 */
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "jitike transfer_ike: jitikeRedisCommand returned NULL while running HGET, failing");
		goto out;
	}

	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

out:
	return ret;
}

/**
 * See header file.
 */
METHOD(jitike_redis_t, handle_redis_fifo, int,
	private_jitike_redis_t *this, const char *command)
{
	//return read_all_fields_for_key(this, command);
	return 0;
}

/**
 * Get the redisAsyncContext
 */
METHOD(jitike_redis_t, get_redis_ctx, redisContext *,
	private_jitike_redis_t *this)
{
	return this->ctx;
}

/* Forward declaration */
int connect_redis_sync(private_jitike_redis_t *this);

/**
 * Reconnect to a Redis master as indicated by Redis Sentinel
 */
METHOD(jitike_redis_t, redis_sentinel_reconnect_master, redisContext *,
	private_jitike_redis_t *this)
{
	redisContext *lctx = NULL;

	if (this->ctx != NULL)
	{
		redisFree(this->ctx);
		this->ctx = NULL;
	}

	if (connect_redis_sync(this) != 0)
	{
		DBG1(DBG_CFG, "redis_sentinel_reconnect_master: Failed reconnecting context");
		goto out;
	}

	lctx = this->ctx;
out:
	return lctx;
}

/* Forward declaration */
int destroy_sentinel_cfg(private_jitike_redis_t *this);

/**
 * Tear-down redis parameters.
 */
METHOD(jitike_redis_t, destroy, void,
        private_jitike_redis_t *this)
{
	destroy_sentinel_cfg(this);
	redisFree(this->ctx);
	jrc_mutex->destroy(jrc_mutex);

	free(this);
}

/**
 * Setup synchronous redis connection.
 */
int connect_redis_sync(private_jitike_redis_t *this)
{
	redisReply *reply = NULL;
	int ret = 0, set = 1;

	/* Connect to the master */
	this->ctx = redis_sentinel_connect_master(this->sentinel, this->timeout);
	if (this->ctx == NULL)
	{
		DBG1(DBG_CFG, "connect_redis: Sync connection error: cannot allocate redis context");
		ret = -1;
		goto out;
	}
	if (this->ctx->err != REDIS_OK)
	{
		DBG1(DBG_CFG, "redis_connect: Sync connection error to %s: %s",
			this->sentinel->name, this->ctx->errstr);
		redisFree(this->ctx);
		this->ctx = NULL;
		ret = -1;
		goto out;
	}

	/* Enable keepalive */
	if (redisEnableKeepAlive(this->ctx) != REDIS_OK)
	{
		DBG1(DBG_CFG, "connect_redis: Cannot enable KEEPALIVE for synchronous redis connection");
		ret = -1;
		goto out;
	}

	/**
	 * NOTE: We call redisCommand() directly here rather than jitikeRedisCommand(). The reason we
	 * can do this is because this function (connectRedisSync()) is only called during initialization
	 * or from jitikeRedisCommand(), and in the latter case, there is a mutex which only allows a
	 * single caller to make it here at a timne.
	 */
	reply = redisCommand(this->ctx, "SELECT %s", this->db);
	if (reply != NULL) {
		freeReplyObject(reply);
	}

out:
	return ret;
}

/**
 * Setup the Sentinel configuration
 */
int setup_sentinel_cfg(private_jitike_redis_t *this)
{
	redis_sentinel_cfg_t *cfg = &this->sentinel_cfg;
	int i = 0, count = 0;
	char *sentinelname, *cfgstr, *token, *str, *tofree;

	/* Walk the config file list and create redis_addr_t entries for each one */
	cfgstr = lib->settings->get_str(lib->settings, "%s.plugins.jitike.redis.sentinel_hosts", NULL, lib->ns);
	if (cfgstr == NULL)
	{
		memset(cfg, 0, sizeof(redis_sentinel_cfg_t));
		return 0;
	}

	sentinelname = lib->settings->get_str(lib->settings, "%s.plugins.jitike.redis.sentinel_name", NULL, lib->ns);
	cfg->name = strdup(sentinelname);
	cfg->db = jitike_db;

	tofree = str = strdup(cfgstr);
	while ((token = strsep(&str, ",")) != NULL)
        {
		count++;
	}
	free(tofree);

	/* Allocate enough memory for all the Sentinel nodes */
	cfg->addr_count = count;
	cfg->addr_arr = calloc(count, sizeof(redis_addr_t));

	tofree = str = strdup(cfgstr);
	i = 0;
	while ((token = strsep(&str, ",")) != NULL)
        {
		if (redis_addr_cfg_parse(token, &cfg->addr_arr[i]) != 0)
		{
			DBG1(DBG_CFG, "setup_sentinel_cfg: Error parsing token string %s", token);
		}

		DBG1(DBG_CFG, "setup_sentinel_cfg: Found host %s port %d for slot %d",
			cfg->addr_arr[i].host, cfg->addr_arr[i].port, i);

		i++;
	}
	free(tofree);

	/* Create the Sentinel */
	this->sentinel = redis_sentinel_create(&this->sentinel_cfg);
	if (this->sentinel == NULL)
	{
		DBG1(DBG_CFG, "setup_sentinel_cfg: Failed creating Sentinel");
		return -1;
	}

	return 0;
}

/**
 * Tear down the Sentinel configuration
 */
int destroy_sentinel_cfg(private_jitike_redis_t *this)
{
	redis_sentinel_cfg_t *cfg = &this->sentinel_cfg;
	int ret = 0, i = 0;

	if (cfg->name)
	{
		free(cfg->name);
	}

	for (i=0; i<cfg->addr_count; i++)
	{
		free(cfg->addr_arr[i].host);
	}
	if (cfg->addr_arr)
	{
		free(cfg->addr_arr);
	}

	return ret;
}

/**
 * Setup redis parameters.
 */
jitike_redis_t *jitike_redis_create(void)
{
	private_jitike_redis_t *this;
	int ret;

	INIT(this,
		.public = {
			.listener = {
				.alert = _alert,
				.ike_keys = _ike_keys,
				.ike_updown = _ike_updown,
				.ike_rekey = _ike_rekey,
				.ike_state_change = _ike_state_change,
				.child_keys = _child_keys,
				.child_state_change = _child_state_change,
				.message = _message_hook,
			},
			.destroy = _destroy,
			.get_redis_ctx = _get_redis_ctx,
			.handle_redis_fifo = _handle_redis_fifo,
			.transfer_ike = _transfer_ike,
			.redis_sentinel_reconnect_master = _redis_sentinel_reconnect_master,
                },
		.local_redis = lib->settings->get_str(lib->settings, "%s.plugins.jitike.redis.local_redis",
						DEFAULT_REDIS_HOSTNAME, lib->ns),
		.db = lib->settings->get_str(lib->settings, "%s.plugins.jitike.redis.db",
						DEFAULT_REDIS_DB, lib->ns),
		.alloc_id  = lib->settings->get_str(lib->settings, "%s.plugins.jitike.redis.alloc_id",
						DEFAULT_REDIS_ALLOC_ID, lib->ns),
		.timeout = {
			.tv_sec = lib->settings->get_int(lib->settings, "%s.plugins.jitike.redis.connect_sec",
						DEFAULT_REDIS_TIMEOUT_SEC, lib->ns),
			.tv_usec = lib->settings->get_int(lib->settings, "%s.plugins.jitike.redis.connect_usec",
						DEFAULT_REDIS_TIMEOUT_USEC, lib->ns),
		},
		.expire = lib->settings->get_int(lib->settings, "%s.plugins.jitike.ike_expire_time",
						JITIKE_KEY_GRACE_PERIOD, lib->ns),
        );

	jitike_db = atoi(this->db);
	jrc_mutex = mutex_create(MUTEX_TYPE_DEFAULT);

	/* Setup Sentinel information */
	if (setup_sentinel_cfg(this) != 0)
	{
		DBG1(DBG_CFG, "jitike_redis_create: Cannot setup Sentinel information");
		return NULL;
	}

	/* Connect to redis */
	if (connect_redis_sync(this) != 0)
	{
		DBG1(DBG_CFG, "jitike_redis_create: Cannot connect synchronously to redis");
		return NULL;
	}

	/* Register our SPI generator */
	if (jitike_spi_generator_register() != TRUE)
	{
		DBG1(DBG_CFG, "jitike_redis_create: Failed creating JITIKE SPI generator");
	}

	/* Start the async job */
	lib->processor->queue_job(lib->processor, (job_t*)start_async_job_create(this->sentinel, this->local_redis, this->timeout, this->alloc_id));

	DBG1(DBG_CFG, "jitike_redis Finished intitializing plugin");

	jrc_redis = &this->public;

	return &this->public;
}
