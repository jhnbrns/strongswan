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

#include "redis_interface.h"
#include "redis_load_ike.h"
#include "redis_child_rekey_job.h"
#include "redis_ike_rekey_job.h"
#include "redis_publish_job.h"
#include "jitike_redis.h"
#include "jitike_redis_sentinel.h"
#include "jitike_db.h"

#include <utils/debug.h>
#include <threading/mutex.h>

#define DEFAULT_REDIS_HOSTNAME          "127.0.0.1"
#define DEFAULT_REDIS_PORT              6379
#define DEFAULT_REDIS_DB                "0"
#define DEFAULT_REDIS_TIMEOUT_SEC       1
#define DEFAULT_REDIS_TIMEOUT_USEC      500000
#define DEFAULT_REDIS_ALLOC_ID          "d3ad-833f-d3ad-833f"

/**
 * The local redis server (e.g. in the same DC)
 */
char *local_redis;

/**
 * Used by charonRedisCommand() to reconnect to Redis via Sentinel
 */
redis_interface_t *charon_redis;

typedef struct redis_connect_info_t redis_connect_info_t;

/**
 * The per-redis data we need when connecting to multiple redis instances
 */
struct redis_connect_info_t {

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
	 * Sentinel configuration
	 */
	redis_sentinel_cfg_t sentinel_cfg;

	/**
	 * The omniscient Sentinel
	 */
	redis_sentinel_t *sentinel;

	/**
	 * DB to connect to.
	 */
	int db;

	/**
	 * Connection timeout.
	 */
	struct timeval timeout;

	/**
	 * Channel to subscribe to.
	 */
	char *channel;

	/**
	 * mutex for listeners
	 */
	mutex_t *mutex;

	/**
	 * A line of config with the sentinel hosts and ports for this DC
	 */
	char *dc_sentinels;
};

typedef struct private_redis_interface_t private_redis_interface_t;

/**
 * Private data of a redis_interface_t object.
 */
struct private_redis_interface_t {

	/**
	 * Public part of redis_interface_t object.
	 */
	redis_interface_t public;
	mutex_t *mutex;

	/**
	 * The node's unique allocation ID
	 */
	char *alloc_id;

	/**
	 * The config file string "sentinel_hosts"
	 */
	char *cinfo_str;

	/**
	 * How many redis_connect_info_t structures we are using
	 */
	int cinfo_count;

	/**
	 * The array of redis_connect_info_t structures
	 */
	redis_connect_info_t **cinfo;
};


/**
 * NOTE: This function is expected to be called with the mutex for this redis_connect_info_t slot
 * already in the lock positon.
 */
int sync_connect_single_redis(redis_connect_info_t *c)
{
	redisReply *reply = NULL;
	int ret = 0, sockret = 0, set = 1;

	c->ctx = redis_sentinel_connect_master(c->sentinel, c->timeout);
	if (c->ctx == NULL)
	{
		DBG1(DBG_CFG, "sync_connect_single_redis: Sync connection error: cannot allocate redis context");
		ret = -1;
		goto out;
	}
	if (c->ctx->err != REDIS_OK)
	{
		DBG1(DBG_CFG, "sync_connect_single_redis: Sync connection error to %s: %s",
				c->sentinel->name, c->ctx->errstr);
		redisFree(c->ctx);
		ret = -1;
		goto out;
	}

	/* Enable keepalive */
	if (redisEnableKeepAlive(c->ctx) != REDIS_OK)
	{
		DBG1(DBG_CFG, "sync_connect_single_redis: Cannot enable KEEPALIVE for synchronous redis connection");
		redisFree(c->ctx);
		ret = -1;
		goto out;
	}

	/**
	 * NOTE: We call redisCommand() directly here rather than charonRedisCommand(). The reason we
	 * can do this is because this function (connectRedisSync()) is only called during initialization
	 * or from charonRedisCommand(), and in the latter case, there is a mutex which only allows a
	 * single caller to make it here at a timne.
	 */
	reply = redisCommand(c->ctx, "SELECT %d", c->db);
	if (reply != NULL) {
		freeReplyObject(reply);
	}

out:
	return ret;
}

/**
 * Connect to each redis instance.
 */
int sync_connect_all_redis(private_redis_interface_t *this)
{
	int i, ret = 0;
	redis_connect_info_t *c;

	for (i = 0; i < this->cinfo_count; i++)
	{
		c = this->cinfo[i];

		c->mutex->lock(c->mutex);
		ret = sync_connect_single_redis(c);
		c->mutex->unlock(c->mutex);
	}

out:
	return ret;
}

int search_redis(private_redis_interface_t *this, int cinfo, redis_connect_info_t *c, char *alloc_id, uint64_t spi_i, uint64_t spi_r)
{
	char key[REDIS_MAX_KEY_SIZE];
	char searchkey[REDIS_MAX_KEY_SIZE];
	redisReply *reply = NULL;
	int ret = 0;
	size_t k = 0;
	bool found_ike_id = FALSE;
	redis_connect_info_t *local_c = this->cinfo[0]; 	/* Always in slot zero */
	ike_sa_t *ike_sa = NULL;
	ike_sa_id_t *ike_sa_id = NULL;
	uint32_t init_mid = 0, resp_mid = 0;

	/* Search for the key in redis */
	snprintf(searchkey, REDIS_MAX_KEY_SIZE, "%.16"PRIx64"_i-%.16"PRIx64"_r",
			spi_i, spi_r);

	reply = charonRedisCommand(cinfo, c->db, "KEYS %s", searchkey);

	/**
	 * charonRedisCommand() can return NULL in cases where Redis is uncreachable.
	 */
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL, failing");
		ret = -1;
		goto out;
	}

	/* Validate the reply */
	if (reply->type != REDIS_REPLY_ARRAY) {
		DBG1(DBG_CFG, "search_redis: Found invalid reply type: %d", reply->type);
		ret = -1;
		goto out;
	}

	/*
	 * We only expect a single key to be found, so log something bad if we find
	 * more than one.
	 */
	if (reply->elements == 0)
	{
		DBG1(DBG_CFG, "search_redis: Did not find key %s in redis", searchkey);
		ret = -1;
		goto out;
	}
	else if (reply->elements != 1)
	{
		DBG1(DBG_CFG, "search_redis: Found inconsistent number of keys in redis (%d) "
				"for searched key %s", reply->elements, searchkey);
		ret = -1;
		goto out;
	}

	/* Find the key and save it */
	snprintf(key, REDIS_MAX_KEY_SIZE, "%s", reply->element[0]->str);

	DBG2(DBG_CFG, "search_redis: Found redis key %s", key);

	/* Delete the previous reply */
	if (reply != NULL)
	{
		freeReplyObject(reply);
		reply = NULL;
	}

	/* Now find the IKE and load it */
	ret = charon_process_ike_add(cinfo, c->mutex, c->db, key);
	if (ret != 0)
	{
		DBG1(DBG_CFG, "search_redis: Error trying to process IKE add, failing");
		goto out;
	}

	/* We own this now, so make it so before notifying others to delete the IKE_SA */
	reply = charonRedisCommand(cinfo, c->db, "HSET %s %s %s", key, JI_ALLOC_ID, alloc_id);

	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL when executing HSET, failing");
		ret = -1;
		goto out;
	}
	else
	{
		/* Delete the previous reply */
		freeReplyObject(reply);
		reply = NULL;
	}

	/**
	 * Delete IKE_REKEY_ID and friends now as well, if it exists.
	 */
	reply = charonRedisCommand(cinfo, c->db, "HDEL %s %s %s %s", key,
		JI_IKE_REKEY_ID, JI_ALG_OLD_PRF, JI_OLD_SKD);
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL, cannot delete IKE_REKEY_ID");
		ret = -1;
		goto out;
	}
	else
	{
		/* Delete the previous reply */
		freeReplyObject(reply);
		reply = NULL;
	}

	/**
	 * STORE THE MID VALUES FROM THE OLD REDIS INTO THE NEW ONES HERE.
	 */
	ike_sa_id = ike_sa_id_create(IKEV2, htobe64(spi_i), htobe64(spi_r), FALSE);
	if (ike_sa_id == NULL)
	{
		DBG1(DBG_CFG, "search_redis: Error creating ike_sa_id for SPIs %.16"PRIx64"_i %.16"PRIx64"_r", spi_i, spi_r);
		ret = -1;
		goto out;
	}

	/**
	 * Checkout the IKE_SA
	 */
	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
	if (ike_sa == NULL)
	{
		/**
		 * If we failed, it may be because the ike_sa_id_t was an initiator, so try again.
		 */
		ike_sa_id->destroy(ike_sa_id);
		ike_sa_id = ike_sa_id_create(IKEV2, htobe64(spi_i), htobe64(spi_r), TRUE);
		ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
		if (ike_sa == NULL)
		{
			DBG1(DBG_CFG, "search_redis: Cannot checkout IKE_SA for SPIs %.16"PRIx64"_i %.16"PRIx64"_r", spi_i, spi_r);
			ret = -1;
			goto out;
		}
	}

	init_mid = ike_sa->get_message_id(ike_sa, TRUE);
	resp_mid = ike_sa->get_message_id(ike_sa, FALSE);
	reply = charonRedisCommand(0 /* Use slot zero here */, local_c->db, "HSET %s %s %d", key, JI_INIT_MID, init_mid);
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL when executing HSET, failing");
		ret = -1;
		goto out;
	}
	else if (reply->type != REDIS_REPLY_INTEGER)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned invalid type when executing HSET, failing");
		ret = -1;
		goto out;
	}
	freeReplyObject(reply);

	reply = charonRedisCommand(0 /* Use slot zero here */, local_c->db, "HSET %s %s %d", key, JI_RESP_MID, resp_mid);
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL when executing HSET, failing");
		ret = -1;
		goto out;
	}
	else if (reply->type != REDIS_REPLY_INTEGER)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned invalid type when executing HSET, failing");
		ret = -1;
		goto out;
	}
	freeReplyObject(reply);

	/* Find the IKE_SA_ID in the reply from redis */

	/* Lets get this party started! */
	reply = charonRedisCommand(cinfo, c->db, "HGETALL %s", key);

	/**
	 * charonRedisCommand() can return NULL in cases where Redis is uncreachable.
	 */
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "search_redis: charonRedisCommand returned NULL when executing HGETALL, failing");
		ret = -1;
		goto out;
	}

	/* Validate the reply */
	if (reply->type != REDIS_REPLY_ARRAY) {
		DBG1(DBG_CFG, "search_redis: Found invalid reply type: %d", reply->type);
		ret = -1;
		goto out;
	}

	DBG2(DBG_CFG, "search_redis: Found %d array items for %s", reply->elements, key);

	if (reply->elements == 0) {
		/* Otherwise, we're done */
		ret = 0;
		goto out;
	}

	for (k=0; k < reply->elements; k+=2)
	{
		if (strncmp(reply->element[k]->str, JI_IKE_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			char *buf;
			cb_radio_t *cb_radio;
			ike_channel_sa_id_encoding_t *enc;
			ike_sa_id_encoding_t *renc;
			size_t transfer_size = 0;

			if (reply->element[k+1]->len < sizeof(ike_sa_id_encoding_t))
			{
				DBG1(DBG_CFG, "search_redis: invalid size for JI_IKE_ID: %d",
					reply->element[k+1]->len);
				ret = -1;
				goto out;
			}

			renc = (ike_sa_id_encoding_t *)reply->element[k+1]->str;

			transfer_size = sizeof(cb_radio_t) + sizeof(ike_channel_sa_id_encoding_t) + strlen(alloc_id) + strlen(local_redis);
			buf = malloc(transfer_size);
			cb_radio = (cb_radio_t *)buf;
			cb_radio->message_type = CB_JITIKE;
			enc = (ike_channel_sa_id_encoding_t *)cb_radio->encoding;

			DBG2(DBG_CFG, "search_redis: Sending alloc_id %s to channel: IKE_SA SPI %.16"PRIx64"_i %.16"PRIx64"_r",
				alloc_id,
				be64toh(renc->initiator_spi),
				be64toh(renc->responder_spi));

			enc->initiator = renc->initiator;
			enc->ike_version = renc->ike_version;
			/** Send the next two in host byte order */
			enc->initiator_spi = be64toh(renc->initiator_spi);
			enc->responder_spi = be64toh(renc->responder_spi);
			enc->alloc_id_len = strlen(alloc_id);
			enc->hostname_len = strlen(local_redis);
			memcpy(enc->encoding, alloc_id, strlen(alloc_id));
			memcpy(enc->encoding+strlen(alloc_id), local_redis, strlen(local_redis));

			/* Free the previous reply */
			if (reply != NULL)
			{
				freeReplyObject(reply);
				reply = NULL;
			}

			DBG2(DBG_CFG, "search_redis: Publishing to host %s / port %d", c->ctx->tcp.host, c->ctx->tcp.port);

			/** Fire off the job now */
			lib->processor->queue_job(lib->processor, (job_t *)start_redis_publish_job_create(cinfo, c->db, TRUE, buf, transfer_size));

			free(buf);

			break;
		}
	}

out:
	if (ike_sa != NULL)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}

	if (ike_sa_id != NULL)
	{
		ike_sa_id->destroy(ike_sa_id);
	}

	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return ret;
}

METHOD(redis_interface_t, get_ike_from_redis, int,
        private_redis_interface_t *this, uint64_t spi_i, uint64_t spi_r)
{
	int i, ret = 0;
	redis_connect_info_t *c;

	/* Walk the array of redis connections searching for an IKE_SA */
	for (i = 0; i < this->cinfo_count; i ++)
	{
		c = this->cinfo[i];

		/**
		 * We need to check if c->ctx is NULL. Charon is multi-threaded, and we could be
		 * in the middle of reconnecting to Redis, meaning this context could be NULL.
		 */
		if (c->ctx == NULL)
		{
			continue;
		}

		DBG2(DBG_CFG, "get_ike_from_redis: Searching redis host %s", c->ctx->tcp.host);
		ret = search_redis(this, i, c, this->alloc_id, spi_i, spi_r);
		/* If ret is zero (0), we found it and we can stop searching */
		if (ret == 0)
		{
			DBG2(DBG_CFG, "get_ike_from_redis: Found value, stopping search in all the redis's");
			break;
		}
	}

	return ret;
}

/**
 * Setup the Sentinel configuration
 */
int redis_core_setup_sentinel_cfg(redis_connect_info_t *c)
{
	redis_sentinel_cfg_t *cfg;
	int i = 0, count = 0;
	char *sentinelname, *token, *str, *tofree;

	cfg = &c->sentinel_cfg;

	sentinelname = lib->settings->get_str(lib->settings, "charon.redis.sentinel_name", NULL, lib->ns);
	cfg->name = strdup(sentinelname);
	cfg->db = c->db;

	tofree = str = strdup(c->dc_sentinels);
	while ((token = strsep(&str, ",")) != NULL)
	{
		count++;
	}
	free(tofree);

	/* Allocate enough memory for all the Sentinel nodes */
	cfg->addr_count = count;
	cfg->addr_arr = calloc(count, sizeof(redis_addr_t));

	tofree = str = strdup(c->dc_sentinels);
	i = 0;
	while ((token = strsep(&str, ",")) != NULL)
	{
		if (redis_addr_cfg_parse(token, &cfg->addr_arr[i]) != 0)
		{
			DBG1(DBG_CFG, "setup_sentinel_cfg: Error parsing token string %s", token);
		}

		DBG2(DBG_CFG, "setup_sentinel_cfg: Found host %s port %d for slot %d",
				cfg->addr_arr[i].host, cfg->addr_arr[i].port, i);

		i++;
	}
	free(tofree);

	/* Create the Sentinel */
	c->sentinel = redis_sentinel_create(&c->sentinel_cfg);
	if (c->sentinel == NULL)
	{
		DBG1(DBG_CFG, "setup_sentinel_cfg: Failed creating Sentinel");
		return -1;
	}

	return 0;
}

METHOD(redis_interface_t, initiate_ike_rekey, int,
	private_redis_interface_t *this, uint64_t spi_i, uint64_t spi_r)
{
	int i, ret = 0;
	redis_connect_info_t *c;

	for (i=0; i < this->cinfo_count; i++)
	{
		c = this->cinfo[i];

		lib->scheduler->schedule_job(lib->scheduler,
			(job_t*)redis_ike_rekey_job_create(c->sentinel, spi_i, spi_r), 1);
	}

	return 0;
}

METHOD(redis_interface_t, redis_sentinel_reconnect_master, redisContext *,
	private_redis_interface_t *this, redisContext *ctx, int cinfo)
{
	redisContext *lctx = NULL;
	redis_connect_info_t *c = this->cinfo[cinfo];

	if (c == NULL)
	{
		DBG1(DBG_CFG, "redis_sentinel_reconnect_master: Failed finding context to reconnect");
		goto out;
	}

	if (sync_connect_single_redis(c) != 0)
	{
		DBG1(DBG_CFG, "redis_sentinel_reconnect_master: Failed reconnecting single context");
		goto out;
	}

	/* Success! */
	lctx = c->ctx;

out:
	return lctx;
}

METHOD(redis_interface_t, redis_find_context, redisContext *,
	private_redis_interface_t *this, int cinfo)
{
	redisContext *lctx = NULL;
	redis_connect_info_t *c = this->cinfo[cinfo];

	if (c == NULL)
	{
		DBG1(DBG_CFG, "redis_find_context: Failed finding context to reconnect");
		goto out;
	}

	lctx = c->ctx;

out:
	return lctx;
}

METHOD(redis_interface_t, redis_find_context_with_mutex, redisContext *,
	private_redis_interface_t *this, int cinfo, mutex_t **mutex)
{
	redisContext *lctx = NULL;
	redis_connect_info_t *c = this->cinfo[cinfo];

	if (c == NULL)
	{
		DBG1(DBG_CFG, "redis_find_context: Failed finding context to reconnect");
		goto out;
	}

	lctx = c->ctx;
	*mutex = c->mutex;

out:
	return lctx;
}

METHOD(redis_interface_t, initiate_child_rekey, int,
	private_redis_interface_t *this, uint64_t spi_i, uint64_t spi_r, char *ike, uint32_t ike_id, char *child, uint32_t child_id)
{
	int i, ret = 0;
	redis_connect_info_t *c;

	for (i=0; i < this->cinfo_count; i++)
	{
		c = this->cinfo[i];

		lib->scheduler->schedule_job(lib->scheduler,
			(job_t*)redis_child_rekey_job_create(c->sentinel, spi_i, spi_r, ike, ike_id, child, child_id), 1);
	}
	return 0;
}

METHOD(redis_interface_t, map_context, int,
	private_redis_interface_t *this, redisContext *ctx, mutex_t **mutex)
{
	int connect_struct = -1;
	int i;
	redis_connect_info_t *c = NULL;

	/* Find the context we want to reconnect */
	for (i = 0; i < this->cinfo_count; i ++)
	{
		if (this->cinfo[i]->ctx == ctx)
		{
			c = this->cinfo[i];
			break;
		}
	}

	if (c == NULL)
	{
		connect_struct = -1;
		*mutex = NULL;
	}
	else
	{
		connect_struct = i;
		*mutex = this->cinfo[i]->mutex;
	}

	return connect_struct;
}

METHOD(redis_interface_t, destroy, void,
	private_redis_interface_t *this)
{
	int i;

	for (i = 0; i < this->cinfo_count; i++)
	{
		int k = 0;
		redis_sentinel_cfg_t *cfg = &this->cinfo[i]->sentinel_cfg;

		if (cfg->name)
		{
			free(cfg->name);
		}

		for (k=0; k<cfg->addr_count; k++)
		{
			free(cfg->addr_arr[k].host);
		}
		if (cfg->addr_arr)
		{
			free(cfg->addr_arr);
		}

		free(this->cinfo[i]->channel);
		this->cinfo[i]->mutex->destroy(this->cinfo[i]->mutex);
		free(this->cinfo[i]);
	}
	free(this->cinfo);

	free(local_redis);

	free(this);
}

/*
 * Described in header-file
 */
redis_interface_t *redis_interface_create(void)
{
	private_redis_interface_t *this;
	char *ifaces;
	int i = 0, count = 1;
	char *token, *str, *tofree;

	INIT(this,
		.public = {
			.get_ike_from_redis = _get_ike_from_redis,
			.redis_sentinel_reconnect_master = _redis_sentinel_reconnect_master,
			.redis_find_context = _redis_find_context,
			.redis_find_context_with_mutex = _redis_find_context_with_mutex,
			.initiate_ike_rekey = _initiate_ike_rekey,
			.initiate_child_rekey = _initiate_child_rekey,
			.map_context = _map_context,
			.destroy = _destroy,
		},
		.alloc_id  = lib->settings->get_str(lib->settings, "charon.redis.alloc_id",
						DEFAULT_REDIS_ALLOC_ID, lib->ns),
		.cinfo_str = lib->settings->get_str(lib->settings, "charon.redis.sentinel_hosts", NULL),

	);

	if (this->cinfo_str == NULL)
	{
		DBG1(DBG_CFG, "redis_interface_create: sentinel_hosts is NULL, not initializing");
		return NULL;
	}
	/* Now figure out how many sentinel items are in the array */
	while (this->cinfo_str[i] != '\0')
	{
		if (this->cinfo_str[i] == ';')
		{
			count++;
		}
		i++;
	}

	/* Allocate the array based on how many hosts were in the config file */
	this->cinfo_count = count;
	this->cinfo = malloc(sizeof(redis_connect_info_t *) * count);
	/* Walk the string and assign hosts to each one */
	tofree = str = strdup(this->cinfo_str);
	i = 0;
	while ((token = strsep(&str, ";")) != NULL)
	{
		this->cinfo[i] = malloc(sizeof(redis_connect_info_t));
		this->cinfo[i]->dc_sentinels = strdup(token);
		this->cinfo[i]->db = atoi(lib->settings->get_str(lib->settings, "charon.redis.db", DEFAULT_REDIS_DB));
		this->cinfo[i]->channel = malloc(strlen(JITIKE_REDIS_CHANNEL)+20);
		snprintf(this->cinfo[i]->channel, strlen(JITIKE_REDIS_CHANNEL)+20, "%s-%d", JITIKE_REDIS_CHANNEL, this->cinfo[i]->db);
		this->cinfo[i]->timeout.tv_sec = lib->settings->get_int(lib->settings, "charon.redis.connect_sec", DEFAULT_REDIS_TIMEOUT_SEC);
		this->cinfo[i]->timeout.tv_usec = lib->settings->get_int(lib->settings, "charon.redis.connect_usec", DEFAULT_REDIS_TIMEOUT_USEC);
		this->cinfo[i]->mutex = mutex_create(MUTEX_TYPE_DEFAULT);

		DBG2(DBG_CFG, "redis_interface_create: dc_sentinels (%s) db (%d)", this->cinfo[i]->dc_sentinels, this->cinfo[i]->db);

		if (redis_core_setup_sentinel_cfg(this->cinfo[i]) != 0)
		{
			DBG1(DBG_CFG, "redis_interface_create: Failed setting up sentinel");
			return NULL;
		}

		i++;
	}
	free(tofree);

	/**
	 * The first redis server in the list is the local redis server for this DC.
	 */
	local_redis = lib->settings->get_str(lib->settings, "charon.redis.local_redis", NULL);

	/* Connect to redis */
	if (sync_connect_all_redis(this) != 0)
	{
		DBG1(DBG_CFG, "redis_interface_create: Cannot connect synchronously to redis");
		return NULL;
	}

	charon_redis = &this->public;

	return &this->public;
}
