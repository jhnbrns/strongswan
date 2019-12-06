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
 * @defgroup jitike_hiredis jitike_hiredis
 * @{ @ingroup jitike
 */

#ifndef JITIKE_HIREDIS_H_
#define JITIKE_HIREDIS_H_

#include <daemon.h>
#include <threading/mutex.h>
#include <hiredis/hiredis.h>
#include <sys/socket.h>
#include <unistd.h>

#include "jitike_redis.h"

/**
 * This function handles sending synchronous commands to redis, and will
 * reconnect if it detects the connection to redis has dropped.
 *
 * @return	Returns a void *, which is the redisReply struct.
 */
static inline void *jitikeRedisCommand(redisContext *c, const char *format, ...)
{
	redisContext *lc = c;
	redisContext *tmpc;
	redisReply *reply = NULL;
	int retry = 0;
	uint32_t max_wait = 3 * 1000000;        /* 3 seconds at most */
	uint32_t count = 0;     /* How many times we wait */
	uint32_t wait_interval = 250000;
	va_list ap;

	DBG2(DBG_CFG, "jitikeRedisCommand: About to send command to redis");
	jrc_mutex->lock(jrc_mutex);

	/** Acquire the context after we have the mutex */
	lc = jrc_redis->get_redis_ctx(jrc_redis);

retry:
	if (retry >= 2)
	{
		DBG1(DBG_CFG, "jitikeRedisCommand: Reached maximum reconnection attempts, failing");
		goto out;
	}

	if (lc == NULL)
	{
		goto reconnect;
	}
	DBG2(DBG_CFG, "jitikeRedisCommand: Sending command to host %s", lc->tcp.host);
	va_start(ap, format);
	reply = redisvCommand(lc, format, ap);
	va_end(ap);

	DBG2(DBG_CFG, "jitikeRedisCommand: Validating reply");

	if (reply == NULL)
	{
		/* Check for a disconnect */
		if (((lc->err == REDIS_ERR_EOF) &&
			(strcmp(lc->errstr, "Server closed the connection") == 0)) ||
		    (lc->err == REDIS_ERR_IO))
		{
master:
			DBG2(DBG_CFG, "jitikeRedisCommand: Handling error (%d / %s)",
				lc->err, lc->errstr);

reconnect:
			while ((count * wait_interval) < max_wait)
			{
				/* Reconnect via Sentinel */
				if ((tmpc = jrc_redis->redis_sentinel_reconnect_master(jrc_redis)) == NULL)
				{
					DBG2(DBG_CFG, "jitikeRedisCommand: Error reconnecting to redis, retrying");
					count++;
					usleep(wait_interval);
				}
				else
				{
					redisReply *dbReply = NULL;
					int set = 1;

					lc = tmpc;

					/* Enable keepalive */
					if (redisEnableKeepAlive(lc) != REDIS_OK)
					{
						DBG2(DBG_CFG, "jitikeRedisCommand: Cannot enable KEEPALIVE for synchronous redis connection");
					}

					dbReply = redisCommand(lc, "SELECT %d", jitike_db);
					if (dbReply != NULL) {
						freeReplyObject(dbReply);
					}

					DBG2(DBG_CFG, "jitikeRedisCommand: Successfully reconnected to redis, retrying command");

					/* Try the command again */
					retry++;
					goto retry;
				}

			}

			DBG1(DBG_CFG, "jitikeRedisCommand: Waited %d microseconds to reconnect and failed", count * wait_interval);
			goto out;
		}
		else
		{
			/**
			 * We received an error we cannot handle from a call to redisCommand(). We'll log a message
			 * here but this will require investigation as to what error we received and why.
			 */
			DBG1(DBG_CFG, "jitikeRedisCommand: Cannot handle unknown error (%d / %s), returning NULL reply",
					lc->err, lc->errstr);
			goto master;
		}
	}
	else if (reply->type == REDIS_REPLY_ERROR)
	{
		DBG1(DBG_CFG, "jitikeRedisCommand: Redis reply had an error (%s), reconnecting and retrying", reply->str);
		goto master;
	}

out:
	jrc_mutex->unlock(jrc_mutex);

	return reply;
}

/**
 * This function handles a reconnect to Redis for a set of commands which were pipelined.
 *
 * To use this function, you would first lock the context you want to pipeline commands on,
 * and then use redisAppendCommand() to load the context with commands. Next, in a loop you
 * would call this function. On the first call, this will send the entire output buffer to
 * the Redis server in a single socket write() call. It then reads replies, one at at time,
 * from the context. You would thus loop through the context, reading all the replies.
 *
 * See the function clean_ts_from_hashset() for an example of using this.
 *
 * @return	Returns a void *, which is the redisReply struct.
 */
static inline redisReply *jitikeRedisPipelineReadReply(redisContext *c)
{
	redisContext *lc = c;
	redisContext *tmpc;
	redisReply *reply = NULL;
	int ret = 0;
	uint32_t max_wait = 3 * 1000000;        /* 3 seconds at most */
	uint32_t count = 0;     /* How many times we wait */
	uint32_t wait_interval = 250000;

	DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: About to send command to redis");

	if (c == NULL)
	{
		goto reconnect;
	}

	DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Sending command to host %s", lc->tcp.host);
	ret = redisGetReply(c, (void **)&reply);

	DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Validating reply");

	if (reply == NULL)
	{
		/* Check for a disconnect */
		if (((lc->err == REDIS_ERR_EOF) &&
			(strcmp(lc->errstr, "Server closed the connection") == 0)) ||
		    (lc->err == REDIS_ERR_IO))
		{
master:
			DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Handling error (%d / %s)",
				lc->err, lc->errstr);

reconnect:
			while ((count * wait_interval) < max_wait)
			{
				/* Reconnect via Sentinel */
				if ((tmpc = jrc_redis->redis_sentinel_reconnect_master(jrc_redis)) == NULL)
				{
					DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Error reconnecting to redis, retrying");
					count++;
					usleep(wait_interval);
				}
				else
				{
					redisReply *dbReply = NULL;
					int set = 1;

					lc = tmpc;

					/* Enable keepalive */
					if (redisEnableKeepAlive(lc) != REDIS_OK)
					{
						DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Cannot enable KEEPALIVE for synchronous redis connection");
					}

					dbReply = redisCommand(lc, "SELECT %d", jitike_db);
					if (dbReply != NULL) {
						freeReplyObject(dbReply);
					}

					DBG2(DBG_CFG, "jitikeRedisPipelineReadReply: Successfully reconnected to redis, failing back to caller for retry");

					reply = NULL;
					goto out;
				}
			}
			DBG1(DBG_CFG, "jitikeRedisPipelineReadReply: Waited %d microseconds to reconnect and failed", count * wait_interval);
			goto out;
		}
		else
		{
			/**
			 * We received an error we cannot handle from a call to redisCommand(). We'll log a message
			 * here but this will require investigation as to what error we received and why.
			 */
			DBG1(DBG_CFG, "jitikeRedisPipelineReadReply: Cannot handle unknown error (%d / %s), returning NULL reply",
					lc->err, lc->errstr);
			goto master;
		}
	}
	else if (ret == REDIS_ERR)
	{
		DBG1(DBG_CFG, "jitikeRedisPipelineReadReply: Error from redisGetReply, reconnecting and retrying");
		goto master;
	}
	else if (reply->type == REDIS_REPLY_ERROR)
	{
		DBG1(DBG_CFG, "jitikeRedisPipelineReadReply: Redis reply had an error (%s), reconnecting and retrying", reply->str);
		goto master;
	}

out:

	return reply;
}

/**
 * The default expire timeout we use to expire our keys when we want to delete them, in seconds.
 * We expire instead of delete because we want them to exist for a bit so the rest of the JITSEC
 * code can use them before they leave Redis.
 */
#define JITIKE_EXPIRE_TIME	5

static inline int redis_expire_jitike_keys(redisContext *ctx, const char *key, int expire, bool deletekey)
{
	int ret = 0, k = 0;
	redisReply *reply = NULL;

	/**
	 * Find all CHILD_SA keys to expire.
	 */
	/**
	 * First, lets get the keys we are looking for.
	 */
	reply = jitikeRedisCommand(ctx, "KEYS %s-*", key);

	if (reply == NULL)
	{
		DBG1(DBG_CFG, "redis_expire_jitike_keys: charonRedisCommand returned NULL while running KEYS, failing");
		ret = -1;
		goto out;
	}

	/* Validate the reply */
	if (reply->type != REDIS_REPLY_ARRAY)
	{
		DBG1(DBG_CFG, "redis_expire_jitike_keys: Found invalid reply type: %d, err is %d / %s", reply->type, ctx->err, ctx->errstr);
		ret = -1;
		goto out;
	}

	if (reply->elements == 0)
	{
		/**
		 * This means there are no child key hashsets in Redis, so skip down and expire the main
		 * JITIKE hashset at this point.
		 */
		ret = 0;
		goto expire_jitike;
	}

	/**
	 * Walk each key, processing it and adding the CHILD_SA it represents.
	 */
	for (k=0; k < reply->elements; k++)
	{
		redisReply *innerReply = NULL;
		int m = 0;

		if (deletekey)
		{
			innerReply = jitikeRedisCommand(ctx, "DEL %s", reply->element[k]->str);
		}
		else
		{
			innerReply = jitikeRedisCommand(ctx, "EXPIRE %s %d", reply->element[k]->str, expire);
		}

		if (innerReply == NULL)
		{
			DBG1(DBG_CFG, "redis_expire_jitike_keys: NULL while running HGETALL %s", reply->element[k]->str);
			continue;
		}
		else
		{
			freeReplyObject(innerReply);
		}
	}

expire_jitike:
	/**
	 * Now expire the original key, but first, free the above redisReply.
	 */
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	if (deletekey)
	{
		reply = jitikeRedisCommand(ctx, "DEL %s", key);
	}
	else
	{
		reply = jitikeRedisCommand(ctx, "EXPIRE %s %d", key, expire);
	}

	/* Fall through ... */
out:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return ret;
}

#endif /** JITIKE_REDIS_H_ @}*/
