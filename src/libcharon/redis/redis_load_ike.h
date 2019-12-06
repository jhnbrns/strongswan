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
 * @defgroup redis_load_ike redis_load_ike
 * @{ @ingroup redis
 */

#ifndef REDIS_LOAD_IKE_H_
#define REDIS_LOAD_IKE_H_

#include "redis_interface.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <hiredis/hiredis.h>

/**
 * This function handles sending synchronous commands to redis, and will
 * reconnect if it detects the connection to redis has dropped.
 *
 * @return	Returns a void *, which is the redisReply struct.
 */
static inline void *charonRedisCommand(int cinfo, int db, const char *format, ...) __attribute__ ((optnone))
{
	redisContext *lc = NULL;
	redisContext *tmpc;
	redisReply *reply = NULL;
	int retry = 0;
	uint32_t max_wait = 3 * 1000000;        /* 3 seconds at most */
	uint32_t count = 0;     /* How many times we wait */
	uint32_t wait_interval = 250000;
	va_list ap;
	mutex_t *mutex = NULL;

	/* Get the context and mutex */
	if ((lc = charon_redis->redis_find_context_with_mutex(charon_redis, cinfo, &mutex)) == NULL)
	{
		DBG1(DBG_CFG, "charonRedisCommand: Failed finding context");
		goto out_no_unlock;
	}

	DBG2(DBG_CFG, "charonRedisCommand: About to send command to redis");
	mutex->lock(mutex);

retry:
	if (retry >= 2)
	{
		DBG1(DBG_CFG, "charonRedisCommand: Reached maximum reconnection attempts, failing");
		goto out;
	}

	DBG2(DBG_CFG, "charonRedisCommand: Sending command to host %s", lc->tcp.host);
	va_start(ap, format);
	reply = redisvCommand(lc, format, ap);
	va_end(ap);

	DBG2(DBG_CFG, "charonRedisCommand: Validating reply");

	if (reply == NULL)
	{
		/* Check for a disconnect */
		if (((lc->err == REDIS_ERR_EOF) &&
			(strcmp(lc->errstr, "Server closed the connection") == 0)) ||
		    (lc->err == REDIS_ERR_IO))
		{
master:
			DBG2(DBG_CFG, "charonRedisCommand: Handling error (%d / %s)",
				lc->err, lc->errstr);

reconnect:
			while ((count * wait_interval) < max_wait)
			{

				if ((tmpc = charon_redis->redis_sentinel_reconnect_master(charon_redis, lc, cinfo)) == NULL)
				{
					DBG2(DBG_CFG, "charonRedisCommand: Error reconnecting to redis, retrying");
					count++;
					usleep(wait_interval);
				}
				else
				{
					lc = tmpc;

					DBG2(DBG_CFG, "charonRedisCommand: Successfully reconnected to redis, retrying command");

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
			DBG1(DBG_CFG, "charonRedisCommand: Cannot handle unknown error (%d / %s), returning NULL reply",
				lc->err, lc->errstr);
			goto master;
		}
	}
	else if (reply->type == REDIS_REPLY_ERROR)
	{
		DBG1(DBG_CFG, "charonRedisCommand: Redis reply had an error (%s), reconnecting and retrying", reply->str);
		goto master;
	}

out:
	mutex->unlock(mutex);
out_no_unlock:

	return reply;
}

/**
 * Add an IKE from redis into the local IKE_SA manager. This includes
 * processing and adding CHILD_SAs as well.
 *
 * @param command	The command to pass to a redis HGETALL operation.
 * @return		Zero for success, -1 for error.
 */
int charon_process_ike_add(int cinfo, mutex_t *mutex, int db, const char *command);

#endif /** REDIS_LOAD_IKE_ @}*/
