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

#include "redis_publish_job.h"
#include "redis_load_ike.h"
#include "jitike_db.h"
#include "jitike_hiredis.h"

#include <daemon.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <hiredis/hiredis.h>

#define DEFAULT_REDIS_TIMEOUT_SEC       1
#define DEFAULT_REDIS_TIMEOUT_USEC      500000

/**
 * How long until we fire the backup delete job, in seconds.
 */
#define BACKUP_JOB_DELAY		5

typedef struct private_start_redis_publish_job_t private_start_redis_publish_job_t;

/**
 * Private data of an start_redis_publish_job_t object.
 */
struct private_start_redis_publish_job_t {
	/**
	 * Public start_redis_publish_job_t interface.
	 */
	start_redis_publish_job_t public;

	/**
	 * Used to send commands to redis
	 */
	int cinfo;

	/**
	 * Channel to subscribe to.
	 */
	char *channel;

	/**
	 * The DB to use
	 */
	int db;

	/**
	 * The data and length we are asked to publish. We make a copy
	 * of the data in buf and free it when we exit.
	 */
	char *buf;
	size_t len;

	/**
	 * Do we fire off a fallback publish job to handle the case where we
	 * publish to Redis, Redis receives the message, and then the master
	 * rolls, meaning the publish is never sent?
	 */
	bool fallback_publish;
};

METHOD(job_t, execute_redis_publish_job, job_requeue_t,
	private_start_redis_publish_job_t *this)
{
	char key[JITIKE_MAX_KEY_SIZE];
	redisReply *reply = NULL;

	DBG2(DBG_CFG, "execute_redis_publish_job: Publishing data to on channel %s", this->channel);

	/* Publish to the channel the fact we're taking over this IKE_SA */
	if ((reply = charonRedisCommand(this->cinfo, this->db, "PUBLISH %s %b", this->channel, this->buf, this->len)) == NULL)
	{
		DBG1(DBG_CFG, "execute_redis_publish_job: Failed publishing IKE_SA information");
	}

	/**
	 * Should we fire another job to handle fallback publishes?
	 */
	if (this->fallback_publish)
	{
		/** Fire off the job now */
		lib->scheduler->schedule_job(lib->scheduler, (job_t *)start_redis_publish_job_create(this->cinfo, this->db,
					FALSE, this->buf, this->len), BACKUP_JOB_DELAY);
	}

out:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return JOB_REQUEUE_NONE;
}

METHOD(job_t, destroy, void,
        private_start_redis_publish_job_t *this)
{
	free(this->buf);
	free(this->channel);
	free(this);
}

METHOD(job_t, get_priority, job_priority_t,
        private_start_redis_publish_job_t *this)
{
	return JOB_PRIO_CRITICAL;
}

/*
 * Described in header
 */
start_redis_publish_job_t *start_redis_publish_job_create(int cinfo, int db, bool fallback_publish, char *buf, size_t len)
{
	private_start_redis_publish_job_t *this;

	INIT(this,
			.public = {
				.job_interface = {
					.execute = _execute_redis_publish_job,
					.get_priority = _get_priority,
					.destroy = _destroy,
				},
			},
			.cinfo = cinfo,
			.db = db,
			.fallback_publish = fallback_publish,
			.len = len,
	);

	this->buf = malloc(this->len);
	if (this->buf == NULL)
	{
		DBG1(DBG_CFG, "start_redis_publish_job_create: Failed allocating memory");
		return NULL;
	}
	memcpy(this->buf, buf, len);
	this->channel = malloc(strlen(JITIKE_REDIS_CHANNEL)+20);
	snprintf(this->channel, strlen(JITIKE_REDIS_CHANNEL)+20, "%s-%d", JITIKE_REDIS_CHANNEL, this->db);

	DBG1(DBG_CFG, "start_redis_publish_job_create: Created redis connection");

	return &this->public;
}

