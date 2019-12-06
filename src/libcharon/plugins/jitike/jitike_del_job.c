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

#include "jitike_del_job.h"
#include "jitike_redis.h"
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

typedef struct private_start_del_job_t private_start_del_job_t;

/**
 * Private data of an start_del_job_t object.
 */
struct private_start_del_job_t {
	/**
	 * Public start_async_job_t interface.
	 */
	start_del_job_t public;

	/**
	 * Used to send commands to redis
	 */
	redisContext *ctx;

	/**
	 * Hostname to connect to.
	*/
	char *redis_hostname;

	/**
	 * Sentinel object for managing redis connections.
	 */
	redis_sentinel_t *sentinel;

	/**
	 * Channel to subscribe to.
	 */
	char *channel;

	/**
	 * A copy of the ike_channel_sa_id_encoding_t we received from the
	 * channel. We are responsible for freeing this memory before the
	 * thread exits.
	 */
	ike_channel_sa_id_encoding_t *enc;

	/**
	 * Do we fire of a fallback delete job to handle the case where we
	 * publish to Redis, Redis receives the message, and then the master
	 * rolls, meaning the publish is never sent?
	 */
	bool fallback_delete;
};

/**
 * Setup synchronous redis connection.
 */
int del_job_connect_redis_sync(private_start_del_job_t *this)
{
	int ret = 0, set = 1;
	struct timeval timeout;

	timeout.tv_sec = DEFAULT_REDIS_TIMEOUT_SEC;
	timeout.tv_usec = DEFAULT_REDIS_TIMEOUT_USEC;

	this->ctx = redis_sentinel_connect_master(this->sentinel, timeout);
	if (this->ctx == NULL)
	{
		DBG1(DBG_CFG, "del_job_connect_redis_sync: Sync connection error: cannot allocate redis context");
		ret = -1;
		redisFree(this->ctx);
		goto out;
	}

	/* Enable keepalive */
	if (redisEnableKeepAlive(this->ctx) != REDIS_OK)
	{
		DBG1(DBG_CFG, "del_job_connect_redis_sync: Cannot enable KEEPALIVE for synchronous redis connection");
		ret = -1;
		goto out;
	}

out:
	return ret;
}

METHOD(job_t, execute_del_job, job_requeue_t,
	private_start_del_job_t *this)
{
	char key[JITIKE_MAX_KEY_SIZE];
	ike_sa_id_t *ike_sa_id = NULL;
	ike_sa_t *ike_sa = NULL;
	char *alloc_id = NULL, *hostname = NULL;

	alloc_id = strndup(this->enc->encoding, this->enc->alloc_id_len);
	hostname = strndup(this->enc->encoding+this->enc->alloc_id_len, this->enc->hostname_len);

	DBG2(DBG_CFG, "execute_del_job: Deleting hashset from redis for SPI %.16"PRIx64"_i %.16"PRIx64"_r",
			this->enc->initiator_spi, this->enc->responder_spi);

	/* Connect to redis */
	if (del_job_connect_redis_sync(this) != 0)
	{
		DBG1(DBG_CFG, "execute_del_job: Cannot connect to redis");
		goto out;
	}

	ike_sa_id = ike_sa_id_create(this->enc->ike_version,
			htobe64(this->enc->initiator_spi), htobe64(this->enc->responder_spi),
			this->enc->initiator);
	ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
	if (ike_sa == NULL)
	{
		DBG1(DBG_CFG, "execute_del_job: Cannot find IKE_SA for SPI %.16"PRIx64"_i %.16"PRIx64"_r",
				be64toh(ike_sa_id->get_initiator_spi(ike_sa_id)),
				be64toh(ike_sa_id->get_responder_spi(ike_sa_id)));
		goto out;
	}

	/* Set the state to PASSIVE and delete the IKE_SA */
	ike_sa->set_state(ike_sa, IKE_PASSIVE);
	charon->ike_sa_manager->checkin_and_destroy(charon->ike_sa_manager, ike_sa);

	if (strncmp(this->redis_hostname, hostname, this->enc->hostname_len) != 0)
	{
		/* We'll use this as the key for storing the information in redis */
		snprintf(key, JITIKE_MAX_KEY_SIZE, "%.16"PRIx64"_i-%.16"PRIx64"_r",
				this->enc->initiator_spi, this->enc->responder_spi);

		if (redis_expire_jitike_keys(this->ctx, key, JITIKE_EXPIRE_TIME, true) != 0)
		{
			DBG1(DBG_CFG, "execute_del_job: Failed expiring hashset keys for %s", key);
		}
	}

	/* Delete the ike_sa_id */
	ike_sa_id->destroy(ike_sa_id);

	/**
	 * Should we fire another job to handle fallback deletes?
	 */
	if (this->fallback_delete)
	{
		ike_channel_sa_id_encoding_t *copy;
		size_t copylen = sizeof(ike_channel_sa_id_encoding_t) + this->enc->alloc_id_len + this->enc->hostname_len;

		copy = malloc(copylen);
		if (copy == NULL)
		{
			DBG1(DBG_CFG, "execute_del_job: Cannot allocate memory");
			goto out;
		}

		memcpy(copy, this->enc, copylen);

		/** Fire off the job now */
		lib->scheduler->schedule_job(lib->scheduler, (job_t *)start_del_job_create(this->sentinel,
                                                        this->redis_hostname, FALSE, copy), BACKUP_JOB_DELAY);
	}

out:
	if (alloc_id != NULL)
	{
		free(alloc_id);
	}
	if (hostname != NULL)
	{
		free(hostname);
	}

	/* Free the ike_channel_sa_id_encoding_t object we were passed */
	free(this->enc);

	return JOB_REQUEUE_NONE;
}

METHOD(job_t, destroy, void,
        private_start_del_job_t *this)
{
	redisFree(this->ctx);
	free(this->channel);
	free(this->redis_hostname);
	free(this);
}

METHOD(job_t, get_priority, job_priority_t,
        private_start_del_job_t *this)
{
	return JOB_PRIO_CRITICAL;
}

/*
 * Described in header
 */
start_del_job_t *start_del_job_create(redis_sentinel_t *sentinel, char *redis_hostname, bool fallback_delete, ike_channel_sa_id_encoding_t *enc)
{
	private_start_del_job_t *this;

	INIT(this,
			.public = {
				.job_interface = {
					.execute = _execute_del_job,
					.get_priority = _get_priority,
					.destroy = _destroy,
				},
			},
			.sentinel = sentinel,
			.fallback_delete = fallback_delete,
			.enc = enc,
	);

	this->redis_hostname = strdup(redis_hostname);
	this->channel = malloc(strlen(JITIKE_REDIS_CHANNEL)+20);
	snprintf(this->channel, strlen(JITIKE_REDIS_CHANNEL)+20, "%s-%d", JITIKE_REDIS_CHANNEL, this->sentinel->db);

	DBG1(DBG_CFG, "start_del_job_create: Created redis connection");

	return &this->public;
}

