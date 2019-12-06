/* * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include "redis_child_rekey_job.h"
#include "redis_load_ike.h"
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

typedef struct private_redis_child_rekey_job_t private_redis_child_rekey_job_t;

/**
 * Private data of an redis_child_rekey_job_t object.
 */
struct private_redis_child_rekey_job_t {
	/**
	 * Public start_async_job_t interface.
	 */
	redis_child_rekey_job_t public;

	/**
	 * Used to send commands to redis
	 */
	redisContext *ctx;

	/**
	 * Sentinel object for managing redis connections.
	 */
	redis_sentinel_t *sentinel;

	/**
	 * Channel to subscribe to.
	 */
	char *channel;

	uint64_t spi_i;
	uint64_t spi_r;
	char *ikesa;
	uint32_t ike_id;
	char *childsa;
	uint32_t child_id;
};

/**
 * Setup synchronous redis connection.
 */
int redis_child_rekey_job_connect_redis_sync(private_redis_child_rekey_job_t *this)
{
	redisReply *reply = NULL;
	int ret = 0, set = 1;
	struct timeval timeout;

	timeout.tv_sec = DEFAULT_REDIS_TIMEOUT_SEC;
	timeout.tv_usec = DEFAULT_REDIS_TIMEOUT_USEC;

	this->ctx = redis_sentinel_connect_master(this->sentinel, timeout);
	if (this->ctx == NULL)
	{
		DBG1(DBG_CFG, "redis_child_rekey_job_connect_redis_sync: Sync connection error: cannot allocate redis context");
		ret = -1;
		goto out;
	}
	if (this->ctx->err != REDIS_OK)
	{
		DBG1(DBG_CFG, "redis_child_rekey_job_connect_redis_sync: Sync connection error: %s", this->ctx->errstr);
		redisFree(this->ctx);
		ret = -1;
		goto out;
	}

	/* Enable keepalive */
	if (redisEnableKeepAlive(this->ctx) != REDIS_OK)
	{
		DBG1(DBG_CFG, "redis_child_rekey_job_connect_redis_sync: Cannot enable KEEPALIVE for synchronous redis connection");
		ret = -1;
		goto out;
	}

	reply = redisCommand(this->ctx, "SELECT %d", this->sentinel->db);
	if (reply != NULL) {
		freeReplyObject(reply);
	}

out:
	return ret;
}

METHOD(job_t, execute_redis_child_rekey_job, job_requeue_t,
	private_redis_child_rekey_job_t *this)
{
	char key[JITIKE_MAX_KEY_SIZE];
	redisReply *reply = NULL;
	char *buf = NULL;
	size_t transfer_size = 0;
	cb_radio_t *cb_radio;
	child_rekey_t *enc;

	DBG2(DBG_CFG, "execute_redis_child_rekey_job: Starting rekey for SPI %.16"PRIx64"_i %.16"PRIx64"_r",
			this->spi_i, this->spi_r);

	/* Connect to redis */
	if (redis_child_rekey_job_connect_redis_sync(this) != 0)
	{
		DBG1(DBG_CFG, "execute_redis_child_rekey_job: Cannot connect to redis");
		goto out;
	}

	transfer_size = sizeof(cb_radio_t) + sizeof(child_rekey_t);
	if (this->ikesa != NULL)
	{
		transfer_size += strlen(this->ikesa)+1;
	}
	if (this->childsa != NULL)
	{
		transfer_size += strlen(this->childsa)+1;
	}
	buf = malloc(transfer_size);
	cb_radio = (cb_radio_t *)buf;
	cb_radio->message_type = CB_REKEY_CHILD_SA;
	enc = (child_rekey_t *)cb_radio->encoding;
	enc->spi_i = this->spi_i;
	enc->spi_r = this->spi_r;
	enc->ike_id = this->ike_id;
	enc->child_id = this->child_id;
	if (this->ikesa != NULL)
	{
		enc->ike_name_len = strlen(this->ikesa);
		memcpy(enc->encoding, this->ikesa, strlen(this->ikesa)+1);
	}
	else
	{
		enc->ike_name_len = 0;
	}
	if (this->childsa != NULL)
	{
		uint32_t ike_len = 0;

		if (this->ikesa != NULL)
		{
			ike_len = strlen(this->ikesa)+1;
		}
		enc->child_name_len = strlen(this->childsa)+1;
		memcpy(enc->encoding + ike_len, this->childsa, strlen(this->childsa)+1);
	}
	else
	{
		enc->child_name_len = 0;
	}

	if ((reply = redisCommand(this->ctx, "PUBLISH %s %b", this->channel, cb_radio, transfer_size)) == NULL)
	{
		DBG1(DBG_CFG, "execute_redis_child_rekey_job: Failed sending rekey event to redis channel");
	}
	free(buf);

out:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return JOB_REQUEUE_NONE;
}

METHOD(job_t, destroy, void,
        private_redis_child_rekey_job_t *this)
{
	redisFree(this->ctx);
	free(this->channel);
	if (this->ikesa != NULL)
	{
		free(this->ikesa);
	}
	if (this->childsa != NULL)
	{
		free(this->childsa);
	}
	free(this);
}

METHOD(job_t, get_priority, job_priority_t,
        private_redis_child_rekey_job_t *this)
{
	return JOB_PRIO_CRITICAL;
}

/*
 * Described in header
 */
redis_child_rekey_job_t *redis_child_rekey_job_create(redis_sentinel_t *sentinel, uint64_t spi_i, uint64_t spi_r,
		char *ikesa, uint32_t ike_id, char *childsa, uint32_t child_id)
{
	private_redis_child_rekey_job_t *this;

	INIT(this,
			.public = {
				.job_interface = {
					.execute = _execute_redis_child_rekey_job,
					.get_priority = _get_priority,
					.destroy = _destroy,
				},
			},
			.sentinel = sentinel,
			.spi_i = spi_i,
			.spi_r = spi_r,
			.ike_id = ike_id,
			.ikesa = NULL,
			.child_id = child_id,
			.childsa = NULL,
	);

	if (ikesa != NULL)
	{
		this->ikesa = malloc(strlen(ikesa)+1);
		strncpy(this->ikesa, ikesa, strlen(ikesa)+1);
	}
	if (childsa != NULL)
	{
		this->childsa = malloc(strlen(childsa)+1);
		strncpy(this->childsa, childsa, strlen(childsa)+1);
	}
	this->channel = malloc(strlen(JITIKE_REDIS_CHANNEL)+20);
	snprintf(this->channel, strlen(JITIKE_REDIS_CHANNEL)+20, "%s-%d", JITIKE_REDIS_CHANNEL, this->sentinel->db);

	DBG1(DBG_CFG, "redis_rekey_job_create: Created redis connection");

	return &this->public;
}

