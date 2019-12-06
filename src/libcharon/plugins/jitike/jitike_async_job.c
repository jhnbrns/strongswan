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

#include "jitike_async_job.h"
#include "jitike_redis.h"
#include "jitike_db.h"
#include "jitike_del_job.h"

#include <daemon.h>
#include <threading/mutex.h>
#include <processing/jobs/rekey_ike_sa_job.h>
#include <processing/jobs/rekey_child_sa_job.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libevent.h>

typedef struct private_async_data_t private_async_data_t;

/**
 * Private data passed from the callback to the async redis handler;
 */

struct private_async_data_t {
	/**
	 * The redis hostname, used to compare if we should delete something or not
	 */
	char *redis_hostname;

	/**
	 * Sentinel object for managing redis connections.
	 */
	redis_sentinel_t *sentinel;

	/**
	 * The node's unique allocation ID
	 */
	char *alloc_id;
};

/* We share this structure across threads, it's write only. */
private_async_data_t adata;

typedef struct private_start_async_job_t private_start_async_job_t;

/**
 * Private data of an start_async_job_t object.
 */
struct private_start_async_job_t {
	/**
	 * Public start_async_job_t interface.
	 */
	start_async_job_t public;

	/**
	 * Used to send commands asynchronously to redis
	 */
	redisAsyncContext *actx;

	/**
	 * redisAsyncContext is not thread safe, we'll use a
	 * mutex to protect access.
	 */
	mutex_t *amutex;

	/**
	 * The redis hostname, used to compare if we should delete something or not
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
	 * The node's unique allocation ID
	 */
	char *alloc_id;

	/**
	 * Connection timeout.
	 */
	struct timeval timeout;
};

/**
 * Forward declarations
 */
void connectCallback(const redisAsyncContext *c, int status);
void disconnectCallback(const redisAsyncContext *c, int status);

/**
 * Setup asynchronous redis connection.
 */
int connect_redis_async(private_start_async_job_t *this)
{
	int ret = 0;

	this->amutex->lock(this->amutex);

	this->actx = redis_sentinel_connect_master_async(this->sentinel, this->timeout);
	if (this->actx == NULL)
	{
		DBG1(DBG_CFG, "connect_redis_async: Connection error: cannot allocate redis context");
		ret = -1;
		goto out;
	}
	this->actx->data = this;

	if (redisAsyncSetDisconnectCallback(this->actx, disconnectCallback) != REDIS_OK)
	{
		DBG1(DBG_CFG, "connect_redis_async: Failed adding disconnect callback");
		redisAsyncDisconnect(this->actx);
		ret = -1;
		goto out;
	}

	if (redisAsyncSetConnectCallback(this->actx, connectCallback) != REDIS_OK)
	{
		DBG1(DBG_CFG, "connect_redis_async: Failed adding disconnect callback");
		redisAsyncDisconnect(this->actx);
		ret = -1;
		goto out;
	}

out:
	this->amutex->unlock(this->amutex);

	return ret;
}

void asyncSubCallback(redisAsyncContext *c, void *r, void *privdata)
{
	redisReply *reply = (redisReply *)r;

	if (reply == NULL)
	{
		DBG2(DBG_CFG, "asyncSubCallback: Reply is NULL");
		return;
	}

	/*
	 * We're looking for an array here (REDIS_REPLY_ARRAY), with 3
	 * items:
	 *
	 * r->element[0].type == REDIS_REPLY_STRING
	 * r->element[0].str  == "message"
	 * r->element[1].type == REDIS_REPLY_STRING
	 * r->element[1].str  == JITIKE_REDIS_CHANNEL-"DB #"
	 * r->element[2].type == REDIS_REPLY_STRING
	 * r->element[2].str  == ike_sa_id_t
	 *
	 */
	if (reply->type == REDIS_REPLY_ARRAY && reply->elements == 3)
	{
		if (strcmp(reply->element[0]->str, "subscribe") != 0)
		{
			cb_radio_t *cb_radio;
			ike_channel_sa_id_encoding_t *enc, *copy;
			char *alloc_id;

			cb_radio = (cb_radio_t *)reply->element[2]->str;

			if (cb_radio->message_type == CB_REKEY_IKE_SA)
			{
				ike_rekey_t *rk;
				ike_sa_id_t *ike_sa_id = NULL;
				ike_sa_t *ike_sa;

				DBG2(DBG_CFG, "asyncSubCallback: Found CB_REKEY_IKE_SA event");

				rk = (ike_rekey_t *)cb_radio->encoding;

				/**
				 * Try creating an ike_sa_id_t as both initiator and responder, doesn't
				 * matter which one works.
				 */
				ike_sa_id = ike_sa_id_create(IKEV2, htobe64(rk->spi_i), htobe64(rk->spi_r), FALSE);

				ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
				if (ike_sa == NULL)
				{
					ike_sa_id->destroy(ike_sa_id);
					ike_sa_id = ike_sa_id_create(IKEV2, htobe64(rk->spi_i), htobe64(rk->spi_r), TRUE);
					ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
					if (ike_sa == NULL)
					{
						DBG1(DBG_CFG, "asyncSubCallback: Cannot find IKE_SA, skipping");
						goto skip_ike;
					}
				}
				/* We found it! */
				charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);

				/* .FIXME: Do we need to set reauth to FALSE here? */
				lib->processor->queue_job(lib->processor,
						(job_t*)rekey_ike_sa_job_create(ike_sa_id, FALSE));

skip_ike:
				ike_sa_id->destroy(ike_sa_id);

				goto out;
			}
			else if (cb_radio->message_type == CB_REKEY_CHILD_SA)
			{
				child_rekey_t *rk;
				char *child = NULL, *ike = NULL;
				uint32_t child_id = 0, ike_id = 0;
				enumerator_t *isas, *csas;
				ike_sa_t *ike_sa;
				ike_sa_id_t *ike_sa_id;
				child_sa_t *child_sa;

				DBG2(DBG_CFG, "asyncSubCallback: Found CB_REKEY_CHILD_SA event");

				rk = (child_rekey_t *)cb_radio->encoding;
				ike_id = rk->ike_id;
				if (rk->ike_name_len != 0)
				{
					ike = malloc(rk->ike_name_len);
					strncpy(ike, rk->encoding, rk->ike_name_len);
				}
				child_id = rk->child_id;
				if (rk->child_name_len != 0)
				{
					child = malloc(rk->child_name_len);
					strncpy(child, rk->encoding+rk->ike_name_len, rk->child_name_len);
				}

				isas = charon->controller->create_ike_sa_enumerator(charon->controller, TRUE);
				while (isas->enumerate(isas, &ike_sa))
				{
					ike_sa_id = ike_sa->get_id(ike_sa);
					if (child || child_id)
					{
						if (ike && !streq(ike, ike_sa->get_name(ike_sa)))
						{
							continue;
						}
						if (ike_id && ike_id != ike_sa->get_unique_id(ike_sa))
						{
							continue;
						}
						if ((rk->spi_i && htobe64(rk->spi_i) != ike_sa_id->get_initiator_spi(ike_sa_id)) &&
							(rk->spi_r && htobe64(rk->spi_r) != ike_sa_id->get_responder_spi(ike_sa_id)))
						{
							continue;
						}
						csas = ike_sa->create_child_sa_enumerator(ike_sa);
						while (csas->enumerate(csas, &child_sa))
						{
							if (child && !streq(child, child_sa->get_name(child_sa)))
							{
								continue;
							}
							if (child_id && child_sa->get_unique_id(child_sa) != child_id)
							{
								continue;
							}
							ike_sa_id = ike_sa->get_id(ike_sa);
							lib->processor->queue_job(lib->processor,
									(job_t*)rekey_child_sa_job_create(
										child_sa->get_protocol(child_sa),
										child_sa->get_spi(child_sa, TRUE), /** Leave in network byte order */
										ike_sa->get_my_host(ike_sa),
										be64toh(ike_sa_id->get_initiator_spi(ike_sa_id)),
										be64toh(ike_sa_id->get_responder_spi(ike_sa_id))));
						}
						csas->destroy(csas);
					}

				}
				isas->destroy(isas);
 
				free(child);
				free(ike);
				goto out;

			}

			enc = (ike_channel_sa_id_encoding_t *)cb_radio->encoding;
			alloc_id = strndup(enc->encoding, enc->alloc_id_len);

			DBG2(DBG_CFG, "asyncSubCallback: Comparing allocation IDs %s / %s",
				adata.alloc_id, alloc_id);

			/*
			 * If the message on the channel came from us, do not delete the IKE_SA
			 * locally.
			 */
			if (strncmp(adata.alloc_id, alloc_id, enc->alloc_id_len) != 0)
			{
				/* Copy the structure here, we'll free it in the job thread */
				copy = malloc(reply->element[2]->len - sizeof(cb_radio_t));
				if (copy == NULL)
				{
					DBG1(DBG_CFG, "asyncSubCallback: Cannot allocate memory");
					free(alloc_id);
					return;
				}
				memcpy(copy, enc, reply->element[2]->len - sizeof(cb_radio_t));

				/* Further processing will be done via a job, and not in this thread */
				lib->processor->queue_job(lib->processor, (job_t*)start_del_job_create(adata.sentinel,
							adata.redis_hostname, FALSE, copy));
			}

			/* Free alloc_id and hostname now */
			free(alloc_id);
		}
	}

out:
	return;
}

void connectCallback(const redisAsyncContext *c, int status)
{
	if (status != REDIS_OK) {
		private_start_async_job_t *this = c->data;

		DBG1(DBG_CFG, "connectCallback: Error: %s, attempting reconnect to Redis", c->errstr);

		if (connect_redis_async(this) != 0)
		{
			DBG1(DBG_CFG, "connectCallback: Cannot reconnect asynchronously to redis");
		}
		return;
	}
	DBG2(DBG_CFG, "connectCallback: Connected...");
}

void disconnectCallback(const redisAsyncContext *c, int status)
{
	private_start_async_job_t *this = c->data;
	uint32_t max_wait = 3 * 1000000;	/* 3 seconds at most */
	uint32_t count = 0;	/* How many times we wait */
	uint32_t wait_interval = 250000;

	if (status != REDIS_OK) {
		DBG2(DBG_CFG, "disconnectCallback: Error: %s", c->errstr);
	}

	DBG2(DBG_CFG, "disconnectCallback: Disconnected ... reconnecting");

	while ((count * wait_interval) < max_wait)
	{
		if (connect_redis_async(this) != 0)
		{
			DBG1(DBG_CFG, "disconnectCallback: Cannot connect asynchronously to redis, sleeping for %d ms", wait_interval);
			count++;
			usleep(wait_interval);
		}
		else
		{
			DBG1(DBG_CFG, "disconnectCallback: Successfully reconnected to redis");
			return;
		}
	}

	DBG1(DBG_CFG, "disconnectCallback: Waited %d microseconds to reconnect and failed", count * wait_interval);

	return;
}

METHOD(job_t, execute_redis_async, job_requeue_t,
	private_start_async_job_t *this)
{
	signal(SIGPIPE, SIG_IGN);
	struct event_base *base = event_base_new();
	int ev_ret = 0;

	if (base == NULL)
	{
		DBG1(DBG_CFG, "execute_redis_async: Cannot callocate event base context");
		goto out;
	}

	if (this->actx == NULL)
	{
		if (connect_redis_async(this) != 0)
		{
			DBG1(DBG_CFG, "execute_redys_async: Cannot connect asynchronously to redis");
			goto out;
		}
	}

	DBG2(DBG_CFG, "execute_redis_async: Running async redis job");
	redisLibeventAttach(this->actx, base);

	/**
	 * Note that if we ever write data from the async thread we'll need to set the DB here,
	 * as redis DBs are shared in some DCs (e.g. all the dev environments in LAX).
	 */

	if (redisAsyncCommand(this->actx, asyncSubCallback, NULL, "SUBSCRIBE %s", this->channel) != REDIS_OK)
	{
		DBG1(DBG_CFG, "execute_redis_async: Error subscribing to channel %s", this->channel);
	}
	else
	{
		DBG2(DBG_CFG, "execute_redis_async: Subscribed to channel %s", this->channel);
	}

	/**
	 * Return values per libevent:
	 *
	 *   @return 0 if successful, -1 if an error occurred, or 1 if no events were registered.
	 */
	ev_ret = event_base_dispatch(base);
	if (ev_ret == -1)
	{
		/* Error */
		DBG2(DBG_CFG, "execute_redis_async: Error returned from event_base_dispatch()");
	}
	else if (ev_ret == 1)
	{
		/* No events registered */
		DBG2(DBG_CFG, "execute_redis_async: No events registered for call to event_base_dispatch()");
	}
	/* Zero (0) on success */

	DBG2(DBG_CFG, "execute_redis_async: Exited event_base_dispatch(), job will be requeued (JOB_REQUEUE_DIRECT)");

out:
	/* Free the memory associated with the event_base */
	if (base != NULL)
	{
		event_base_free(base);
	}

	return JOB_REQUEUE_DIRECT;
}

METHOD(job_t, destroy, void,
        private_start_async_job_t *this)
{
	free(adata.alloc_id);
	this->amutex->destroy(this->amutex);
	free(this->channel);
	free(this->alloc_id);
	free(this->redis_hostname);
	free(this);
}

METHOD(job_t, get_priority, job_priority_t,
        private_start_async_job_t *this)
{
	return JOB_PRIO_CRITICAL;
}

/*
 * Described in header
 */
start_async_job_t *start_async_job_create(redis_sentinel_t *sentinel, char *redis_hostname, struct timeval timeout, char *alloc_id)
{
	private_start_async_job_t *this;

	INIT(this,
			.public = {
				.job_interface = {
					.execute = _execute_redis_async,
					.get_priority = _get_priority,
					.destroy = _destroy,
				},
			},
			.amutex = mutex_create(MUTEX_TYPE_DEFAULT),
			.sentinel = sentinel,
			.timeout = timeout,
	);

	this->redis_hostname = strdup(redis_hostname);
	this->channel = malloc(strlen(JITIKE_REDIS_CHANNEL)+20);
	snprintf(this->channel, strlen(JITIKE_REDIS_CHANNEL)+20, "%s-%d", JITIKE_REDIS_CHANNEL, this->sentinel->db);
	this->alloc_id = strdup(alloc_id);

	/* Save the data in the globla, shared async structure ... */
	adata.sentinel = this->sentinel;
	adata.redis_hostname = strdup(this->redis_hostname);
	adata.alloc_id = strdup(this->alloc_id);

	if (connect_redis_async(this) != 0)
	{
		DBG1(DBG_CFG, "start_async_job_create: Cannot connect asynchronously to redis");
		return NULL;
	}

	DBG1(DBG_CFG, "start_async_job_create: Created ASYNC redis connection");

	return &this->public;
}

