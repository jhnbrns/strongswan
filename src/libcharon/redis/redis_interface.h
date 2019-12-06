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
 * @defgroup redis_interface redis_interface
 * @{ @ingroup redis
 */

#ifndef REDIS_INTERFACE_H_
#define REDIS_INTERFACE_H_

#include <string.h>
#include <inttypes.h>

#include <threading/mutex.h>

#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#define REDIS_MAX_KEY_SIZE      512

/**
 * The local redis server (e.g. in the same DC)
 */
extern char *local_redis;

typedef struct redis_interface_t redis_interface_t;

/**
 * Redis interface for charon.
 */
struct redis_interface_t {

	/**
	 * Add an IKE_SA from redis into the local IKE manager.
	 *
	 * @param spi_i         Initiator SPI
	 * @param spi_r         Responder SPI
	 * @return              Zero for success, -1 for failure
	 */
	int (*get_ike_from_redis)(redis_interface_t *this, uint64_t spi_i, uint64_t spi_r);

	/**
	 * Reconnect to a master, taking into account Redis Sentinel
	 *
	 * @param ctx           The context to reconnect
	 * @param cinfo         An int mapping into the redis_connect_info_t struct so we can match the context
	 * @return		A connected redisContext, or NULL if it fails
	 */
	redisContext* (*redis_sentinel_reconnect_master)(redis_interface_t *this, redisContext *ctx, int cinfo);

	/**
	 * Take an index into an array of contexts and return the context.
	 *
	 */
	redisContext* (*redis_find_context)(redis_interface_t *this, int cinfo);

	/**
	 * Take an index into an array of contexts and return the context with the mutex as well.
	 *
	 */
	redisContext* (*redis_find_context_with_mutex)(redis_interface_t *this, int cinfo, mutex_t **mutex);

	/**
	 * Schedules an IKE rekey event to be sent to the redis channel
	 *
	 * @param spi_i         Initiator SPI
	 * @param spi_r         Responder SPI
	 * @return              Zero for success, -1 for failure
	 */
	int (*initiate_ike_rekey)(redis_interface_t *this, uint64_t spi_i, uint64_t spi_r);

	/**
	 * Schedules a child rekey event to be sent to the redis channel
	 * NOTE: child or child_id is required
	 *
	 * @param spi_i         Initiator SPI
	 * @param spi_r         Responder SPI
	 * @param child         The name of the child SA to rekey
	 * @param child_id      The ID of the child SA to rekey
	 * @return              Zero for success, -1 for failure
	 */
	int (*initiate_child_rekey)(redis_interface_t *this, uint64_t spi_i, uint64_t spi_r, char *ike, uint32_t ike_id, char *child, uint32_t child_id);

	/**
	 * Which Redis connection is this context associated with.
	 *
	 * @param ctx           The Redis Context to search for
	 * @return		The connect_info_t struct this context maps to, -1 on error
	 */
	int (*map_context)(redis_interface_t *this, redisContext *ctx, mutex_t **mutex);

	/**
	 * Destroys a redis_interface_t object.
	 */
	void (*destroy)(redis_interface_t *this);
};

/**
 * Used to reconnect to Redis via Sentinel by charonRedisCommand()
 */
extern redis_interface_t *charon_redis;

/**
 * Creates an object of type kernel_interface_t.
 */
redis_interface_t *redis_interface_create(void);

#endif /** REDIS_INTERFACE_H_ @}*/
