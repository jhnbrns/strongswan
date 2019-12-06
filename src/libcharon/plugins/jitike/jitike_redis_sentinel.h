/*
 * Copyright (c) 2016 haipo yang
 * Copyright (c) 2019 Cisco and/or its affiliates.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @defgroup jitike_redis_sentinel jitike_redis_sentinel
 * @{ @ingroup jitike
 */

#ifndef JITIKE_REDIS_SENTINEL_H_
#define JITIKE_REDIS_SENTINEL_H_

#include <stddef.h>
#include <stdint.h>
#include <hiredis/hiredis.h>
#include <hiredis/async.h>

#define JITIKE_SENTINEL_CONFIG_NAME	"jitike-sentinel"

typedef struct redis_addr_t redis_addr_t;

/**
 * Redis Sentinel address information
 */
struct redis_addr_t {
	/**
	 * The hostname of this Sentinel instance.
	 */
	char *host;

	/**
	 * The port of the Sentinel instance.
	 */
	int   port;
};

typedef struct redis_sentinel_cfg_t redis_sentinel_cfg_t;

/**
 * Sentinel configuration
 */
struct redis_sentinel_cfg_t {
	/**
	 * The name of this configuration
	 */
	char *name;

	/**
	 * How many address instances in the addr_arr
	 */
	uint32_t addr_count;

	/**
	 * An array of addresses to connect to
	 */
	redis_addr_t *addr_arr;

	/**
	 * The DB to connect to
	 */
	int db;
};

typedef struct redis_sentinel_node_t redis_sentinel_node_t;

/**
 * An individual Sentinel node
 */
struct redis_sentinel_node_t {
	/**
	 * A node's redis_addr_t information
	 */
	struct redis_addr_t addr;

	/**
	 * Previous and next entries in the list
	 */
	struct redis_sentinel_node_t *prev;
	struct redis_sentinel_node_t *next;
};

typedef struct redis_sentinel_t redis_sentinel_t;

/**
 * Overlord structure of a Redis Sentinel connection
 */
struct redis_sentinel_t {
	/**
	 * The name of this instance
	 */
	char *name;

	/**
	 * The list of nodes for this Sentinel instance
	 */
	redis_sentinel_node_t *list;

	/**
	 * The DB to connect to on each node
	 */
	int db;
};

/**
 * Create a Redis Sentinel instance
 *
 * @param cfg       The configuration to use to connect to the Sentinel cluster
 * @ret             A redis_sentinel_t structure
 */
redis_sentinel_t *redis_sentinel_create(redis_sentinel_cfg_t *cfg);

/**
 * Release a redis_sentinel_t structure
 *
 * @param context   The context to free
 */
void redis_sentinel_release(redis_sentinel_t *context);

/**
 * Get the master Redis address from Sentinel
 *
 * @param context   The context to use to connect to Sentinel
 * @param addr      The address (host/port) of the master.
 *                  NOTE: The caller needs to free this information.
 * @param timeout   Timeout on Redis commands
 * @ret             0 for success, -1 for failure.
 */
int redis_sentinel_get_master_addr(redis_sentinel_t *context, redis_addr_t *addr, struct timeval timeout);

/**
 * Get the slave Redis address from Sentinel
 *
 * @param context   The context to use to connect to Sentinel
 * @param addr      The address (host/port) of the master.
 *                  NOTE: The caller needs to free this information.
 * @param timeout   Timeout on Redis commands
 * @ret             0 for success, -1 for failure.
 */
int redis_sentinel_get_slave_addr(redis_sentinel_t *context, redis_addr_t *addr, struct timeval timeout);

/**
 * Connect to the sentinel master
 *
 * @param context   The context to use to connect
 * @param timeout   Timeout on Redis commands
 * @return          If successful, the redisContext, otherwise NULL
 */
redisContext *redis_sentinel_connect_master(redis_sentinel_t *context, struct timeval timeout);

/**
 * Connect to the sentinel slave
 *
 * @param context   The context to use to connect
 * @param timeout   Timeout on Redis commands
 * @return          If successful, the redisContext, otherwise NULL
 */
redisContext *redis_sentinel_connect_slave(redis_sentinel_t *context, struct timeval timeout);

/**
 * Connect asynchronously to the sentinel master
 *
 * @param context   The context to use to connect
 * @param timeout   Timeout on Redis commands
 * @return          If successful, the redisAsyncContext, otherwise NULL
 */
redisAsyncContext *redis_sentinel_connect_master_async(redis_sentinel_t *context, struct timeval timeout);

/**
 * Connect asynchronously to the sentinel slave
 *
 * @param context   The context to use to connect
 * @param timeout   Timeout on Redis commands
 * @return          If successful, the redisAsyncContext, otherwise NULL
 */
redisAsyncContext *redis_sentinel_connect_slave_async(redis_sentinel_t *context, struct timeval timeout);

/**
 * Parse a string of "hostname:port" type into a redis_addr_t structure
 *
 * @param cfg       The string to parse
 * @param addr      Where to store the parsed results
 * @return          Zero for success, -1 for error
 */
int redis_addr_cfg_parse(const char *cfg, redis_addr_t *addr);

#endif /** JITIKE_REDIS_SENTINEL_H_ @}*/
