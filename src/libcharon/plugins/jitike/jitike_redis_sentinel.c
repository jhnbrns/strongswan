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

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "jitike_redis_sentinel.h"
#include <utils/debug.h>

#define DEFAULT_SENTINEL_PORT	26379

static void append_node(redis_sentinel_t *context, redis_sentinel_node_t *node)
{
	if (context->list == NULL)
	{
		context->list = node;
		return;
	}
	redis_sentinel_node_t *curr = context->list;
	while (curr->next != NULL)
	{
		curr = curr->next;
	}
	curr->next = node;
	node->prev = curr;
}

static void move_to_front(redis_sentinel_t *context, redis_sentinel_node_t *node)
{
	if (node == context->list)
	{
		return;
	}
	node->prev->next = node->next;
	if (node->next)
	{
		node->next->prev = node->prev;
	}
	node->next = context->list;
	node->prev = NULL;
	context->list->prev = node;
	context->list = node;
}

redis_sentinel_t *redis_sentinel_create(redis_sentinel_cfg_t *cfg)
{
	redis_sentinel_t *context = malloc(sizeof(redis_sentinel_t));
	if (context == NULL)
	{
		return NULL;
	}
	memset(context, 0, sizeof(redis_sentinel_t));
	context->db = cfg->db;
	context->name = strdup(cfg->name);
	if (context->name == NULL)
	{
		free(context);
		return NULL;
	}

	for (uint32_t i = 0; i < cfg->addr_count; ++i)
	{
		redis_sentinel_node_t *node = malloc(sizeof(redis_sentinel_node_t));
		if (node == NULL)
		{
			redis_sentinel_release(context);
			return NULL;
		}
		memset(node, 0, sizeof(redis_sentinel_node_t));
		node->addr.host = strdup(cfg->addr_arr[i].host);
		node->addr.port = cfg->addr_arr[i].port;
		if (node->addr.host == NULL)
		{
			free(node);
			redis_sentinel_release(context);
			return NULL;
		}
		append_node(context, node);
	}

	return context;
}

void redis_sentinel_release(redis_sentinel_t *context)
{
	redis_sentinel_node_t *curr = context->list;
	redis_sentinel_node_t *next;
	while (curr)
	{
		next = curr->next;
		free(curr->addr.host);
		free(curr);
		curr = next;
	}
	free(context);
}

int redis_sentinel_get_master_addr(redis_sentinel_t *context, redis_addr_t *addr, struct timeval timeout)
{
	redis_sentinel_node_t *curr = context->list;
	while (curr)
	{
		redisContext *redis = redisConnectWithTimeout(curr->addr.host, curr->addr.port, timeout);
		if (redis == NULL || redis->err)
		{
			if (redis)
			{
				redisFree(redis);
			}
			curr = curr->next;
			continue;
		}
		redisReply *reply = redisCommand(redis, "SENTINEL get-master-addr-by-name %s", context->name);
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY || reply->elements != 2)
		{
			if (reply)
			{
				freeReplyObject(reply);
				redisFree(redis);
			}
			curr = curr->next;
			continue;
		}

		move_to_front(context, curr);
		addr->host = strdup(reply->element[0]->str);
		addr->port = atoi(reply->element[1]->str);
		freeReplyObject(reply);
		redisFree(redis);

		return 0;
	}

	return -1;
}

static char *get_slave_info(size_t elements, redisReply **element, char *key)
{
	for (size_t i = 0; i < elements; i += 2)
	{
		if (strcmp(element[i]->str, key) == 0)
		{
			return element[i + 1]->str;
		}
	}
	return NULL;
}

int redis_sentinel_get_slave_addr(redis_sentinel_t *context, redis_addr_t *addr, struct timeval timeout)
{
	redis_sentinel_node_t *curr = context->list;
	while (curr)
	{
		redisContext *redis = redisConnectWithTimeout(curr->addr.host, curr->addr.port, timeout);
		if (redis == NULL || redis->err)
		{
			if (redis)
			{
				redisFree(redis);
			}
			curr = curr->next;
			continue;
		}
		redisReply *reply = redisCommand(redis, "SENTINEL slaves %s", context->name);
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY)
		{
			if (reply)
			{
				freeReplyObject(reply);
				redisFree(redis);
			}
			curr = curr->next;
			continue;
		}

		for (size_t i = 0; i < reply->elements; ++i)
		{
			const char *flags = get_slave_info(reply->element[i]->elements, reply->element[i]->element, "flags");
			if (flags == NULL || strstr(flags, "disconnected"))
			{
				continue;
			}
			const char *host = get_slave_info(reply->element[i]->elements, reply->element[i]->element, "ip");
			if (host == NULL)
			{
				continue;
			}
			const char *port = get_slave_info(reply->element[i]->elements, reply->element[i]->element, "port");
			if (port == NULL)
			{
				continue;
			}

			move_to_front(context, curr);
			addr->host = strdup(host);
			addr->port = atoi(port);
			freeReplyObject(reply);
			redisFree(redis);

			return 0;
		}

		curr = curr->next;
	}

	return -1;
}

redisContext *redis_sentinel_connect_master(redis_sentinel_t *context, struct timeval timeout)
{
	for (int i = 0; i < 3; ++i)
	{
		redis_addr_t addr;
		if (redis_sentinel_get_master_addr(context, &addr, timeout) < 0)
		{
			return NULL;
		}

		redisContext *redis = redisConnectWithTimeout(addr.host, addr.port, timeout);
		if (redis == NULL || redis->err)
		{
			if (redis)
			{
				redisFree(redis);
			}
			free(addr.host);
			return NULL;
		}
		free(addr.host);

		redisReply *reply = redisCommand(redis, "ROLE");
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY)
		{
			if (reply)
			{
				freeReplyObject(reply);
			}
			redisFree(redis);
			return NULL;
		}
		if (strcmp(reply->element[0]->str, "master") != 0)
		{
			freeReplyObject(reply);
			redisFree(redis);
			continue;
		}
		freeReplyObject(reply);

		if (context->db > 0)
		{
			reply = redisCommand(redis, "SELECT %d", context->db);
			if (redis == NULL || reply->type == REDIS_REPLY_ERROR)
			{
				if (reply)
				{
					freeReplyObject(reply);
				}
				redisFree(redis);
				return NULL;
			}
			freeReplyObject(reply);
		}

		return redis;
	}

	return NULL;
}

redisContext *redis_sentinel_connect_slave(redis_sentinel_t *context, struct timeval timeout)
{
	for (int i = 0; i < 3; ++i)
	{
		redis_addr_t addr;
		if (redis_sentinel_get_slave_addr(context, &addr, timeout) < 0)
		{
			return NULL;
		}

		redisContext *redis = redisConnectWithTimeout(addr.host, addr.port, timeout);
		if (redis == NULL || redis->err)
		{
			if (redis)
			{
				redisFree(redis);
			}
			free(addr.host);
			return NULL;
		}
		free(addr.host);

		redisReply *reply = redisCommand(redis, "ROLE");
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY)
		{
			if (reply)
			{
				freeReplyObject(reply);
			}
			redisFree(redis);
			return NULL;
		}
		if (strcmp(reply->element[0]->str, "slave") != 0)
		{
			freeReplyObject(reply);
			redisFree(redis);
			continue;
		}
		freeReplyObject(reply);

		if (context->db > 0)
		{
			reply = redisCommand(redis, "SELECT %d", context->db);
			if (redis == NULL || reply->type == REDIS_REPLY_ERROR)
			{
				if (reply)
				{
					freeReplyObject(reply);
				}
				redisFree(redis);
				return NULL;
			}
			freeReplyObject(reply);
		}

		return redis;
	}

	return NULL;
}

redisAsyncContext *redis_sentinel_connect_master_async(redis_sentinel_t *context, struct timeval timeout)
{
        for (int i = 0; i < 3; ++i)
        {
		redis_addr_t addr;
		if (redis_sentinel_get_master_addr(context, &addr, timeout) < 0)
		{
			return NULL;
		}

		redisContext *redis = redisConnectWithTimeout(addr.host, addr.port, timeout);
		if (redis == NULL || redis->err)
		{
			if (redis)
			{
				redisFree(redis);
			}
			free(addr.host);
			return NULL;
		}

		redisReply *reply = redisCommand(redis, "ROLE");
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY)
		{
			if (reply)
			{
				freeReplyObject(reply);
			}
			redisFree(redis);
			free(addr.host);
			return NULL;
		}
		if (strcmp(reply->element[0]->str, "master") != 0)
		{
			freeReplyObject(reply);
			redisFree(redis);
			free(addr.host);
			continue;
		}
		freeReplyObject(reply);

		if (context->db > 0)
		{
			reply = redisCommand(redis, "SELECT %d", context->db);
			if (redis == NULL || reply->type == REDIS_REPLY_ERROR)
			{
				if (reply)
				{
					freeReplyObject(reply);
				}
				redisFree(redis);
				free(addr.host);
				return NULL;
			}
			freeReplyObject(reply);
		}
		redisFree(redis);

		redisAsyncContext *async_redis = redisAsyncConnect(addr.host, addr.port);
		if (async_redis == NULL || async_redis->err)
		{
			if (async_redis)
			{
				redisAsyncFree(async_redis);
			}
			free(addr.host);
			free(addr.host);
			return NULL;
		}
		DBG1(DBG_CFG, "Successfully connected to host %s / port %d", addr.host, addr.port);
		free(addr.host);

		return async_redis;
        }

        return NULL;
}

redisAsyncContext *redis_sentinel_connect_slave_async(redis_sentinel_t *context, struct timeval timeout)
{
	redisAsyncContext *actx = NULL;

	return actx;
}

int redis_addr_cfg_parse(const char *cfg, redis_addr_t *addr)
{
	char *sep = strchr(cfg, ':');
	if (sep == NULL)
	{
		/**
		 * We only have a hostname, not a "hostname:port" combo ...
		 */
		addr->host = strdup(cfg);
		addr->port = DEFAULT_SENTINEL_PORT;
		return 0;
	}
	addr->port = atoi(sep + 1);
	if (addr->port <= 0)
	{
		return -1;
	}
	addr->host = strndup(cfg, sep - cfg);

	return 0;
}
