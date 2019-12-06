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
 * @defgroup jitike_async_job jitike_async_job
 * @{ @ingroup jitike
 */

#ifndef JITIKE_ASYNC_JOB_H_
#define JITIKE_ASYNC_JOB_H_

typedef struct start_async_job_t start_async_job_t;

#include <library.h>
#include <processing/jobs/job.h>

#include "jitike_redis_sentinel.h"

/**
 * Class representing an asynchronous job which will run the libevent
 * event_base_dispatch() function to process asynchronous redis
 * events.
 */
struct start_async_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * Creates a job of type start_async_job.
 *
 * @return                      start_async_job_t object
 */
start_async_job_t *start_async_job_create(redis_sentinel_t *sentinel, char *redis_hostname, struct timeval timeout, char *alloc_id);

#endif /** JITIKE_ASYNC_JOB_H_ @}*/
