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
 * @defgroup redis_publish_job redis_publish_job
 * @{ @ingroup redis
 */

#ifndef REDIS_PUBLISH_JOB_H_
#define REDIS_PUBLISH_JOB_H_

typedef struct start_redis_publish_job_t start_redis_publish_job_t;

#include <library.h>
#include <processing/jobs/job.h>

#include "jitike_db.h"
#include "jitike_redis_sentinel.h"

#include <hiredis/hiredis.h>

/**
 * Class which handles publishing an event to Redis, with retry.
 */
struct start_redis_publish_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * Creates a job of type start_redis_publish_job_t
 *
 * @buf        buffer of data to publish
 * @len        length of the data to transfer
 * @return     start_del_job_t object
 */
start_redis_publish_job_t *start_redis_publish_job_create(int cinfo, int db, bool fallback_publish, char *buf, size_t len);

#endif /** REDIS_PUBLISH_JOB_H_ @}*/
