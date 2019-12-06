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
 * @defgroup jitike_del_job jitike_del_job
 * @{ @ingroup jitike
 */

#ifndef JITIKE_DEL_JOB_H_
#define JITIKE_DEL_JOB_H_

typedef struct start_del_job_t start_del_job_t;

#include <library.h>
#include <processing/jobs/job.h>

#include "jitike_db.h"
#include "jitike_redis_sentinel.h"

#include <hiredis/hiredis.h>

/**
 * Class which deletes a hashset from redis for a specificed IKE_SA
 * initiator/responder SPI key.
 */
struct start_del_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * Creates a job of type start_del_job.
 *
 * @reply      We're passed a copy of the redisReply object, which we will free when finished
 * @return     start_del_job_t object
 */
start_del_job_t *start_del_job_create(redis_sentinel_t *sentinel, char *redis_hostname, bool fallback_delete, ike_channel_sa_id_encoding_t *enc);

#endif /** JITIKE_DEL_JOB_H_ @}*/
