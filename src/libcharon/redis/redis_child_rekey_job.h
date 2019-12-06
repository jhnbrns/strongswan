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
 * @defgroup redis_child_rekey_job redis_child_rekey_job
 * @{ @ingroup redis
 */

#ifndef REDIS_CHILD_REKEY_JOB_H_
#define REDIS_CHILD_REKEY_JOB_H_

typedef struct redis_child_rekey_job_t redis_child_rekey_job_t;

#include <library.h>
#include <processing/jobs/job.h>

#include "jitike_db.h"
#include "jitike_redis_sentinel.h"

#include <hiredis/hiredis.h>

/**
 * Class which will publish a rekey message to Redis for a specific
 * IKE or CHILD SA.
 */
struct redis_child_rekey_job_t {
	/**
	 * The job_t interface.
	 */
	job_t job_interface;
};

/**
 * Creates a job of type redis_child_rekey_job_t,
 *
 * @spi_i      Initiator SPI
 * @spi_r      Responder SPI
 * @return     redis_rekey_job_t object
 */
redis_child_rekey_job_t *redis_child_rekey_job_create(redis_sentinel_t *sentinel, uint64_t spi_i, uint64_t spi_r,
		char *ikesa, uint32_t ike_id, char *childsa, uint32_t child_id);

#endif /** REDIS_CHILD_REKEY_JOB_H_ @}*/
