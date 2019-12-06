/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
 * Copyright (C) 2019 Cisco and/or its affiliates.
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
 * @defgroup redis_dh redis_dh
 * @{ @ingroup redis
 */

#ifndef REDIS_DH_H_
#define REDIS_DH_H_

#include "redis_interface.h"

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev1/keymat_v1.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/adopt_children_job.h>
#include <string.h>
#include <inttypes.h>

/**
 * Return a diffie_hellman_t struct
 */
diffie_hellman_t *create_redis_dh(chunk_t secret, chunk_t pub);

#endif /** REDIS_DH_ @}*/
