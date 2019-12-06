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

#include "redis_dh.h"

#include <daemon.h>
#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev1/keymat_v1.h>
#include <processing/jobs/callback_job.h>
#include <processing/jobs/adopt_children_job.h>
#include <string.h>
#include <inttypes.h>

typedef struct private_redis_dispatcher_t private_redis_dispatcher_t;
typedef struct redis_diffie_hellman_t redis_diffie_hellman_t;

/**
 * DH implementation for HA synced DH values
 */
struct redis_diffie_hellman_t {

	/**
	 * Implements diffie_hellman_t
	 */
	diffie_hellman_t dh;

	/**
	 * Shared secret
	 */
	chunk_t secret;

	/**
	 * Own public value
	 */
	chunk_t pub;
};

METHOD(diffie_hellman_t, dh_get_shared_secret, bool,
	redis_diffie_hellman_t *this, chunk_t *secret)
{
	*secret = chunk_clone(this->secret);
	return TRUE;
}

METHOD(diffie_hellman_t, dh_get_my_public_value, bool,
	redis_diffie_hellman_t *this, chunk_t *value)
{
	*value = chunk_clone(this->pub);
	return TRUE;
}

METHOD(diffie_hellman_t, dh_destroy, void,
	redis_diffie_hellman_t *this)
{
	free(this);
}

/**
 * Create a HA synced DH implementation
 */
diffie_hellman_t *redis_diffie_hellman_create(chunk_t secret, chunk_t pub)
{
	redis_diffie_hellman_t *this;

	INIT(this,
		.dh = {
			.get_shared_secret = _dh_get_shared_secret,
			.get_my_public_value = _dh_get_my_public_value,
			.destroy = _dh_destroy,
		},
		.secret = secret,
		.pub = pub,
	);

	return &this->dh;
}

diffie_hellman_t *create_redis_dh(chunk_t secret, chunk_t pub)
{
	return redis_diffie_hellman_create(secret, pub);
}
