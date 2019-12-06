/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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

#include "jitike_ipsec.h"

#include <time.h>

typedef struct private_jitike_ipsec_t private_jitike_ipsec_t;

/**
 * Private variables and functions of kernel_pfkey class.
 */
struct private_jitike_ipsec_t {
	/**
	 * Public interface.
	 */
	jitike_ipsec_t public;

	rng_t *rng;
};

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_jitike_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	uint32_t r_spi;

	if (!this->rng->get_bytes(this->rng, sizeof(r_spi), (uint8_t*)&r_spi))
	{
		*spi = 0;
	}

	*spi = r_spi;

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_jitike_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	return FAILED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	*use_time = 1;
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_jitike_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_jitike_ipsec_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
jitike_ipsec_t *jitike_ipsec_create()
{
	private_jitike_ipsec_t *this;
	rng_t *rng;

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FALSE;
	}

	INIT(this,
		.public = {
			.interface = {
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = (void*)return_failed,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = (void*)return_failed,
				.bypass_socket = (void*)return_true,
				.enable_udp_decap = (void*)return_true,
				.destroy = _destroy,
			},
		},
		.rng = rng,
	);

	return &this->public;
}
