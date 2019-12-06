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

#include <inttypes.h>
#include <library.h>
#include <daemon.h>

#include "jitike_spi_generator.h"

#include <sys/types.h>
#include <ifaddrs.h>

/**
 * Get SPI callback arguments
 */
typedef struct {
	rng_t *rng;
	uint32_t host_ipv4_address;
} get_spi_args_t;

static get_spi_args_t *spi_args;

/**
 * Callback called to generate an IKE SPI for JITIKE.
 *
 * @param this                  Callback args containing rng_t and uint32_t
 * @return                      labeled SPI
 */
CALLBACK(jitike_get_spi, uint64_t,
        const get_spi_args_t *this)
{
	uint64_t spi;
	uint32_t lower_spi;

	if (!this->rng->get_bytes(this->rng, sizeof(lower_spi), (uint8_t*)&lower_spi))
	{
		return 0;
	}

	spi = (((uint64_t)this->host_ipv4_address << 32) | lower_spi);
	return spi;
}

bool jitike_spi_generator_register(void)
{
	rng_t *rng;
	uint32_t ipv4_addr = 0;
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	char *addr;
	char *cfg_iface = lib->settings->get_str(lib->settings, "%s.plugins.jitike.spi_interface", NULL, lib->ns);
	bool found_iface = FALSE;

	if (cfg_iface == NULL)
	{
		DBG1(DBG_CFG, "jitike_spi_generator_register: No interface defined, skipping using JITIKE SPI generator");
		return FALSE;
	}

	rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
	if (!rng)
	{
		return FALSE;
	}

	getifaddrs (&ifap);
	for (ifa = ifap; ifa; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr->sa_family==AF_INET)
		{
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			addr = inet_ntoa(sa->sin_addr);

			if (strncmp(ifa->ifa_name, cfg_iface, strlen(cfg_iface)) == 0)
			{
				DBG1(DBG_CFG, "jitike_spi_generator_register: Interface: %s\tAddress: %s\n", ifa->ifa_name, addr);

				if (inet_pton(AF_INET, addr, &ipv4_addr) != 1)
				{
					DBG1(DBG_CFG, "jitike_spi_generator_register: cannot generate IPv4 address for hostname, failing");
					return FALSE;
				}
				found_iface = TRUE;
				break;
			}
		}
	}

	freeifaddrs(ifap);

	/**
	 * If we did not find an interface, we need to return FALSE.
	 */
	if (found_iface != TRUE)
	{
		DBG1(DBG_CFG, "jitike_spi_generator_register: Cannot find interface %s", cfg_iface);
		return FALSE;
	}

	INIT(spi_args,
			.rng = rng,
			.host_ipv4_address = ipv4_addr,
	    );

	charon->ike_sa_manager->set_spi_cb(charon->ike_sa_manager,
			jitike_get_spi, spi_args);
	DBG1(DBG_CFG, "jitike_spi_generator_register: using IP address as uint32_t (%ld)", ipv4_addr);

	return TRUE;
}
