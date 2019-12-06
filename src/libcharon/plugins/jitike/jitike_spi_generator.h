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
 * @defgroup jitike_spi_generator jitike_spi_generator
 * @{ @ingroup jitike
 */

#ifndef JITIKE_SPI_GENERATOR_H_
#define JITIKE_SPI_GENERATOR_H_

#include <plugins/plugin.h>

/**
 * Register the JITIKE SPI generator callback.
 *
 * @return                      TRUE on success
 */
bool jitike_spi_generator_register(void);

#endif /** JITIKE_SPI_GENERATOR_H_ @}*/
