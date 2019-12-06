/*
 * Copyright (C) 2008 Martin Willi
 * HSR Hochschule fuer Technik Rapperswil
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
 * @defgroup jitike jitike
 * @ingroup cplugins
 *
 * @defgroup jitike_plugin jitike_plugin
 * @{ @ingroup jitike
 */

#ifndef JITIKE_PLUGIN_H_
#define JITIKE_PLUGIN_H_

#include <plugins/plugin.h>

/**
 * UDP port we use for communication
 */
#define JITIKE_PORT 4510

typedef struct jitike_plugin_t jitike_plugin_t;

/**
 * Plugin to synchronize state in a high availability cluster.
 */
struct jitike_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** JITIKE_PLUGIN_H_ @}*/
