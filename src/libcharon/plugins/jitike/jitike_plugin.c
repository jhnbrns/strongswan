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

#include "jitike_plugin.h"
#include "jitike_redis.h"
#include "jitike_db.h"
#include "jitike_ipsec.h"

#include <daemon.h>
#include <config/child_cfg.h>

typedef struct private_jitike_plugin_t private_jitike_plugin_t;

/**
 * private data of ha plugin
 */
struct private_jitike_plugin_t {

	/**
	 * implements plugin interface
	 */
	jitike_plugin_t public;

#if 0
	/**
	 * CHILD_SA synchronization
	 */
	jitike_child_t *child;
.FIXME: Add child listener into jitike_redis
#endif

	/**
	 * Redis connection information.
	 */
	jitike_redis_t *redis;
};

METHOD(plugin_t, get_name, char*,
	private_jitike_plugin_t *this)
{
	return "jitike";
}

/**
 * Initialize plugin
 */
static bool initialize_plugin(private_jitike_plugin_t *this)
{
	char *local, *remote, *secret;
	u_int count;
	bool fifo, monitor, resync;

	if ((this->redis = jitike_redis_create()) == NULL) {
		DBG1(DBG_CFG, "jitike plugin failed redis intialization");
		DESTROY_IF(this->redis);
		return FALSE;
	}

	return TRUE;
}

/**
 * Initialize plugin and register listener
 */
static bool plugin_cb(private_jitike_plugin_t *this,
					  plugin_feature_t *feature, bool reg, void *cb_data)
{
	if (reg)
	{
		if (!initialize_plugin(this))
		{
			return FALSE;
		}
		charon->bus->add_listener(charon->bus, &this->redis->listener);
	}
	else
	{
		charon->bus->remove_listener(charon->bus, &this->redis->listener);
	}
	return TRUE;
}

METHOD(plugin_t, get_features, int,
	private_jitike_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK((plugin_feature_callback_t)plugin_cb, NULL),
			PLUGIN_PROVIDE(CUSTOM, "jitike"),
				PLUGIN_DEPENDS(CUSTOM, "kernel-net"),
		PLUGIN_CALLBACK(kernel_ipsec_register, jitike_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
	};
	int count = countof(f);

	*features = f;

	if (!lib->settings->get_bool(lib->settings,
				"%s.plugins.jitike.fake_kernel", FALSE, lib->ns))
	{
		count -= 2;
	}

	return count;
}

METHOD(plugin_t, destroy, void,
	private_jitike_plugin_t *this)
{
	DESTROY_IF(this->redis);
	free(this);
}

/**
 * Plugin constructor
 */
plugin_t *jitike_plugin_create()
{
	private_jitike_plugin_t *this;

#if 0
	if (!lib->caps->keep(lib->caps, CAP_CHOWN))
	{	/* required to chown(2) control socket, jitike_kernel also needs it at
		 * runtime */
		DBG1(DBG_CFG, "jitike plugin requires CAP_CHOWN capability");
		return NULL;
	}
#endif

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
	);

	return &this->public.plugin;
}
