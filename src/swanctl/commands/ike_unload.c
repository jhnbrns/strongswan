/*
 * Copyright (C) 2017-2018 Tobias Brunner
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

#include "command.h"

#include <errno.h>

static int ike_unload(vici_conn_t *conn)
{
	vici_req_t *req;
	vici_res_t *res;
	command_format_options_t format = COMMAND_FORMAT_NONE;
	char *arg, *spi_i = NULL, *spi_r = NULL;
	int ret = 0;
	bool reauth = FALSE;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'i':
				spi_i = arg;
				continue;
			case 'r':
				spi_r = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --ike-unload  option");
		}
		break;
	}

	req = vici_begin("ike-unload");
	if (spi_i)
	{
		vici_add_key_valuef(req, "spi_i", "%s", spi_i);
	}
	if (spi_r)
	{
		vici_add_key_valuef(req, "spi_r", "%s", spi_r);
	}
	res = vici_submit(req, conn);
	if (!res)
	{
		ret = errno;
		fprintf(stderr, "ike-unload request failed: %s\n", strerror(errno));
		return ret;
	}
	if (format & COMMAND_FORMAT_RAW)
	{
		vici_dump(res, "ike-unload reply", format & COMMAND_FORMAT_PRETTY,
				  stdout);
	}
	else
	{
		if (streq(vici_find_str(res, "no", "success"), "yes"))
		{
			printf("ike-unload completed successfully\n");
		}
		else
		{
			fprintf(stderr, "ike-unload failed: %s\n",
					vici_find_str(res, "", "errmsg"));
			ret = 1;
		}
	}
	vici_free_res(res);
	return ret;
}

/**
 * Register the command.
 */
static void __attribute__ ((constructor))reg()
{
	command_register((command_t) {
		ike_unload, 'U', "ike-unload", "Unload an IKE from Redis",
		{"--spi_i <initiator SPI> --spi_r <responder SPI>"},
		{
			{"help",		'h', 0, "show usage information"},
			{"spi_i",		'i', 1, "initiator SPI"},
			{"spi_r",		'r', 1, "responder SPI"},
		}
	});
}
