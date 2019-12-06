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

#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>

#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev1/keymat_v1.h>
#include <threading/mutex.h>
#include <encoding/payloads/ike_header.h>

#include "redis_load_ike.h"
#include "redis_interface.h"
#include "redis_dh.h"
#include "jitike_redis.h"
#include "jitike_db.h"

/*
 * .FIXME: Ugly hack due to us including jitike_db.h.
 */
char ha_one[MAX_REDIS_ADDR_SIZE];
char ha_two[MAX_REDIS_ADDR_SIZE];

/**
 * Lookup a child cfg from the peer cfg by name
 */
static child_cfg_t* find_child_cfg(ike_sa_t *ike_sa, char *name)
{
	peer_cfg_t *peer_cfg;
	child_cfg_t *current, *found = NULL;
	enumerator_t *enumerator;

	peer_cfg = ike_sa->get_peer_cfg(ike_sa);
	if (peer_cfg)
	{
		enumerator = peer_cfg->create_child_cfg_enumerator(peer_cfg);
		while (enumerator->enumerate(enumerator, &current))
		{
			if (streq(current->get_name(current), name))
			{
				found = current;
				break;
			}
		}
		enumerator->destroy(enumerator);
	}
	return found;
}

int charon_process_ike_updown(redisReply *reply)
{
	size_t k=0;
	ike_sa_id_t *ike_sa_id = NULL;
	ike_sa_t *ike_sa = NULL;
	host_t *local, *other;
	bool received_vip = FALSE, first_local_vip = TRUE, first_peer_addr = TRUE;
	peer_cfg_t *peer_cfg = NULL;

	/* Get the IKE_ID first and checkout the IKE_SA */
	for (k=0; k < reply->elements; k+=2) {
		if (strncmp(reply->element[k]->str, JI_IKE_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			ike_sa_id_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(ike_sa_id_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: invalid size for JI_IKE_ID: %d",
						reply->element[k+1]->len);
				return -1;
			}

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_IKE_ID key %s", reply->element[k]->str);

			enc = (ike_sa_id_encoding_t *)reply->element[k+1]->str;
			ike_sa_id = ike_sa_id_create(enc->ike_version,
					enc->initiator_spi, enc->responder_spi,
					enc->initiator);
			ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);
		}
	}

	/* If we can't find the IKE_SA, return an error */
	if (ike_sa == NULL)
	{
		DBG1(DBG_CFG, "charon_process_ike_updown: Failed checking out IKE_SA, returning FALSE");
		return -1;
	}

	/* Dump the entire array */
	for (k=0; k < reply->elements; k+=2) {
		if (strncmp(reply->element[k]->str, JI_LOCAL_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			identification_encoding_t *enc;
			u_char *data;
			chunk_t did;
			identification_t *id;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_LOCAL_ID key %s", reply->element[k]->str);

			enc = (identification_encoding_t *)reply->element[k+1]->str;
			data = malloc(enc->len);
			memcpy(data, enc->encoding, enc->len);
			did = chunk_create(data, enc->len);
			id = identification_create_from_encoding(enc->type, did);
			ike_sa->set_my_id(ike_sa, id->clone(id));
			chunk_free(&did);
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			identification_encoding_t *enc;
			u_char *data;
			chunk_t did;
			identification_t *id;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_REMOTE_ID key %s", reply->element[k]->str);

			enc = (identification_encoding_t *)reply->element[k+1]->str;
			data = malloc(enc->len);
			memcpy(data, enc->encoding, enc->len);
			did = chunk_create(data, enc->len);
			id = identification_create_from_encoding(enc->type, did);
			ike_sa->set_other_id(ike_sa, id->clone(id));
			chunk_free(&did);
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_EAP_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			auth_cfg_t *auth;
			identification_encoding_t *enc;
			u_char *data;
			chunk_t did;
			identification_t *id;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_REMOTE_EAP_ID key %s", reply->element[k]->str);

			enc = (identification_encoding_t *)reply->element[k+1]->str;
			data = malloc(enc->len);
			memcpy(data, enc->encoding, enc->len);
			did = chunk_create(data, enc->len);
			id = identification_create_from_encoding(enc->type, did);
			auth = auth_cfg_create();
			auth->add(auth, AUTH_RULE_EAP_IDENTITY, id->clone(id));
			ike_sa->add_auth_cfg(ike_sa, FALSE, auth);
			chunk_free(&did);
		}
		else if (strncmp(reply->element[k]->str, JI_LOCAL_ADDR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(host_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: invalid size for JI_LOCAL_ADDR: %d",
						reply->element[k+1]->len);
				return -1;
			}

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_LOCAL_ADDR key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			local = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!local)
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: Failed creating local host in JI_LOCAL_ADDR");
				return -1;
			}
			ike_sa->set_my_host(ike_sa, local->clone(local));
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_ADDR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(host_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: invalid size for JI_REMOTE_ADDR: %d",
						reply->element[k+1]->len);
				return -1;
			}

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_REMOTE_ADDR key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			other = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!other)
			{
				DBG1(DBG_CFG, "process_ike_updopwn: Failed creating local host in JI_REMOTE_ADDR");
				return -1;
			}
			ike_sa->set_other_host(ike_sa, other->clone(other));
		}
		else if (strncmp(reply->element[k]->str, JI_CONDITIONS, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			uint32_t val;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_CONDITIONS key %s", reply->element[k]->str);

			val = atoi(reply->element[k+1]->str);
			set_condition(ike_sa, val, COND_NAT_ANY);
			set_condition(ike_sa, val, COND_NAT_HERE);
			set_condition(ike_sa, val, COND_NAT_THERE);
			set_condition(ike_sa, val, COND_NAT_FAKE);
			set_condition(ike_sa, val, COND_EAP_AUTHENTICATED);
			set_condition(ike_sa, val, COND_CERTREQ_SEEN);
			set_condition(ike_sa, val, COND_ORIGINAL_INITIATOR);
			set_condition(ike_sa, val, COND_STALE);
			set_condition(ike_sa, val, COND_INIT_CONTACT_SEEN);
			set_condition(ike_sa, val, COND_XAUTH_AUTHENTICATED);
		}
		else if (strncmp(reply->element[k]->str, JI_EXTENSIONS, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			uint32_t val;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_EXTENSIONS key %s", reply->element[k]->str);

			val = atoi(reply->element[k+1]->str);
			set_extension(ike_sa, val, EXT_NATT);
			set_extension(ike_sa, val, EXT_MOBIKE);
			set_extension(ike_sa, val, EXT_HASH_AND_URL);
			set_extension(ike_sa, val, EXT_MULTIPLE_AUTH);
			set_extension(ike_sa, val, EXT_STRONGSWAN);
			set_extension(ike_sa, val, EXT_EAP_ONLY_AUTHENTICATION);
			set_extension(ike_sa, val, EXT_MS_WINDOWS);
			set_extension(ike_sa, val, EXT_XAUTH);
			set_extension(ike_sa, val, EXT_DPD);
		}
		else if (strncmp(reply->element[k]->str, JI_LOCAL_VIP, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_LOCAL_VIP key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			other = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!other)
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: Failed creating local host in JI_LOCAL_VIP");
				return -1;
			}

			if (first_local_vip)
			{
				ike_sa->clear_virtual_ips(ike_sa, TRUE);
				first_local_vip = FALSE;
			}
			ike_sa->add_virtual_ip(ike_sa, TRUE, other);
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_VIP, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_REMOTE_VIP key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			other = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!other)
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: Failed creating local host in JI_REMOTE_VIP");
				return -1;
			}

			if (!received_vip)
			{
				ike_sa->clear_virtual_ips(ike_sa, TRUE);
			}
			ike_sa->add_virtual_ip(ike_sa, FALSE, other);
			received_vip = TRUE;
		}
		else if (strncmp(reply->element[k]->str, JI_PEER_ADDR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_updown: Found JI_PEER_ADDR key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			other = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!other)
			{
				DBG1(DBG_CFG, "charon_process_ike_updown: Failed creating local host in JI_PEER_ADDR");
				return -1;
			}

			if (first_peer_addr)
			{
				ike_sa->clear_peer_addresses(ike_sa);
				first_peer_addr = FALSE;
			}
			ike_sa->add_peer_address(ike_sa, other->clone(other));
		}
		else
		{
			DBG2(DBG_CFG, "charon_process_ike_updown: Found unneeded redis field: %s", reply->element[k]->str);
		}
	}

	if (ike_sa)
	{
		if (ike_sa->get_state(ike_sa) == IKE_CONNECTING &&
				ike_sa->get_peer_cfg(ike_sa))
		{
			DBG1(DBG_CFG, "installed IKE_SA '%s' %H[%Y]...%H[%Y]",
					ike_sa->get_name(ike_sa),
					ike_sa->get_my_host(ike_sa), ike_sa->get_my_id(ike_sa),
					ike_sa->get_other_host(ike_sa), ike_sa->get_other_id(ike_sa));
			ike_sa->set_state(ike_sa, IKE_ESTABLISHED);
		}
#ifdef USE_IKEV1
		if (ike_sa->get_version(ike_sa) == IKEV1)
		{
			lib->processor->queue_job(lib->processor, (job_t*)
					adopt_children_job_create(ike_sa->get_id(ike_sa)));
		}
#endif /* USE_IKEV1 */
		charon->bus->ike_updown(charon->bus, ike_sa, TRUE);
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
	}

	return 0;
}

/**
 * This function will pull all CHILD_SA JITIKE hashsets from Redis for an IKE_SA, and install
 * them locally into strongSwan.
 */
int charon_add_all_child_sa(int cinfo, mutex_t *mutex, int db, ike_sa_id_t *ike_sa_id, const char *key)
{
	int ret = 0, k = 0;
	redisReply *reply = NULL;

	/**
	 * The basic idea of how this works:
	 *
	 * Get a list of all CHILD_SA hashset keys:
	 *	* KEYS key-*
	 * Now, for each one, get the hashset and parse the data we need:
	 *	* HGETALL key
	 * Add the keys.
	 */

	/**
	 * First, lets get the keys we are looking for.
	 */
	reply = charonRedisCommand(cinfo, db, "KEYS %s-*", key);

	if (reply == NULL)
	{
		DBG1(DBG_CFG, "charon_add_all_child_sa: charonRedisCommand returned NULL while running KEYS, failing");
		ret = -1;
		goto out;
	}

	/* Validate the reply */
	if (reply->type != REDIS_REPLY_ARRAY)
	{
		ret = -1;
		goto out;
	}

	if (reply->elements == 0)
	{
		/* Otherwise, we're done */
		ret = 0;
		goto out;
	}

	/**
	 * Walk each key, processing it and adding the CHILD_SA it represents.
	 */
	for (k=0; k < reply->elements; k++)
	{
		redisReply *innerReply = NULL;
		int m = 0;
		ike_sa_t *ike_sa;
		bool initiator = FALSE;
		uint32_t inbound_spi = 0, outbound_spi = 0;
		uint16_t inbound_cpi = 0, outbound_cpi = 0;
		uint8_t mode = MODE_TUNNEL, ipcomp = 0;
		char config_name_child[128];
		linked_list_t *local_ts = NULL, *remote_ts = NULL;
		traffic_selector_t *rts, *lts;
		uint16_t dh_grp_child = 0, integ_child = 0, encr_child = 0, len_child = 0;
		chunk_t nonce_i_child = chunk_empty, nonce_r_child = chunk_empty, secret_child = chunk_empty;
		uint16_t esn_child = NO_EXT_SEQ_NUMBERS;
		child_cfg_t *config = NULL;
		child_sa_t *child_sa;
		proposal_t *proposal;
		diffie_hellman_t *dh = NULL;
		chunk_t encr_i, integ_i, encr_r, integ_r;
		bool ok = FALSE, failed = FALSE;
		chunk_t nonce_i = chunk_empty, nonce_r = chunk_empty;

		/* Create traffic selector linked lists */
		local_ts = linked_list_create();
		remote_ts = linked_list_create();

		innerReply = charonRedisCommand(cinfo, db, "HGETALL %s", reply->element[k]->str);

		if (innerReply == NULL)
		{
			DBG1(DBG_CFG, "charon_add_all_child_sa: NULL while running HGETALL %s", reply->element[k]->str);
			goto next_child;
		}

		if (innerReply->type != REDIS_REPLY_ARRAY)
		{
			DBG1(DBG_CFG, "charon_add_all_child_sa: While processing HGETALL %s, invalid reply type: %d", innerReply->type);
			goto next_child;
		}

		if (innerReply->elements == 0)
		{
			DBG1(DBG_CFG, "charon_add_all_child_sa: Invalid number of elements");
			goto next_child;
		}

		/**
		 * Process all items in the array now.
		 */
		for (m=0; m < innerReply->elements; m+=2)
		{
			if (strncmp(innerReply->element[m]->str, JI_INITIATOR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				initiator = atoi(innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_INITIATOR key %s with value %d",
						innerReply->element[m]->str, initiator);
			}
			else if (strncmp(innerReply->element[m]->str, JI_INBOUND_SPI, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				inbound_spi = htonl(atoi(innerReply->element[m+1]->str));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found inbound_spi 0x%08x", inbound_spi);
			}
			else if (strncmp(innerReply->element[m]->str, JI_OUTBOUND_SPI, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				outbound_spi = htonl(atoi(innerReply->element[m+1]->str));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found outbound_spi 0x%08x", outbound_spi);
			}
			else if (strncmp(innerReply->element[m]->str, JI_INBOUND_CPI, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				inbound_cpi = htons(atoi(innerReply->element[m+1]->str));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found inbound_cpi %d", inbound_cpi);
			}
			else if (strncmp(innerReply->element[m]->str, JI_OUTBOUND_CPI, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				outbound_cpi = htons(atoi(innerReply->element[m+1]->str));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found outbound_cpi %d", outbound_cpi);
			}
			else if (strncmp(innerReply->element[m]->str, JI_IPSEC_MODE, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				mode = atoi(innerReply->element[m+1]->str);
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found mode %d", mode);
			}
			else if (strncmp(innerReply->element[m]->str, JI_IPCOMP, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				ipcomp = atoi(innerReply->element[m+1]->str);
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found ipcomp %d", ipcomp);
			}
			else if (strncmp(innerReply->element[m]->str, JI_CONFIG_NAME_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				/**
				 * .FIXME: Hard coded string length!?!?!
				 */
				snprintf(config_name_child, 128, "%s", innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_CONFIG_NAME key %s with value %s",
						innerReply->element[m]->str, config_name_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_LOCAL_TS, strlen(JI_LOCAL_TS)) == 0)
			{
				ts_encoding_t *enc;
				host_t *host;
				int addr_len;

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_LOCAL_TS");

				enc = (ts_encoding_t *)innerReply->element[m+1]->str;

				switch (enc->type)
				{
					case TS_IPV4_ADDR_RANGE:
						addr_len = 4;
						break;
					case TS_IPV6_ADDR_RANGE:
						addr_len = 16;
						break;
					default:
						DBG1(DBG_CFG, "charon_add_all_child_sa: Error with JI_LOCAL_TS type");
						goto next_child;
				}
				if (enc->dynamic)
				{
					host = host_create_from_chunk(0, chunk_create((u_char *)enc->encoding, addr_len), 0);
					if (!host)
					{
						DBG1(DBG_CFG, "charon_add_all_child_sa: JI_LOCAL_TS host not found");
						goto next_child;
					}
					lts = traffic_selector_create_dynamic(enc->protocol, enc->from_port, enc->to_port);
					lts->set_address(lts, host);
					host->destroy(host);
				}
				else
				{
					lts = traffic_selector_create_from_bytes(enc->protocol,
							enc->type, chunk_create((u_char *)enc->encoding, addr_len),
							enc->from_port,
							chunk_create((u_char *)enc->encoding + addr_len, addr_len),
							enc->to_port);
					if (!lts)
					{
						DBG1(DBG_CFG, "charon_add_all_child_sa: JI_LOCAL_TS error creating traffic selector");
						goto next_child;
					}
				}

				local_ts->insert_last(local_ts, lts->clone(lts));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found local TS: %R", lts);
				lts->destroy(lts);
			}
			else if (strncmp(innerReply->element[m]->str, JI_REMOTE_TS, strlen(JI_REMOTE_TS)) == 0)
			{
				ts_encoding_t *enc;
				host_t *host;
				int addr_len;

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_REMOTE_TS");

				enc = (ts_encoding_t *)innerReply->element[m+1]->str;

				switch (enc->type)
				{
					case TS_IPV4_ADDR_RANGE:
						addr_len = 4;
						break;
					case TS_IPV6_ADDR_RANGE:
						addr_len = 16;
						break;
					default:
						DBG1(DBG_CFG, "charon_add_all_child_sa: Error with JI_REMOTE_TS type");
						goto next_child;
				}
				if (enc->dynamic)
				{
					host = host_create_from_chunk(0, chunk_create((u_char *)enc->encoding, addr_len), 0);
					if (!host)
					{
						DBG1(DBG_CFG, "charon_add_all_child_sa: JI_REMOTE_TS host not found");
						goto next_child;
					}
					rts = traffic_selector_create_dynamic(enc->protocol, enc->from_port, enc->to_port);
					rts->set_address(rts, host);
					host->destroy(host);
				}
				else
				{
					rts = traffic_selector_create_from_bytes(enc->protocol,
							enc->type, chunk_create((u_char *)enc->encoding, addr_len),
							enc->from_port,
							chunk_create((u_char *)enc->encoding + addr_len, addr_len),
							enc->to_port);
					if (!rts)
					{
						DBG1(DBG_CFG, "charon_add_all_child_sa: JI_REMOTE_TS error creating traffic selector");
						goto next_child;
					}
				}

				remote_ts->insert_last(remote_ts, rts->clone(rts));
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found remote TS: %R", rts);
				rts->destroy(rts);
			}
			else if (strncmp(innerReply->element[m]->str, JI_ALG_INTEG_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				integ_child = atoi(innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_ALG_INTEG_CHILD key %s with value %d",
						innerReply->element[m]->str, integ_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_ALG_ENCR_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				encr_child = atoi(innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_ALGR_ENCR_CHILD key %s with value %d",
						innerReply->element[m]->str, encr_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_ALG_ENCR_LEN_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				len_child = atoi(innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_ALGR_ENCR_LEN_CHILD key %s with value %d",
						innerReply->element[m]->str, len_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_ALG_DH_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				dh_grp_child = atoi(innerReply->element[m+1]->str);

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_ALG_DH_CHILD key %s with value %d",
						innerReply->element[m]->str, dh_grp_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_ESN_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				esn_child = atoi(innerReply->element[m+1]->str);
				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_ESN_CHILD %d", esn_child);
			}
			else if (strncmp(innerReply->element[m]->str, JI_NONCE_I_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				chunk_encoding_t *enc;

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_NONCE_I_CHILD key");

				enc = (chunk_encoding_t *)innerReply->element[m+1]->str;
				nonce_i_child = chunk_create((u_char *)enc->encoding, enc->len);
			}
			else if (strncmp(innerReply->element[m]->str, JI_NONCE_R_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				chunk_encoding_t *enc;

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_NONCE_R_CHILD key");

				enc = (chunk_encoding_t *)innerReply->element[m+1]->str;
				nonce_r_child = chunk_create((u_char *)enc->encoding, enc->len);
			}
			else if (strncmp(innerReply->element[m]->str, JI_SECRET_CHILD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
			{
				chunk_encoding_t *enc;

				DBG2(DBG_CFG, "charon_add_all_child_sa: Found JI_SECRET_CHILD key %s", innerReply->element[m]->str);

				enc = (chunk_encoding_t *)innerReply->element[m+1]->str;
				secret_child = chunk_create((u_char *)enc->encoding, enc->len);
			}
		}

		/* Now install the CHILD_SAs */
		ike_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, ike_sa_id);

		if (!ike_sa)
		{
			DBG1(DBG_CHD, "charon_add_all_child_sa: IKE_SA [%s] for JITIKE CHILD_SA not found", key);
			ret = -1;
			goto next_child;
		}

		config = find_child_cfg(ike_sa, config_name_child);
		if (!config)
		{
			DBG1(DBG_CHD, "charon_add_all_child_sa: JITIKE is missing nodes child configuration for [%s]", key);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			ret = -1;
			goto next_child;
		}

		child_sa = child_sa_create(ike_sa->get_my_host(ike_sa),
				ike_sa->get_other_host(ike_sa), config, 0,
				ike_sa->has_condition(ike_sa, COND_NAT_ANY),
				0, 0);

		child_sa->set_mode(child_sa, mode);
		child_sa->set_protocol(child_sa, PROTO_ESP);
		child_sa->set_ipcomp(child_sa, ipcomp);

		proposal = proposal_create(PROTO_ESP, 0);
		if (integ_child)
		{
			proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, integ_child, 0);
		}
		if (encr_child)
		{
			proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, encr_child, len_child);
		}
		if (dh_grp_child)
		{
			proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, dh_grp_child, 0);
		}

		proposal->add_algorithm(proposal, EXTENDED_SEQUENCE_NUMBERS, esn_child, 0);
		if (secret_child.len)
		{
			dh = create_redis_dh(secret_child, chunk_empty);
		}
		if (ike_sa->get_version(ike_sa) == IKEV2)
		{
			keymat_v2_t *keymat_v2 = (keymat_v2_t*)ike_sa->get_keymat(ike_sa);

			ok = keymat_v2->derive_child_keys(keymat_v2, proposal, dh,
					nonce_i_child, nonce_r_child, &encr_i, &integ_i, &encr_r, &integ_r);
		}
		if (ike_sa->get_version(ike_sa) == IKEV1)
		{
			keymat_v1_t *keymat_v1 = (keymat_v1_t*)ike_sa->get_keymat(ike_sa);
			uint32_t spi_i, spi_r;

			spi_i = initiator ? inbound_spi : outbound_spi;
			spi_r = initiator ? outbound_spi : inbound_spi;

			ok = keymat_v1->derive_child_keys(keymat_v1, proposal, dh, spi_i, spi_r,
					nonce_i_child, nonce_r_child, &encr_i, &integ_i, &encr_r, &integ_r);
		}
		if (!ok)
		{
			DBG1(DBG_CHD, "charon_add_all_child_sa: JITIKE CHILD_SA key derivation failed for [%s]", key);
			child_sa->destroy(child_sa);
			proposal->destroy(proposal);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			ret = -1;
			goto next_child;
		}
		child_sa->set_proposal(child_sa, proposal);
		child_sa->set_state(child_sa, CHILD_INSTALLING);
		proposal->destroy(proposal);

		child_sa->set_policies(child_sa, local_ts, remote_ts);

		if (initiator)
		{
			if (child_sa->install(child_sa, encr_r, integ_r, inbound_spi,
						inbound_cpi, initiator, TRUE, TRUE) != SUCCESS ||
					child_sa->install(child_sa, encr_i, integ_i, outbound_spi,
						outbound_cpi, initiator, FALSE, TRUE) != SUCCESS)
			{
				failed = TRUE;
			}
		}
		else
		{
			if (child_sa->install(child_sa, encr_i, integ_i, inbound_spi,
						inbound_cpi, initiator, TRUE, TRUE) != SUCCESS ||
					child_sa->install(child_sa, encr_r, integ_r, outbound_spi,
						outbound_cpi, initiator, FALSE, TRUE) != SUCCESS)
			{
				failed = TRUE;
			}
		}
		charon->bus->child_keys(charon->bus, child_sa, initiator, dh, nonce_i, nonce_r);
		DESTROY_IF(dh);
		chunk_clear(&encr_i);
		chunk_clear(&integ_i);
		chunk_clear(&encr_r);
		chunk_clear(&integ_r);

		if (failed)
		{
			DBG1(DBG_CHD, "charon_add_all_child_sa: JITIKE CHILD_SA installation failed for [%s]", key);
			child_sa->destroy(child_sa);
			local_ts->destroy_offset(local_ts, offsetof(traffic_selector_t, destroy));
			remote_ts->destroy_offset(remote_ts, offsetof(traffic_selector_t, destroy));
			local_ts = remote_ts = NULL;
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
			/*
			 * This is an error when we fail to install a CHILD_SA, mark it as so.
			 */
			ret = -1;
			goto next_child;
		}

		child_sa->install_policies(child_sa);
		local_ts->destroy_offset(local_ts, offsetof(traffic_selector_t, destroy));
		remote_ts->destroy_offset(remote_ts, offsetof(traffic_selector_t, destroy));
		local_ts = remote_ts = NULL;

		child_sa->set_state(child_sa, CHILD_INSTALLED);
		ike_sa->add_child_sa(ike_sa, child_sa);

		charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);

next_child:
		if (innerReply != NULL)
		{
			freeReplyObject(innerReply);
		}
		if (local_ts != NULL)
		{
			local_ts->destroy(local_ts);
		}
		if (remote_ts != NULL)
		{
			remote_ts->destroy(remote_ts);
		}
	}

out:
	if (reply != NULL)
	{
		freeReplyObject(reply);
	}

	return ret;
}

int charon_process_ike_add(int cinfo, mutex_t *mutex, int db, const char *command)
{
	redisReply *reply = NULL;
	size_t k=0;
	int ret = 0;
	ike_version_t version = IKEV2;
	ike_sa_id_t *ike_sa_id = NULL, *old_sa_id = NULL;
	ike_sa_t *ike_sa = NULL, *old_sa = NULL;
	host_t *other = NULL;
	chunk_t nonce_i = chunk_empty, nonce_r = chunk_empty;
	chunk_t secret = chunk_empty, old_skd = chunk_empty;;
	chunk_t local_dh = chunk_empty, remote_dh = chunk_empty, psk = chunk_empty;
	uint16_t encr = 0, len = 0, integ = 0, prf = 0, old_prf = PRF_UNDEFINED;
	uint16_t dh_grp = 0;
	auth_method_t method = AUTH_RSA;
	peer_cfg_t *peer_cfg = NULL;
	uint16_t esn = NO_EXT_SEQ_NUMBERS;
	/* .FIXME: DO NOT HARDCODE THE BELOW */
	char config_name[128];
	bool ok = FALSE, failed = FALSE;
	uint32_t init_mid = 0, resp_mid = 0;

	/* Lets get this party started! */
	reply = charonRedisCommand(cinfo, db, "HGETALL %s", command);

	/**
	 * charonRedisCommand() can return NULL in cases where Redis is uncreachable.
	 */
	if (reply == NULL)
	{
		DBG1(DBG_CFG, "charon_process_ike_add: charonRedisCommand returned NULL while running HGETALL, failing");
		ret = -1;
		goto out;
	}

	/* Validate the reply */
	if (reply->type != REDIS_REPLY_ARRAY) {
		ret = -1;
		goto out;
	}

	DBG2(DBG_CFG, "charon_process_ike_add: Found %d array items for %s", reply->elements, command);

	if (reply->elements == 0) {
		/* Otherwise, we're done */
		ret = 0;
		goto out;
	}

	/* Get the IKE_ID first and create the IKE_SA */
	for (k=0; k < reply->elements; k+=2) {
		if (strncmp(reply->element[k]->str, JI_IKE_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			ike_sa_id_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(ike_sa_id_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_add: invalid size for JI_IKE_ID: %d",
						reply->element[k+1]->len);
				ret = -1;
				goto out;
			}

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_IKE_ID key %s", reply->element[k]->str);

			enc = (ike_sa_id_encoding_t *)reply->element[k+1]->str;
			ike_sa_id = ike_sa_id_create(enc->ike_version,
					enc->initiator_spi, enc->responder_spi,
					enc->initiator);
			ike_sa = ike_sa_create(ike_sa_id, ike_sa_id->is_initiator(ike_sa_id), version);
			break;
		}
	}

	/* If we can't find the IKE_SA, return an error */
	if (ike_sa == NULL)
	{
		DBG1(DBG_CFG, "charon_process_ike_add: Failed checking out IKE_SA, returning FALSE");
		ret = -1;
		goto out;
	}


	/* Dump the entire array */
	for (k=0; k < reply->elements; k+=2) {
		if (strncmp(reply->element[k]->str, JI_IKE_REKEY_ID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			ike_sa_id_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(ike_sa_id_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_add: invalid size for JI_IKE_REKEY_ID: %d",
						reply->element[k+1]->len);
				ret = -1;
				goto out;
			}

			enc = (ike_sa_id_encoding_t *)reply->element[k+1]->str;
			old_sa_id = ike_sa_id_create(enc->ike_version,
					enc->initiator_spi, enc->responder_spi,
					enc->initiator);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_IKE_REKEY_ID key for SPI %.16"PRIx64"_i %.16"PRIx64"_r",
				be64toh(old_sa_id->get_initiator_spi(old_sa_id)),
				be64toh(old_sa_id->get_responder_spi(old_sa_id)));

			old_sa = charon->ike_sa_manager->checkout(charon->ike_sa_manager, old_sa_id);
			if (old_sa == NULL)
			{
				DBG1(DBG_CFG, "charon_process_ike_add: Cannot checkout OLD IKE_SA for IKE_REKEY_ID with SPI %.16"PRIx64"_i %.16"PRIx64"_r",
					be64toh(old_sa_id->get_initiator_spi(old_sa_id)),
					be64toh(old_sa_id->get_responder_spi(old_sa_id)));
			}
			old_sa_id->destroy(old_sa_id);
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_ADDR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			host_encoding_t *enc;

			if (reply->element[k+1]->len < sizeof(host_encoding_t))
			{
				DBG1(DBG_CFG, "charon_process_ike_add: invalid size for JI_REMOTE_ADDR: %d",
						reply->element[k+1]->len);
				ret = -1;
				goto out;
			}

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_REMOTE_ADDR key %s", reply->element[k]->str);

			enc = (host_encoding_t *)reply->element[k+1]->str;
			other = host_create_from_chunk(enc->family,
					chunk_create((u_char *)enc->encoding, reply->element[k+1]->len - sizeof(host_encoding_t)),
					enc->port);
			if (!other)
			{
				DBG1(DBG_CFG, "charon_process_ike_add: Failed creating local host in JI_REMOTE_ADDR");
				ret = -1;
				goto out;
			}
		}
		else if (strncmp(reply->element[k]->str, JI_NONCE_I, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_NONCE_I key");

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			nonce_i = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_NONCE_R, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_NONCE_R key");

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			nonce_r = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_SECRET, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_SECRET key %s", reply->element[k]->str);

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			secret = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_OLD_SKD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_OLD_SKD key %s", reply->element[k]->str);

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			old_skd = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_PRF, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			prf = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALG_PRF key %s with value %d", reply->element[k]->str, prf);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_OLD_PRF, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			old_prf = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALG_OLD_PRF key %s with value %d",
					reply->element[k]->str, old_prf);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_ENCR, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			encr = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALGR_ENCR key %s with value %d",
					reply->element[k]->str, encr);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_ENCR_LEN, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			len = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALGR_ENCR_LEN key %s with value %d",
					reply->element[k]->str, len);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_INTEG, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			integ = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALG_INTEG key %s with value %d",
					reply->element[k]->str, integ);
		}
		else if (strncmp(reply->element[k]->str, JI_ALG_DH, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			dh_grp = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ALG_DH key %s with value %d",
					reply->element[k]->str, dh_grp);
		}
		else if (strncmp(reply->element[k]->str, JI_IKE_VERSION, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			version = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_IKE_VERSION key %s with value %d",
					reply->element[k]->str, version);
		}
		else if (strncmp(reply->element[k]->str, JI_LOCAL_DH, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_LOCAL_DH key %s", reply->element[k]->str);

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			local_dh = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_REMOTE_DH, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_REMOTE_DH key %s", reply->element[k]->str);

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			remote_dh = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_PSK, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			chunk_encoding_t *enc;

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_SK key %s", reply->element[k]->str);

			enc = (chunk_encoding_t *)reply->element[k+1]->str;
			psk = chunk_create((u_char *)enc->encoding, enc->len);
		}
		else if (strncmp(reply->element[k]->str, JI_AUTH_METHOD, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			method = atoi(reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_AUTH_METHOD key %s with value %d",
					reply->element[k]->str, method);
		}
		else if (strncmp(reply->element[k]->str, JI_CONFIG_NAME, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{

			snprintf(config_name, 128, "%s", reply->element[k+1]->str);

			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_CONFIG_NAME key %s with value %s",
					reply->element[k]->str, config_name);

			peer_cfg = charon->backends->get_peer_cfg_by_name(charon->backends, config_name);
			if (peer_cfg)
			{
				ike_sa->set_peer_cfg(ike_sa, peer_cfg);
				peer_cfg->destroy(peer_cfg);
			}
			else
			{
				DBG1(DBG_IKE, "charon_process_ike_add: Missing nodes peer configuration, checkin and delete IKE_SA");
				charon->ike_sa_manager->checkin_and_destroy( charon->ike_sa_manager, ike_sa);
				ike_sa = NULL;
				break;
			}
		}
		else if (strncmp(reply->element[k]->str, JI_INIT_MID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			init_mid = atoi(reply->element[k+1]->str);
			DBG2(DBG_CFG, "charon_process_ike_add: Found initiator message ID 0%08x", init_mid);
		}
		else if (strncmp(reply->element[k]->str, JI_RESP_MID, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			resp_mid = atoi(reply->element[k+1]->str);
			DBG2(DBG_CFG, "charon_process_ike_add: Found responder message ID 0%08x", resp_mid);
		}
		else if (strncmp(reply->element[k]->str, JI_ESN, JITIKE_MAX_REDIS_KEY_SIZE) == 0)
		{
			esn = atoi(reply->element[k+1]->str);
			DBG2(DBG_CFG, "charon_process_ike_add: Found JI_ESN %d", esn);
		}
		else
		{
			DBG2(DBG_CFG, "prodcess_ike_add: Found unneeded redis key: %s", reply->element[k]->str);
		}
	}

	if (ike_sa)
	{
		proposal_t *proposal;
		diffie_hellman_t *dh;

		/* Set the message IDs */
		if (init_mid != 0)
		{
			ike_sa->set_message_id(ike_sa, TRUE, init_mid);
		}
		if (resp_mid != 0)
		{
			ike_sa->set_message_id(ike_sa, FALSE, resp_mid);
		}

		proposal = proposal_create(PROTO_IKE, 0);
		if (integ)
		{
			proposal->add_algorithm(proposal, INTEGRITY_ALGORITHM, integ, 0);
		}
		if (encr)
		{
			proposal->add_algorithm(proposal, ENCRYPTION_ALGORITHM, encr, len);
		}
		if (prf)
		{
			proposal->add_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, prf, 0);
		}
		if (dh_grp)
		{
			proposal->add_algorithm(proposal, DIFFIE_HELLMAN_GROUP, dh_grp, 0);
		}
		charon->bus->set_sa(charon->bus, ike_sa);
		dh = create_redis_dh(secret, local_dh);
		if (ike_sa->get_version(ike_sa) == IKEV2)
		{
			keymat_v2_t *keymat_v2 = (keymat_v2_t*)ike_sa->get_keymat(ike_sa);

			ok = keymat_v2->derive_ike_keys(keymat_v2, proposal, dh, nonce_i,
					nonce_r, ike_sa->get_id(ike_sa), old_prf, old_skd);
		}
		if (ike_sa->get_version(ike_sa) == IKEV1)
		{
			keymat_v1_t *keymat_v1 = (keymat_v1_t*)ike_sa->get_keymat(ike_sa);
			shared_key_t *shared = NULL;

			if (psk.len)
			{
				method = AUTH_PSK;
				shared = shared_key_create(SHARED_IKE, chunk_clone(psk));
			}
			if (keymat_v1->create_hasher(keymat_v1, proposal))
			{
				ok = keymat_v1->derive_ike_keys(keymat_v1, proposal,
						dh, remote_dh, nonce_i, nonce_r,
						ike_sa->get_id(ike_sa), method, shared);
			}
			DESTROY_IF(shared);
		}
		if (ok)
		{
			if (old_sa)
			{
				ike_sa->inherit_pre(ike_sa, old_sa);
				ike_sa->inherit_post(ike_sa, old_sa);
				charon->ike_sa_manager->checkin_and_destroy(
						charon->ike_sa_manager, old_sa);
				old_sa = NULL;
			}
			if (other != NULL)
			{
				ike_sa->set_other_host(ike_sa, other);
				other = NULL;
			}
			ike_sa->set_initiator_exchange_type(ike_sa, EXCHANGE_TYPE_UNDEFINED);
			ike_sa->set_state(ike_sa, IKE_CONNECTING);
			ike_sa->set_proposal(ike_sa, proposal);
			charon->bus->ike_keys(charon->bus, ike_sa, dh, remote_dh, nonce_i, nonce_r, NULL, NULL, AUTH_NONE);
			charon->ike_sa_manager->checkin(charon->ike_sa_manager, ike_sa);
		}
		else
		{
			DBG1(DBG_IKE, "charon_process_ike_add: JITIKE keymat derivation failed");
			ike_sa->destroy(ike_sa);
		}
		dh->destroy(dh);
		charon->bus->set_sa(charon->bus, NULL);
		proposal->destroy(proposal);
	}
	else
	{
		/**
		 * For some reason we got here without an IKE_SA, we need to return an error.
		 */
		DBG1(DBG_CFG, "charon_process_ike_add: JITIKE IKE_SA to update not found");
		ret = -1;
		goto out;
	}

	if (old_sa)
	{
		charon->ike_sa_manager->checkin(charon->ike_sa_manager, old_sa);
	}
	if (other != NULL)
	{
		other->destroy(other);
	}

	/*
	 * Process the IKE SA up/down .
	 *
	 * NOTE: We pass in the reply structure from this function so that charon_process_ike_updown()
	 * does not have to query redis again to get it. It also walks the list of fields in the
	 * key and takes action based on those. Likely this could be optimized at some point.
	 */
	if (charon_process_ike_updown(reply) != 0) {
		DBG1(DBG_CFG, "charon_process_ike_add: Error processing ike up/down");
		ret = -1;
		goto out;
	}

	/**
	 * Add all CHILD_SAs from Redis
	 */
	if (charon_add_all_child_sa(cinfo, mutex, db, ike_sa_id, command) != 0)
	{
		DBG1(DBG_CFG, "charon_process_ike_add: Error adding CHILD_SAs to IKE_SA");
		ret = -1;
		goto out;
	}

out:
	if (reply)
	{
		freeReplyObject(reply);
	}

	return ret;
}
