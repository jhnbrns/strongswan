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

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <test_suite.h>
#include <utils/chunk.h>

#include <threading/thread.h>

#include "../jitike_crypto.h"

START_TEST(test_get_encryption_key_path)
{
	char enc_key_path[PATH_MAX] = {};
	bool ret = get_encryption_key_path("keyid", enc_key_path);
	ck_assert(ret == true);
	ck_assert_str_eq(enc_key_path, "/dev/shm/redis_encryption_keys/keyid/public.pem");
}
END_TEST

START_TEST(test_get_encryption_key)
{
	ck_assert(get_encryption_key("/non-existent-path") == NULL);
	ck_assert(get_encryption_key("/etc/shadow") == NULL); /* File exists; no read permissions */

	RSA *rsa = RSA_generate_key(RSA_KEY_LEN, 3, NULL, NULL);
	FILE *pub_key_file = fopen("/tmp/public.pem", "wb");
	PEM_write_RSAPublicKey(pub_key_file, rsa);
	fclose(pub_key_file);

	ck_assert(get_encryption_key("/tmp/public.pem") != NULL);
	RSA_free(rsa);
}
END_TEST

START_TEST(test_base64_encode)
{
	char *encoded = NULL;
	unsigned char buffer[7] = "jitike";
	ck_assert(base64_encode(buffer, strlen(buffer), &encoded) == true);
	ck_assert(encoded != NULL);
	ck_assert(strcmp(encoded, "aml0aWtl") == 0);
	free(encoded);
}
END_TEST

START_TEST(test_encrypt_chunk)
{
	RSA *rsa = RSA_generate_key(RSA_KEY_LEN, 3, NULL, NULL);
	chunk_t chunk = chunk_from_str("jitike");
	char *encrypted = NULL;
	ck_assert(encrypt_chunk(chunk, rsa, &encrypted) == true);
	ck_assert(encrypted != NULL);
	free(encrypted);
	RSA_free(rsa);
}
END_TEST

Suite *jitike_crypto()
{
	Suite *s;
	TCase *tc;

	s = suite_create("jitike_crypto");

	tc = tcase_create("get_encryption_key_path");
	tcase_add_loop_test(tc, test_get_encryption_key_path, 0, 2);
	//suite_add_tcase(s, tc); FIXME: runtime error

	tc = tcase_create("get_encryption_key");
	tcase_add_loop_test(tc, test_get_encryption_key, 0, 2);
	//suite_add_tcase(s, tc); FIXME: runtime error

	tc = tcase_create("base64_encode");
	tcase_add_loop_test(tc, test_base64_encode, 0, 2);
	suite_add_tcase(s, tc);

	tc = tcase_create("encrypt_chunk");
	tcase_add_loop_test(tc, test_encrypt_chunk, 0, 2);
	suite_add_tcase(s, tc);

	return s;
}
