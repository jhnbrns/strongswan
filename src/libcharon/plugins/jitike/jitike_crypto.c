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
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <utils/chunk.h>

#include <daemon.h>
#include <library.h>
#include <utils/debug.h>

#include "jitike_crypto.h"

bool get_encryption_key_path(const char *keyid_hash, char *enc_key_path)
{
	char *enc_key_dir = lib->settings->get_str(lib->settings,
		"%s.plugins.jitike.redis.enc_key_dir",
		DEFAULT_REDIS_ENC_KEY_DIR,
		lib->ns);
	/* Use PATH_MAX to avoid truncation, as enc_key_dir can be specified by the user */
	size_t path_len = 0;
	path_len = snprintf(enc_key_path, PATH_MAX, "%s/%s/public.pem", enc_key_dir, keyid_hash);
	if (path_len >= PATH_MAX)
	{
		DBG1(DBG_CFG, "get_encryption_key_path: Encryption key path potentially truncated");
	}
	else if (path_len == -1)
	{
		DBG1(DBG_CFG, "get_encryption_key_path: Error getting encryption key path: %s", strerror(errno));
		return false;
	}

	DBG2(DBG_CFG, "get_encryption_key_path: Encryption key path: %s", enc_key_path);
	return true;
}

RSA *get_encryption_key(const char *enc_key_path)
{
	if (access(enc_key_path, R_OK) == -1) goto error_out;

	FILE *fp = fopen(enc_key_path, "r");
	if (fp == NULL) goto error_out;

	RSA *pubkey = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	if (pubkey) return pubkey;

error_out:
	DBG1(DBG_CFG, "get_encryption_key: Error reading encryption key: %s", strerror(errno));
	return NULL;
}

bool base64_encode(const unsigned char *buffer, size_t buffer_length, char **encoded)
{
	bool ret = false;

	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new(BIO_s_mem());
	if (b64 == NULL || bio == NULL) return false;

	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	if(BIO_write(bio, buffer, buffer_length) <= 0) goto error_out;
	if(BIO_flush(bio) <= 0) goto error_out;

	BUF_MEM *buf_mem;
	BIO_get_mem_ptr(bio, &buf_mem);

	/* make a copy of buf_mem to encoded, so we can free up buf_mem */
	*encoded = strndup(buf_mem->data, buf_mem->length);

	ret = true;
	goto out;

error_out:
	DBG1(DBG_CFG, "base64_encode: error converting to base64");

out:
	BIO_free_all(bio);
	return ret;
}

bool encrypt_chunk(struct chunk_t chunk, RSA *enc_key, char **encrypted)
{
	if (chunk.len > (RSA_size(enc_key) - RSA_PKCS1_OAEP_PADDING_OVERHEAD))
	{
		/* reference: https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html */
		DBG1(DBG_CFG, "encrypt_chunk: Error input data is too long: %d bytes", chunk.len);
		return false;
	}

	/* no envelope necessary, as ESP keys are smaller than RSA_KEY_LEN; RSA_ciphertext is not null-terminated */
	unsigned char RSA_ciphertext[RSA_KEY_LEN/8] = {};
	size_t RSA_ciphertext_len = RSA_public_encrypt(chunk.len, chunk.ptr, RSA_ciphertext, enc_key, RSA_PKCS1_OAEP_PADDING);
	if (RSA_ciphertext_len == -1)
	{
		char *err = malloc(128);
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		DBG1(DBG_CFG, "encrypt_chunk: Encryption error: %s", err);
		free(err);
		return false;
	}

	/* "encrypted" buffer is a base64-encoded RSA ciphertext */
	return base64_encode(RSA_ciphertext, RSA_ciphertext_len, encrypted);
}
