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

#include <openssl/rsa.h>
#include <stdbool.h>
#include <utils/chunk.h>

/** The default directory for encryption keys */
#define DEFAULT_REDIS_ENC_KEY_DIR	   "/dev/shm/redis_encryption_keys"

/** Default RSA key length */
#define RSA_KEY_LEN 4096

/**
 *  Input data should not exceed key size - overhead
 *  Reference: https://www.openssl.org/docs/manmaster/man3/RSA_public_encrypt.html
 */
#define RSA_PKCS1_OAEP_PADDING_OVERHEAD 42

/**
 * Determines the filesystem path where a given key should be saved
 *
 * @param keyid_hash	Name of the redis key
 * @param enc_key_path	Destination buffer where the path to the encryption key will be returned
 */
bool get_encryption_key_path(const char *keyid_hash, char *enc_key_path);

/**
 * Reads an encryption key from enc_key_path
 *
 * @param enc_key_path  Path from which the encryption key should be read
 */
RSA *get_encryption_key(const char *enc_key_path);

/**
 * Encodes a base64 string
 * @param buffer	Input buffer
 * @param buffer_length	Buffer length
 * @param encoded	Returned encoded string
 */
bool base64_encode(const unsigned char *buffer, size_t buffer_length, char **encoded);

/**
 * Encrypts a chunk using a public key associated with a <keyid>
 *
 * @param chunk	Chunk of data to be encrypted
 * @param enc_key	Encryption key
 * @param encrypted	Buffer where base64-encoded cyphertext is returned
 */
bool encrypt_chunk(struct chunk_t chunk, RSA *enc_key, char **encrypted);
