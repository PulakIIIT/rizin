// SPDX-FileCopyrightText: 2015-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_aes_algo.h"

static bool aes_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	rz_return_val_if_fail(cry->user && key, false);
	aes_state_t *st = (aes_state_t *)cry->user;

	if (!(keylen == 128 / 8 || keylen == 192 / 8 || keylen == 256 / 8)) {
		return false;
	}
	st->key_size = keylen;
	st->rounds = 6 + (int)(keylen / 4);
	st->columns = (int)(keylen / 4);
	memcpy(st->key, key, keylen);
	cry->dir = direction;
	return true;
}

static int aes_get_key_size(RzCrypto *cry) {
	rz_return_val_if_fail(cry->user, 0);
	aes_state_t *st = (aes_state_t *)cry->user;

	return st->key_size;
}

static bool aes_use(const char *algo) {
	return !strcmp(algo, "aes-ecb");
}

#define BLOCK_SIZE 16

static bool update(RzCrypto *cry, const ut8 *buf, int len) {
	rz_return_val_if_fail(cry->user, 0);
	aes_state_t *st = (aes_state_t *)cry->user;

	if (len < 1) {
		return false;
	}

	// Pad to the block size, do not append dummy block
	const int diff = (BLOCK_SIZE - (len % BLOCK_SIZE)) % BLOCK_SIZE;
	const int size = len + diff;
	const int blocks = size / BLOCK_SIZE;
	int i;

	ut8 *const obuf = calloc(1, size);
	if (!obuf) {
		return false;
	}
	ut8 *const ibuf = calloc(1, size);
	if (!ibuf) {
		free(obuf);
		return false;
	}

	memset(ibuf, 0, size);
	memcpy(ibuf, buf, len);
	// Padding should start like 100000...
	if (diff) {
		ibuf[len] = 8; //0b1000;
	}

	if (cry->dir == RZ_CRYPTO_DIR_ENCRYPT) {
		for (i = 0; i < blocks; i++) {
			const int delta = BLOCK_SIZE * i;
			aes_encrypt(st, ibuf + delta, obuf + delta);
		}
	} else {
		for (i = 0; i < blocks; i++) {
			const int delta = BLOCK_SIZE * i;
			aes_decrypt(st, ibuf + delta, obuf + delta);
		}
	}

	// printf("%128s\n", obuf);

	rz_crypto_append(cry, obuf, size);
	free(obuf);
	free(ibuf);
	return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool aes_ecb_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	cry->user = RZ_NEW0(aes_state_t);
	return cry->user != NULL;
}

static bool aes_ecb_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry, false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_aes = {
	.name = "aes-ecb",
	.set_key = aes_set_key,
	.get_key_size = aes_get_key_size,
	.use = aes_use,
	.update = update,
	.final = final,
	.init = aes_ecb_init,
	.fini = aes_ecb_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_aes,
	.version = RZ_VERSION
};
#endif
