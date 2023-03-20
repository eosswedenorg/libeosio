/**
 * MIT License
 *
 * Copyright (c) 2019-2021 EOS Sw/eden
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <libeosio/ec.hpp>
#include "rng.h"

namespace libeosio {

secp256k1_context* ctx;

int ec_init() {
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	return ctx == NULL ? -1 : 0;
}

void ec_shutdown() {
	if (ctx) {
		secp256k1_context_destroy(ctx);
		ctx = NULL;
	}
}

int ec_generate_privkey(ec_privkey_t *priv) {

	unsigned char randomize[32];

	if (!fill_random(randomize, sizeof(randomize))) {
		return -1;
	}

	if (secp256k1_context_randomize(ctx, randomize) < 0) {
		return -1;
	}

	while (1) {
		if (!fill_random(priv->data(), priv->size())) {
			return -1;
		}
		if (secp256k1_ec_seckey_verify(ctx, priv->data())) {
			break;
		}
	}

	return 0;
}

int ec_get_publickey(const ec_privkey_t *priv, ec_pubkey_t* pub) {

	size_t len;
	secp256k1_pubkey ec_pub;

	if (secp256k1_ec_pubkey_create(ctx, &ec_pub, priv->data()) < 0) {
		return -1;
	}

	len = EC_PUBKEY_SIZE;
	secp256k1_ec_pubkey_serialize(ctx, pub->data(), &len, &ec_pub, SECP256K1_EC_COMPRESSED);

	return len != EC_PUBKEY_SIZE ? -1 : 0;
}

int ec_generate_key(struct ec_keypair *pair) {

	if (ec_generate_privkey(&pair->secret) < 0) {
		return -1;
	}

	return ec_get_publickey(&pair->secret, &pair->pub);
}

} // namespace libeosio
