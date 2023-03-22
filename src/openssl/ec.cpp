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
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/hmac.h>
#include <libeosio/ec.hpp>

namespace libeosio {

#define EC_POINT_encode(group, point, buf, len, ctx) \
	EC_POINT_point2oct((group), (point), POINT_CONVERSION_COMPRESSED, (buf), (len), (ctx))

BN_CTX *ctx = NULL;
EC_KEY *k = NULL;

int ec_init() {

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		return -1;
	}

	// Construct curve.
	k = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (k == NULL) {
		BN_CTX_free(ctx);
		return -1;
	}

	return 0;
}

void ec_shutdown() {
	if (ctx) {
		BN_CTX_free(ctx);
		ctx = NULL;
	}

	if (k) {
		EC_KEY_free(k);
		k = NULL;
	}
}

int ec_generate_privkey(ec_privkey_t *priv) {

	// Generate new private key.
	if (EC_KEY_generate_key(k) == 0)  {
		return -1;
	}

	if (EC_KEY_priv2oct(k, priv->data(), EC_PRIVKEY_SIZE) == 0) {
		return -1;
	}

	return 0;
}

// Calcualte a public key from a EC_KEY object.
int calculate_pubkey(const EC_GROUP *group, const EC_KEY *ec_key, EC_POINT **point) {
	const BIGNUM* pk;

	// Then get the private key number
	if ((pk = EC_KEY_get0_private_key(ec_key)) == NULL) {
		return 0;
	}

	// Create a new point.
	if ((*point = EC_POINT_new(group)) == NULL) {
		return 0;
	}

	// Multiply curve (group) and private key to get the public key.
	return EC_POINT_mul(group, *point, pk, NULL, NULL, NULL);
}

int ec_get_publickey(const ec_privkey_t *priv, ec_pubkey_t* pub) {

	int rc = -1;
	const EC_GROUP *group;
	EC_POINT *point;

	// Load private key
	if (EC_KEY_oct2priv(k, priv->data(), EC_PRIVKEY_SIZE) == 0) {
		return -1;
	}

	if ((group = EC_KEY_get0_group(k)) == NULL) {
		return -1;
	}

	if (calculate_pubkey(group, k, &point) == 0) {
		return -1;
	}

	// Encode public key
	if (EC_POINT_encode(group, point, pub->data(), EC_PUBKEY_SIZE, ctx) != 0) {
		rc = 0;
	}

	EC_POINT_free(point);
	return rc;
}

int ec_generate_key(struct ec_keypair *pair) {

	// Generate new key pair.
	if (EC_KEY_generate_key(k) != 1)  {
		return -1;
	}

	// Copy private key to binary format.
	EC_KEY_priv2oct(k, pair->secret.data(), EC_PRIVKEY_SIZE);

	// Copy public key
	EC_POINT_point2oct(EC_KEY_get0_group(k),
		EC_KEY_get0_public_key(k), POINT_CONVERSION_COMPRESSED,
	   	pair->pub.data(), EC_PUBKEY_SIZE, ctx);

	return 0;
}

} // namespace libeosio
