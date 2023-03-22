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
#include <openssl/ecdsa.h>
#include <libeosio/ec.hpp>
#include "internal.h"

namespace libeosio {

extern BN_CTX *ctx;

int ecdsa_sign(const ec_privkey_t& key, const sha256_t* digest, ec_signature_t& sig) {

	int rc = -1;
	EC_POINT *pub;
	const EC_GROUP *group;
	ECDSA_SIG *ecdsa_sig;
	EC_KEY *ec_key;

	if ((ec_key = EC_KEY_new_secp256k1()) == NULL) {
		return -1;
	}

	if (EC_KEY_oct2priv(ec_key, key.data(), key.size()) < 0) {
		goto err1;
	}

	group = EC_KEY_get0_group(ec_key);
	if (group == NULL) {
		goto err1;
	}

	if (calculate_pubkey(group, ec_key, &pub) == 0) {
		goto err2;
	}

	while (1) {
		int recid = -1;
		const BIGNUM *r, *s;
		EC_KEY* tmpk;

		ecdsa_sig = ECDSA_do_sign(digest->data, 32, ec_key);
		if (ecdsa_sig == NULL) {
			goto err2;
		}

		// Get R and S numbers.
		r = ECDSA_SIG_get0_r(ecdsa_sig);
		s = ECDSA_SIG_get0_s(ecdsa_sig);

		tmpk = EC_KEY_new_by_curve_name( NID_secp256k1 );
		for (int i = 0; i < 4; i++) {
			if (ECDSA_SIG_recover_key_GFp(tmpk, r, s, digest->data, sizeof(digest->data), i, 1) == 1) {
				const EC_POINT *p = EC_KEY_get0_public_key(tmpk);

				// Compare public keys
				if (EC_POINT_cmp(group, pub, p, ctx) == 0) {
					recid = i;
					break;
				}
			}
		}

		EC_KEY_free( tmpk );

		// Could not find recovery id.
		if (recid == -1) {
			goto err2;
		}

		if (ECDSA_SIG_serialize(ecdsa_sig, recid, sig.data()) == 0) {
			goto out;
		}
	}

out:	rc = 0;
err2:
	EC_POINT_free(pub);
err1:
	EC_KEY_free(ec_key);
	return rc;
}

int ecdsa_verify(const sha256_t* digest, const ec_signature_t& sig, const ec_pubkey_t& pub) {

	int recid, ret = -1;
	EC_POINT *point;
	const EC_GROUP *group;
	ECDSA_SIG* ecdsa_sig;
	EC_KEY *ec_key;

	ec_key = EC_KEY_new_by_curve_name( NID_secp256k1 );
	if (ec_key == NULL) {
		return -1;
	}

	if ((ecdsa_sig = ECDSA_SIG_new()) == NULL) {
		goto err1;
	}

	if (ECDSA_SIG_unserialize(sig.data(), ecdsa_sig, &recid) == 0) {
		goto err2;
	}

	if ((group = EC_KEY_get0_group(ec_key)) == NULL) {
		goto err2;
	}

	if ((point = EC_POINT_new(group)) == NULL) {
		goto err2;
	}

	if (EC_POINT_oct2point(group, point, pub.data(), EC_PUBKEY_SIZE, ctx) == 0) {
		goto err3;
	}

	if (EC_KEY_set_public_key(ec_key, point) == 0) {
		goto err3;
	}

	if (ECDSA_do_verify(digest->data, 32, ecdsa_sig, ec_key) == 1) {
		ret = 0;
	}

err3:	EC_POINT_free(point);
err2:	ECDSA_SIG_free(ecdsa_sig);
err1:	EC_KEY_free(ec_key);
	return ret;
}

int ecdsa_recover(const sha256_t* digest, const ec_signature_t& sig, ec_pubkey_t& key) {

	int recid;
	int ret = -1;
	BIGNUM *r, *s;
	EC_KEY *ec_key;

	// Initialize ec variables.
	if ((ec_key = EC_KEY_new_secp256k1()) == NULL) goto err1;

	// Unserialize signature into r,s,recid components.
	ECDSA_SIG_unserialize_rs(sig.data(), &r, &s, &recid);

	// Recover public key.
	if (ECDSA_SIG_recover_key_GFp(ec_key, r, s, digest->data, 32, recid, 1) == 1) {

		// Encode point to binary compressed format.
		const EC_POINT *p = EC_KEY_get0_public_key(ec_key);
		const EC_GROUP *g = EC_KEY_get0_group(ec_key);
		if (EC_POINT_encode(g, p, key.data(), EC_PUBKEY_SIZE, ctx) == 0) {
			goto err4;
		}

		ret = 0;
	}

err4:	BN_free(s);
err3:	BN_free(r);
err2:   EC_KEY_free(ec_key);
err1:	return ret;
}

} // namespace libeosio