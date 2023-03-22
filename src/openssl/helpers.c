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
#include <string.h>

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

int ECDSA_SIG_unserialize_rs(const unsigned char *sig, BIGNUM **r, BIGNUM **s, int *recid) {

	*recid = sig[0] - 27 - 4;

	if ((*r = BN_bin2bn(sig + 1, 32, NULL)) == NULL) {
		return 0;
	}

	if ((*s = BN_bin2bn(sig + 33, 32, NULL)) == NULL) {
		BN_free(*r);
		return 0;
	}
	return 1;
}

int ECDSA_SIG_unserialize(const unsigned char *sig, ECDSA_SIG *ecdsa_sig, int *recid) {

	BIGNUM *r, *s;

	if (ECDSA_SIG_unserialize_rs(sig, &r, &s, recid) == 0) {
		return 0;
	}

	if (ECDSA_SIG_set0(ecdsa_sig, r, s) == 0) {
		BN_free(r);
		BN_free(s);
		return 0;
	}

	// r,s pointers are owned by ECDSA_SIG from this point.
	// So we should not free them.
	return 1;
}

int ECDSA_SIG_serialize(const ECDSA_SIG *ecdsa_sig, int recid, unsigned char* sig) {

	unsigned char* der = NULL;
	int bytes, ret = -1;
	unsigned char lR, lS;

	bytes = i2d_ECDSA_SIG( ecdsa_sig, &der );
	lR = der[3];
	lS = der[5+lR];

	if (lR != 32 || lS != 32) goto err;

	memcpy(sig + 1, &der[4], 32);
	memcpy(sig + 33, &der[6+32], 32);
	sig[0] = recid + 27 + 4;

	ret = 0;
err:
	free(der);
	return ret;
}