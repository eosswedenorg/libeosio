/**
 * MIT License
 *
 * Copyright (c) 2019-2023 EOS Sw/eden
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
#include <openssl/hmac.h>

#ifndef LIBEOSIO_OPENSSL_INTERNAL_H
#define LIBEOSIO_OPENSSL_INTERNAL_H

#define EC_KEY_new_secp256k1() (EC_KEY_new_by_curve_name( NID_secp256k1 ))

#define EC_POINT_encode(group, point, buf, len, ctx) \
	EC_POINT_point2oct((group), (point), POINT_CONVERSION_COMPRESSED, (buf), (len), (ctx))

#ifdef __cplusplus
extern "C" {
#endif

int calculate_pubkey(const EC_GROUP *group, const EC_KEY *ec_key, EC_POINT **point);

int ECDSA_SIG_recover_key_GFp(EC_KEY *eckey, const BIGNUM* r, const BIGNUM* s, const unsigned char *msg, int msglen, int recid, int check);

/**
 * Signature serialization function.
 * sig must be a pointer to a serialized signature and be atleast 65 (32s + 32 + 1) bytes long.
 *
 * returns -1 if there was an error. zero otherwise.
 */
int ECDSA_SIG_serialize(const ECDSA_SIG *ecdsa_sig, int recid, unsigned char* sig);

/**
 * Signature unserialization functions.
 * sig must be a pointer to a serialized signature and be atleast 65 (32s + 32 + 1) bytes long.
 *
 * returns -1 if there was an error. zero otherwise.
 */
int ECDSA_SIG_unserialize(const unsigned char *sig, ECDSA_SIG *ecdsa_sig, int *recid);

int ECDSA_SIG_unserialize_rs(const unsigned char *sig, BIGNUM **r, BIGNUM **s, int *recid);

#ifdef __cplusplus
}
#endif

#endif /* LIBEOSIO_OPENSSL_INTERNAL_H */