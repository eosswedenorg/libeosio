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