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
#include <secp256k1_recovery.h>
#include <libeosio/ec.hpp>
#include "rng.h"

namespace libeosio {

extern secp256k1_context* ctx;

int is_canonical(const unsigned char *d) {
	return !(d[1] & 0x80)
		&& !(d[1] == 0 && !(d[2] & 0x80))
		&& !(d[33] & 0x80)
		&& !(d[33] == 0 && !(d[34] & 0x80));
}

static int extended_nonce_function( unsigned char *nonce32, const unsigned char *msg32,
                                        const unsigned char *key32, const unsigned char* algo16,
                                        void* data, unsigned int attempt ) {
	return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, nullptr, *(unsigned int*) data);
}

int ecdsa_sign(const ec_privkey_t& key, const sha256_t* digest, ec_signature_t& sig) {

	for (unsigned int counter = 1; counter < 25; counter++) {

		int v = 0;
		secp256k1_ecdsa_recoverable_signature s;

		if (!secp256k1_ecdsa_sign_recoverable(ctx, &s, digest->data, key.data(), extended_nonce_function, &counter)) {
			return -1;
		}

		secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig.data() + 1, &v, &s);

		if (is_canonical(sig.data())) {
			sig[0] = 27 + 4 + v;
			return 0;
		}
	}

	return -1;
}

int ecdsa_verify(const sha256_t* digest, const ec_signature_t& sig, const ec_pubkey_t& key) {

	secp256k1_ecdsa_signature ec_sig;
	secp256k1_ecdsa_recoverable_signature ec_rec_sig;
	secp256k1_pubkey pubkey;
	int recid;

	recid = sig.at(0) - 27 - 4;

	// Parse signature
	if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &ec_rec_sig, sig.data() + 1, recid)) {
		return -1;
	}

	// Parse public key
	if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, key.data(), key.size())) {
		return -1;
	}

	// Verify
	secp256k1_ecdsa_recoverable_signature_convert(ctx, &ec_sig, &ec_rec_sig);
	return secp256k1_ecdsa_verify(ctx, &ec_sig, digest->data, &pubkey) > 0 ? 0 : -1;
}


} // namespace libeosio
