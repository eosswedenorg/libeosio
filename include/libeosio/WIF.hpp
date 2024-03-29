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
#ifndef LIBEOSIO_WIF_H
#define LIBEOSIO_WIF_H

#include <string>
#include <libeosio/ec.hpp>

namespace libeosio {

/**
 * Key prefixes. (strings that is not equal to these prefixes are treated as legacy format.)
 */
extern const std::string WIF_PUB_LEG;
extern const std::string WIF_PUB_K1;
extern const std::string WIF_PVT_LEG;
extern const std::string WIF_PVT_K1;
extern const std::string WIF_SIG_K1;

/**
 * Codecs
 */

// A WIF Codec is an public and private key prefix pair.
typedef struct {
	std::string pub;
	std::string pvt;
} wif_codec_t;

extern const wif_codec_t WIF_CODEC_K1;
extern const wif_codec_t WIF_CODEC_LEG;

inline wif_codec_t wif_create_legacy_codec(const std::string& pub_prefix) {
	return { pub_prefix, WIF_PVT_LEG };
}

/**
 * Encode an EC private key to WIF String.
 */
std::string wif_priv_encode(const ec_privkey_t& priv, const std::string& prefix = WIF_PVT_K1);

/**
 * Decode an WIF String to EC private key
 */
bool wif_priv_decode(ec_privkey_t& priv, const std::string& data);

/**
 * Encode an EC public key to WIF String.
 */
std::string wif_pub_encode(const ec_pubkey_t& pub, const std::string& prefix = WIF_PUB_K1);

/**
 * Decode an WIF String to EC public key
 */
bool wif_pub_decode(ec_pubkey_t& pub, const std::string& data);

/**
 * Prints an EC keypair in WIF format to standard out.
 */
void wif_print_key(const struct ec_keypair *key, const wif_codec_t& codec = WIF_CODEC_K1);

/**
 * Signatures
 */

/**
 * Encode an EC signature to WIF String.
 */
std::string wif_sig_encode(const ec_signature_t& sig);

/**
 * Decode an WIF String to EC signature
 */
bool wif_sig_decode(ec_signature_t& sig, const std::string& data);

} // namespace libeosio

#endif /* LIBEOSIO_WIF_H */
