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
#include <libeosio/types.hpp>

namespace libeosio {

/**
 * Encode an EC private key to WIF String.
 */
std::string wif_priv_encode(const ec_privkey_t& priv);

/**
 * Decode an WIF String to EC private key
 */
bool wif_priv_decode(ec_privkey_t& priv, const std::string& data);

/**
 * Encode an EC public key to WIF String.
 */
std::string wif_pub_encode(const ec_pubkey_t& pub, const std::string& prefix = "EOS");

/**
 * Decode an WIF String to EC public key
 */
bool wif_pub_decode(ec_pubkey_t& pub, const std::string& data, size_t prefix_length = 3);

/**
 * Prints an EC keypair in WIF format to standard out.
 */
void wif_print_key(const struct ec_keypair *key, const std::string& prefix = "EOS");

} // namespace libeosio

#endif /* LIBEOSIO_WIF_H */
