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

#include <libeosio/checksum.hpp>
#include "codec.hpp"

namespace libeosio { namespace internal {

void pub_encoder_legacy(const ec_pubkey_t& key, unsigned char *buf) {

	checksum_t check = checksum_ripemd160(key.data(), EC_PUBKEY_SIZE);

	memcpy(buf, key.data(), EC_PUBKEY_SIZE);
	memcpy(buf + EC_PUBKEY_SIZE, check.data(), check.size());
}

bool pub_decoder_legacy(const std::vector<unsigned char>& buf, ec_pubkey_t& key) {

	if (!checksum_validate<checksum_ripemd160>(buf.data(), buf.size())) {
		return false;
	}

	memcpy(key.data(), buf.data(), EC_PUBKEY_SIZE);
	return true;
}

}} // namespace libeosio::internal