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
#include <vector>
#include "codec.hpp"

namespace libeosio { namespace internal {

// Just to make it "harder" the calculated checksum for a signature (k1) and pub/priv keys in k1/r1 format.
// has a suffix that is not present in the WIF encoded string.
// So this function is a quick hack to calculate it.
//
// Should implement and use Init/Update/Finalize hash functions to do it inplace.
void _checksum_suffix(const unsigned char *in, size_t size, const char *suffix, checksum_t check) {
	std::vector<unsigned char> buf(size + 2);

	memcpy(buf.data(), in, size);
	memcpy(buf.data() + size, suffix, 2);

	return checksum_ripemd160(buf.data(), buf.size(), (unsigned char*) check);
}

void pub_encoder_k1(const ec_pubkey_t& key, unsigned char *buf) {

	checksum_t check;

	_checksum_suffix(key.data(), EC_PUBKEY_SIZE, "K1", check);

	memcpy(buf, key.data(), EC_PUBKEY_SIZE);
	memcpy(buf + EC_PUBKEY_SIZE, check, CHECKSUM_SIZE);
}

bool pub_decoder_k1(const std::vector<unsigned char>& buf, ec_pubkey_t& key) {

	checksum_t check;

	_checksum_suffix(buf.data(), EC_PUBKEY_SIZE, "K1", check);

	if (memcmp(buf.data() + EC_PUBKEY_SIZE, check, CHECKSUM_SIZE)) {
		return false;
	}

	memcpy(key.data(), buf.data(), EC_PUBKEY_SIZE);
	return true;
}

size_t priv_encoder_k1(const ec_privkey_t& priv, unsigned char *buf) {
	checksum_t check;

	_checksum_suffix(priv.data(), EC_PRIVKEY_SIZE, "K1", check);

	memcpy(buf, priv.data(), priv.size());
	memcpy(buf + EC_PRIVKEY_SIZE, check, CHECKSUM_SIZE);

	return EC_PRIVKEY_SIZE + CHECKSUM_SIZE;
}

bool priv_decoder_k1(const std::vector<unsigned char>& buf, ec_privkey_t& priv) {

	if (buf.size() != EC_PRIVKEY_SIZE + CHECKSUM_SIZE) {
		return false;
	}

	checksum_t check;
	_checksum_suffix(buf.data(), EC_PRIVKEY_SIZE, "K1", check);
	if (memcmp(buf.data() + EC_PRIVKEY_SIZE, check, CHECKSUM_SIZE)) {
		return false;
	}

	memcpy(priv.data(), buf.data(), priv.size());
	return true;
}

void sig_encoder_k1(const ec_signature_t& sig, unsigned char *buf) {

	checksum_t check;

	_checksum_suffix(sig.data(), EC_SIGNATURE_SIZE, "K1", check);

	memcpy(buf, sig.data(), sig.size());
	memcpy(buf + EC_SIGNATURE_SIZE, check, CHECKSUM_SIZE);
}

bool sig_decoder_k1(const std::vector<unsigned char>& buf, ec_signature_t& sig) {

	checksum_t check;

	if (buf.size() != EC_SIGNATURE_SIZE + CHECKSUM_SIZE) {
		return false;
	}

	// Calculate checksum
	_checksum_suffix(buf.data(), EC_SIGNATURE_SIZE, "K1", check);

	// And validate
	if (memcmp(buf.data() + EC_SIGNATURE_SIZE, check, CHECKSUM_SIZE)) {
		return false;
	}

	// Copy data to output
	memcpy(sig.data(), buf.data(), sig.size());
	return true;
}


}} // namespace libeosio::internal