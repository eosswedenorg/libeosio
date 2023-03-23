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
#include <iostream>
#include <cstring>
#include <libeosio/base58.hpp>
#include <libeosio/checksum.hpp>
#include <libeosio/WIF.hpp>

namespace libeosio {

#define PRIV_KEY_PREFIX 0x80 /* 0x80 for "Bitcoin mainnet". Always used by EOS. */

// Just to make it "harder" the calculated checksum for a signature (k1) and pub/priv keys in k1/r1 format.
// has a suffix that is not present in the WIF encoded string.
// So this function is a quick hack to calculate it.
//
// Should implement and use Init/Update/Finalize hash functions to do it inplace.
checksum_t _checksum_suffix(const unsigned char *in, size_t size, const char *suffix) {
	unsigned char buf[size + 2];

	memcpy(buf, in, size);
	memcpy(buf + size, suffix, 2);

	return checksum_ripemd160(buf, size + 2);
}

std::string wif_priv_encode(const ec_privkey_t& priv) {

	checksum_t check;
	// 1 byte extra for prefix.
	unsigned char buf[1 + EC_PRIVKEY_SIZE + CHECKSUM_SIZE] = { PRIV_KEY_PREFIX };

	memcpy(buf + 1, priv.data(), priv.size());

	// Checksum
	check = checksum_sha256d(buf, 1 + EC_PRIVKEY_SIZE);
	memcpy(buf + 1 + EC_PRIVKEY_SIZE, check.data(), check.size());

	return base58_encode(buf, buf + sizeof(buf));
}

bool wif_priv_decode(ec_privkey_t& priv, const std::string& data) {

	std::vector<unsigned char> buf;

	if (!base58_decode(data, buf)) {
		return false;
	}

	if (buf.size() != 1 + EC_PRIVKEY_SIZE + CHECKSUM_SIZE) {
		return false;
	}

	// First byte is the prefix
	if (buf[0] != PRIV_KEY_PREFIX) {
		return false;
	}

	// Calculate and validate checksum
	if (!checksum_validate<checksum_sha256d>(buf.data(), buf.size())) {
		return false;
	}

	// Copy data to output
	memcpy(priv.data(), buf.data() + 1, priv.size());
	return true;
}

std::string wif_pub_encode(const ec_pubkey_t& pub, const std::string& prefix) {

	checksum_t check;
	unsigned char buf[EC_PUBKEY_SIZE + CHECKSUM_SIZE];

	memcpy(buf, pub.data(), pub.size());


	if (prefix == WIF_PUB_K1) {
		check = _checksum_suffix(buf, EC_PUBKEY_SIZE, "K1");
	}
	// Legacy
	else {
		check = checksum_ripemd160(pub.data(), pub.size());
	}

	memcpy(buf + EC_PUBKEY_SIZE, check.data(), check.size());

	return prefix + base58_encode(buf, buf + sizeof(buf));
}

bool wif_pub_decode(ec_pubkey_t& pub, const std::string& data) {

	const char *suffix;
	int offset;
	std::vector<unsigned char> buf;

	// Check prefix
	if (data.substr(0, WIF_PUB_K1.size()) == WIF_PUB_K1) {
		suffix = "K1";
		offset = WIF_PUB_K1.size();
	} else {
		// Legacy
		suffix = "";
		offset = 3;
	}

	if (!base58_decode(data.c_str() + offset, buf)) {
		return false;
	}

	if (buf.size() != EC_PUBKEY_SIZE + CHECKSUM_SIZE) {
		return false;
	}

	if (suffix[0] != '\0') {
		checksum_t check = _checksum_suffix(buf.data(), EC_PUBKEY_SIZE, suffix);
		if (memcmp(buf.data() + EC_PUBKEY_SIZE, check.data(), CHECKSUM_SIZE)) {
			return false;
		}
	} else if (!checksum_validate<checksum_ripemd160>(buf.data(), buf.size())) {
		return false;
	}

	// Copy data to output
	memcpy(pub.data(), buf.data(), pub.size());
	return true;
}

void wif_print_key(const struct ec_keypair *key, const std::string& prefix) {

	std::cout << "Public: " << wif_pub_encode(key->pub, prefix) << std::endl;
	std::cout << "Private: " << wif_priv_encode(key->secret) << std::endl;
}

bool wif_sig_decode(ec_signature_t& sig, const std::string& data) {

	checksum_t checksum;
	std::vector<unsigned char> buf;

	if (data.substr(0, 7) != "SIG_K1_") {
		// Invalid prefix
		return false;
	}

	if (!base58_decode(data.c_str() + 7, buf)) {
		return false;
	}

	if (buf.size() != EC_SIGNATURE_SIZE + CHECKSUM_SIZE) {
		return false;
	}

	// Calculate checksum
	checksum = _checksum_suffix(buf.data(), EC_SIGNATURE_SIZE, "K1");

	// And validate
	if (memcmp(buf.data() + EC_SIGNATURE_SIZE, checksum.data(), CHECKSUM_SIZE)) {
		return false;
	}

	// Copy data to output
	memcpy(sig.data(), buf.data(), sig.size());
	return true;
}

std::string wif_sig_encode(const ec_signature_t& sig) {

	unsigned char buf[EC_SIGNATURE_SIZE + CHECKSUM_SIZE];
	checksum_t check = _checksum_suffix(sig.data(), EC_SIGNATURE_SIZE, "K1");

	memcpy(buf, sig.data(), sig.size());
	memcpy(buf + EC_SIGNATURE_SIZE, check.data(), check.size());

	return "SIG_K1_" + base58_encode(buf, buf + sizeof(buf));
}

} // namespace libeosio
