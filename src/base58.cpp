/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2009-2019 The Bitcoin Core developers
 * Copyright (c) 2009-2019 Bitcoin Developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Based on code from https://github.com/bitcoin/bitcoin/blob/f1e2f2a85962c1664e4e55471061af0eaa798d40/src/base58.cpp
 */
#include <algorithm>
#include <cstddef>
#include <cassert>
#include <cstring>
#include <libeosio/base58.hpp>

namespace libeosio {

static const char charmap[59] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t table[256] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
};

bool is_space(char c) {
	return c == ' ' || c == '\f' || c == '\n' || c == '\r' || c == '\t' || c == '\v';
}


std::string base58_encode(const unsigned char* pbegin, const unsigned char* pend) {

    // Skip & count leading zeroes.
    int zeroes = 0;
    int length = 0;
    while (pbegin != pend && *pbegin == 0) {
        pbegin++;
        zeroes++;
    }
    // Allocate enough space in big-endian base58 representation.
    std::size_t size = (pend - pbegin) * 138 / 100 + 1; // log(256) / log(58), rounded up.
    std::vector<unsigned char> b58(size);
    // Process the bytes.
    while (pbegin != pend) {
        int carry = *pbegin;
        int i = 0;
        // Apply "b58 = b58 * 256 + ch".
        for (std::vector<unsigned char>::reverse_iterator it = b58.rbegin(); (carry != 0 || i < length) && (it != b58.rend()); it++, i++) {
            carry += 256 * (*it);
            *it = static_cast<unsigned char>(carry % 58);
            carry /= 58;
        }

        assert(carry == 0);
        length = i;
        pbegin++;
    }
    // Skip leading zeroes in base58 result.
    std::vector<unsigned char>::iterator it = b58.begin() + (size - length);
    while (it != b58.end() && *it == 0)
        it++;
    // Translate the result into a string.
    std::string str;
    str.reserve(zeroes + (b58.end() - it));
    str.assign(zeroes, '1');
    while (it != b58.end())
        str += charmap[*(it++)];
    return str;
}

std::string base58_encode(const std::string& str) {

    const unsigned char *ptr = (const unsigned char *) str.c_str();
    return base58_encode(ptr, ptr + str.length());
}

std::string base58_encode(const std::vector<unsigned char>& vch) {

    return base58_encode(vch.data(), vch.data() + vch.size());
}

bool base58_decode(const char* psz, std::vector<unsigned char>& out) {
	// Skip leading spaces.
	while (*psz && is_space(*psz))
		psz++;
	// Skip and count leading '1's.
	int zeroes = 0;
	int length = 0;
	while (*psz == '1') {
		zeroes++;
		psz++;
	}
	// Allocate enough space in big-endian base256 representation.
	int size = strlen(psz) * 733 /1000 + 1; // log(58) / log(256), rounded up.
	std::vector<unsigned char> b256(size);
	// Process the characters.

	while (*psz && !is_space(*psz)) {
		// Decode base58 character
		int carry = table[(uint8_t)*psz];
		if (carry == -1)  // Invalid b58 character
			return false;
		int i = 0;
		for (std::vector<unsigned char>::reverse_iterator it = b256.rbegin(); (carry != 0 || i < length) && (it != b256.rend()); ++it, ++i) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		assert(carry == 0);
		length = i;
		psz++;
	}

	// Skip trailing spaces.
	while (is_space(*psz))
		psz++;

	if (*psz != 0)
		return false;

	// Skip leading zeroes in b256.
	std::vector<unsigned char>::iterator it = b256.begin() + (size - length);
	while (it != b256.end() && *it == 0)
		it++;

	// Copy result into output vector.
	out.reserve(zeroes + (b256.end() - it));
	out.assign(zeroes, 0);
	while (it != b256.end())
		out.push_back(*(it++));
	return true;
}

bool base58_decode(const std::string& str, std::vector<unsigned char>& out) {
	return base58_decode(str.c_str(), out);
}

bool is_base58(char ch) {
	for(unsigned int i=0; i < sizeof(charmap); i++) {
		if (ch == charmap[i]) {
			return true;
		}
	}
	return false;
}

size_t is_base58(const std::string& str) {

	auto p = std::find_if_not(str.begin(), str.end(), static_cast<bool (*)(char)>(is_base58));

	if (p == str.end()) {
		return std::string::npos;
	}
	return p - str.begin();
}

std::string& base58_strip(std::string &str) {
	str.erase(std::remove_if(str.begin(), str.end(), [] (std::string::value_type ch)
		{ return is_base58(ch) == false; }
	), str.end());
    return str;
}

} // namespace libeosio
