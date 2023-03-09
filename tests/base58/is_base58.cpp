#include <libeosio/base58.hpp>
#include <iostream>
#include <array>

typedef std::pair<std::string, size_t> testpair_t;
typedef std::array<testpair_t, 6> tests;

int test_string() {
	tests input = {
		// Empty string is a valid base58 string.
		testpair_t("", std::string::npos),

		// Test Zero (0)
		testpair_t("2SdasxuGGdVU5VVyrXiko4jKASeS57E0P9uokzUphZt7tZxt24bzsEwvre", 31),

		// Test O
		testpair_t("2RTAsaYN2fpxVEDzaQht8ZnAUmwRpJz9C18VXrAWypxQSijRb9295kw13MA8krpRzK5cj2N5p84qQh3OGJrucW8hkLNy3aaEd2rTVhYkekhFiQoQ41JiNScD5KjmpDDxy", 79),

		// Test I
		testpair_t("5hWrCBA55zLmKpIhZd3RS1DHsJ7SnZpnyBfmibqGpDCJ7QCJGkogvhqPvGuwMgwNHzuZFyR", 14),

		// Test l
		testpair_t("lHxVA2fQKawLAK9MCJSr2xaWyDpoquQxVP6MMchdhzY49TjTfti8LDR6YL", 0),

		// All valid
		testpair_t("2BCoJ2BqNWorSoQcSWCQNanB8teoKFaqjojWGEXPBCPPdoGyVN8dgmKRdw", std::string::npos),
	};

	for(tests::const_iterator it = input.begin(); it != input.end(); it++) {

		size_t ret = libeosio::is_base58(it->first);

		if ( ret != it->second ) {
			std::cout << ret << " is not equalt to " << it->second << std::endl;
			return 1;
		}
	}
	return 0;
}

int test_char() {

	std::string valid_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::string invalid_alphabet = "0OIl";

	for(int i = 0; i < valid_alphabet.length(); i++) {
		char ch = valid_alphabet[i];

		if ( libeosio::is_base58(ch) == false ) {
			std::cout << ch << " should be a valid base58 character " << std::endl;
			return 1;
		}
	}

	for(int i = 0; i < invalid_alphabet.length(); i++) {
		char ch = invalid_alphabet[i];

		if ( libeosio::is_base58(ch) ) {
			std::cout << ch << " should be a invalid base58 character " << std::endl;
			return 1;
		}
	}
	return 0;
}

int main() {

	if (test_string() != 0) {
		return 1;
	}

	if (test_char() != 0) {
		return 1;
	}

	return 0;
}