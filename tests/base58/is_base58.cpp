#include <libeosio/base58.hpp>
#include <iostream>
#include <array>
#include <doctest.h>

typedef std::pair<std::string, size_t> testpair_t;
typedef std::array<testpair_t, 6> tests;

TEST_CASE("base58::is_base58 [string]") {
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

		CHECK(ret == it->second);
	}
}
TEST_CASE("base58::is_base58 [char]") {
	std::string valid_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::string invalid_alphabet = "0OIl";

	for(int i = 0; i < valid_alphabet.length(); i++) {
		char ch = valid_alphabet[i];

		CHECK(libeosio::is_base58(ch) == true);
	}

	for(int i = 0; i < invalid_alphabet.length(); i++) {
		char ch = invalid_alphabet[i];

		CHECK(libeosio::is_base58(ch) == false);
	}
}