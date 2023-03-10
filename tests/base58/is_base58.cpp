#include <libeosio/base58.hpp>
#include <iostream>
#include <vector>
#include <doctest.h>

TEST_CASE("base58::is_base58 [string]") {

	struct testcase{
		const char *name;
		std::string input;
		size_t expected;
	};

	std::vector<struct testcase> tests = {
		{"empty", "", std::string::npos},
		{"zero", "2SdasxuGGdVU5VVyrXiko4jKASeS57E0P9uokzUphZt7tZxt24bzsEwvre", 31},
		{"O", "2RTAsaYN2fpxVEDzaQht8ZnAUmwRpJz9C18VXrAWypxQSijRb9295kw13MA8krpRzK5cj2N5p84qQh3OGJrucW8hkLNy3aaEd2rTVhYkekhFiQoQ41JiNScD5KjmpDDxy", 79},
		{"I", "5hWrCBA55zLmKpIhZd3RS1DHsJ7SnZpnyBfmibqGpDCJ7QCJGkogvhqPvGuwMgwNHzuZFyR", 14},
		{"l", "lHxVA2fQKawLAK9MCJSr2xaWyDpoquQxVP6MMchdhzY49TjTfti8LDR6YL", 0},
		{"all_valid", "2BCoJ2BqNWorSoQcSWCQNanB8teoKFaqjojWGEXPBCPPdoGyVN8dgmKRdw", std::string::npos},
	};

	for(auto it = tests.begin(); it != tests.end(); it++) {

		SUBCASE(it->name) {
			CHECK(libeosio::is_base58(it->input) == it->expected);
		}

	}
}
TEST_CASE("base58::is_base58 [char]") {
	std::string valid_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	std::string invalid_alphabet = "0OIl";


	SUBCASE("valid") {

		for(int i = 0; i < valid_alphabet.length(); i++) {
			char ch = valid_alphabet[i];

			CHECK(libeosio::is_base58(ch));
		}
	}

	SUBCASE("invalid") {
		for(int i = 0; i < invalid_alphabet.length(); i++) {
			char ch = invalid_alphabet[i];

			CHECK_FALSE(libeosio::is_base58(ch));
		}
	}
}