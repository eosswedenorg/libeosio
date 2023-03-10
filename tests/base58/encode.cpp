#include <libeosio/base58.hpp>
#include <iostream>
#include <vector>
#include <doctest.h>

TEST_CASE("base58::base58_encode") {

	struct testcase {
		const char* name;
		std::string in;
		std::string expected;
	};

	std::vector<struct testcase> tests = {
		{"empty","",""},
		{
			"first",
			"Quisque ut ipsum lorem. Nullam ac justo elit. Sed gravida convallis mattis.",
			"2nPTv2DT874jRaYBN4uhM9mT2iRiwdJuCXuX5buUHyyvWUSu6cX62i8HYo8PsWqgs9DHbwhpSpV5SVUnCqyLcpxcuGanH68eXgzZTGq"
		},
		{
			"second",
			"Cras fringilla, eros et imperdiet tincidunt",
			"5yAgp6rBagDHQZ3GacZSeaEPF2jfuwVHM21aNfXETJgn3EkArxc5UWSq1RM"
		},
	};

	for(auto it = tests.begin(); it != tests.end(); it++) {

		SUBCASE(it->name) {
			CHECK( libeosio::base58_encode(it->in) == it->expected );
		}
	}
}