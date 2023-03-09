#include <libeosio/base58.hpp>
#include <iostream>
#include <array>
#include <doctest.h>

typedef std::pair<std::string, std::string> testpair_t;
typedef std::array<testpair_t, 3> tests;

TEST_CASE("base58::base58_encode") {

	tests input = {
		testpair_t("",""),
		testpair_t(
			"Quisque ut ipsum lorem. Nullam ac justo elit. Sed gravida convallis mattis.",
			"2nPTv2DT874jRaYBN4uhM9mT2iRiwdJuCXuX5buUHyyvWUSu6cX62i8HYo8PsWqgs9DHbwhpSpV5SVUnCqyLcpxcuGanH68eXgzZTGq"
		),
		testpair_t(
			"Cras fringilla, eros et imperdiet tincidunt",
			"5yAgp6rBagDHQZ3GacZSeaEPF2jfuwVHM21aNfXETJgn3EkArxc5UWSq1RM"
		),
	};

	for(tests::const_iterator it = input.begin(); it != input.end(); it++) {
		CHECK( libeosio::base58_encode(it->first) == it->second );
	}
}