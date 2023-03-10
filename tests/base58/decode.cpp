#include <libeosio/base58.hpp>
#include <iostream>
#include <vector>
#include <doctest.h>

TEST_CASE("base58_decode") {
	struct testcase {
		const char* name;
		std::string in;
		std::string expectedOut;
		bool expectedReturn;
	};

	std::vector<testcase> tests = {
		{"empty", "","", true},
		{"invalid","OI","",false},
		{
			"valid #1",
			"2nPTv2DT874jRaYBN4uhM9mT2iRiwdJuCXuX5buUHyyvWUSu6cX62i8HYo8PsWqgs9DHbwhpSpV5SVUnCqyLcpxcuGanH68eXgzZTGq",
			"Quisque ut ipsum lorem. Nullam ac justo elit. Sed gravida convallis mattis.",
			true
		},
		{
			"valid #2",
			"5yAgp6rBagDHQZ3GacZSeaEPF2jfuwVHM21aNfXETJgn3EkArxc5UWSq1RM",
			"Cras fringilla, eros et imperdiet tincidunt",
			true
		},
		{
			"valid #3",
			"9P7SxYWTWMq5hHkri53b1CGvWKRXxq3uXWPs5RiVtYagFrsnTXDxvKnk1twkPmV7BuxcRhBHWSwFLXpXbmdfHwZrnDaTB3wrBhsjm2Dd7F95ixh5vQLxajmT8hd22yUbvXuAZci8vTgFWMUyQi5YzWwntQiK5KFDkx3oA7kxvdU5t1yJZur84a9aKTCihEWtvCJ6LoBCpxvyB16YaCKeBQWLbUqoaXvFoDM78BpKD8biYyWQhnzHonjdwAS4KNXs5ByBdBvvPK1Q2Knr8zuFZxKHEFmgZGFTt8SMSsTDjkanUjojbfpJt5gcrHh6UFrt45n7kT9sj9Xsf1UyXZG3E2H85jXSbVnKowz2VPq1TkLLUKG8CSfdH3fVRp2E3yL5cpbbFWngbMzsbBZDgr4kPPcazebvSZ8qm8taBcBmt1ry25ey9TfFbMzP4FR1q9yjvkqGusMtrrBFm8YEeRmoMugMQoXvUgpExh29j",
			"Praesent massa nibh, feugiat ac aliquet sed, varius quis metus. Fusce auctor imperdiet purus. Vivamus elementum risus vel imperdiet condimentum. Nunc iaculis, sem eu sollicitudin tempus, nibh felis scelerisque orci, a tincidunt felis lectus in nulla. Vestibulum egestas eu elit id luctus. Vivamus eget ipsum neque. Fusce eleifend mauris a tempus vehicula.",
			true
		},
	};

	for(auto it = tests.begin(); it != tests.end(); it++) {

		SUBCASE(it->name) {
			std::vector<unsigned char> result;

			std::vector<unsigned char> expectedOut(it->expectedOut.begin(), it->expectedOut.end());

			CHECK( libeosio::base58_decode(it->in, result) == it->expectedReturn );
			CHECK( result == expectedOut );
		}
	}
}