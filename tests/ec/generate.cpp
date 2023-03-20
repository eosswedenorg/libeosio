#include <libeosio/ec.hpp>
#include <doctest.h>

TEST_CASE("ec::generate") {

	libeosio::ec_init();

	libeosio::ec_pubkey_t result;
	libeosio::ec_keypair pair;
	CHECK(libeosio::ec_generate_key(&pair) == 0);

	// Can't test much because... well the private key should be random :)
	// But alteast verify that the public key belongs to the private key.
	CHECK(libeosio::ec_get_publickey(&pair.secret, &result) == 0);
	CHECK( result == pair.pub );

	libeosio::ec_shutdown();
}