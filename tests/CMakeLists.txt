
set(TEST_SRC
	main.cpp

	# ec
	ec/generate.cpp
	ec/pubkey.cpp
	ec/ecdsa_sign.cpp
	ec/ecdsa_recover.cpp
	ec/ecdsa_verify.cpp

	# Base58
	base58/encode.cpp
	base58/decode.cpp
	base58/is_base58.cpp

	# WIF
	WIF/priv_encode.cpp
	WIF/priv_decode.cpp
	WIF/pub_encode.cpp
	WIF/pub_decode.cpp
	WIF/sig_encode.cpp
	WIF/sig_decode.cpp)

add_executable(doctest ${TEST_SRC})
target_link_libraries(doctest PRIVATE ${LIB_NAME})
target_include_directories(doctest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

add_test(
	NAME doctest
	COMMAND $<TARGET_FILE:doctest> -ni -fc
)

if (WITH_BENCHMARK)
	add_subdirectory( benchmark )
endif (WITH_BENCHMARK)