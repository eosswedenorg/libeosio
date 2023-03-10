
set(TEST_SRC
	main.cpp

	# Base58
	base58/encode.cpp
	base58/decode.cpp
	base58/is_base58.cpp

	# WIF
	WIF/priv_encode.cpp
	WIF/priv_decode.cpp
	WIF/pub_encode.cpp
)

add_executable(doctest ${TEST_SRC})
target_link_libraries(doctest PRIVATE ${LIB_NAME})
target_include_directories(doctest PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)

add_test(
	NAME doctest
	COMMAND $<TARGET_FILE:doctest> -ni -fc
)