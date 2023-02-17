
add_executable(base58_encode_test base58_encode.cpp)
target_link_libraries(base58_encode_test PRIVATE ${LIB_NAME})

add_executable(is_base58_test is_base58.cpp)
target_link_libraries(is_base58_test PRIVATE ${LIB_NAME})

# define tests
add_test(
  NAME base58_encode_test
  COMMAND $<TARGET_FILE:base58_encode_test>
)

add_test(
  NAME is_base58_test
  COMMAND $<TARGET_FILE:is_base58_test>
)