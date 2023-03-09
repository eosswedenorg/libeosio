
function(test name)
	add_executable(${name}_test ${name}.cpp)
	target_link_libraries(${name}_test PRIVATE ${LIB_NAME})

	# define tests
	add_test(
		NAME ${name}_test
		COMMAND $<TARGET_FILE:${name}_test>
	)
endfunction()

add_subdirectory( base58 )
