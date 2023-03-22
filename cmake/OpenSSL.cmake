
# On Windows if OPENSSL_ROOT_DIR is not explicitly set
# we use a local static version.
if (WIN32 AND NOT OPENSSL_ROOT_DIR)
	set( VENDOR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor)
	set( OPENSSL_ZIP_FILE ${VENDOR_DIR}/openssl-1.1.1e-win-static.zip )
	set( OPENSSL_ROOT_DIR ${VENDOR_DIR}/openssl-1.1.1e )
	# Force static.
	set( OPENSSL_USE_STATIC_LIBS TRUE )

	if (NOT EXISTS ${OPENSSL_ROOT_DIR})
		message( "Unpacking ${OPENSSL_ZIP_FILE} to ${OPENSSL_ROOT_DIR}" )
		execute_process( COMMAND ${CMAKE_COMMAND} -E make_directory ${OPENSSL_ROOT_DIR} )
		execute_process(
			COMMAND ${CMAKE_COMMAND} -E tar -xf ${OPENSSL_ZIP_FILE}
			WORKING_DIRECTORY ${OPENSSL_ROOT_DIR}
		)
	endif()
endif()

# OpenSSL
find_package(OpenSSL 1.1 REQUIRED)

# Bug in FindOpenSSL. Win needs to link to these if static libs are used.
if (WIN32 AND OPENSSL_USE_STATIC_LIBS)
	set (OPENSSL_CRYPTO_LIBRARY "${OPENSSL_CRYPTO_LIBRARY};Crypt32;ws2_32")
	target_link_libraries(OpenSSL::Crypto INTERFACE "Crypt32;ws2_32")
endif()
