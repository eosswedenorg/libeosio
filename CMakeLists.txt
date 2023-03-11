cmake_minimum_required(VERSION 3.15)

# --------------------------------
#  Info
# --------------------------------

# Project name and version
project(libeosio
	VERSION 0.1.5
	DESCRIPTION "C++ library for EOSIO"
	HOMEPAGE_URL "https://github.com/eosswedenorg/libeosio"
	LANGUAGES CXX
)

set( PROJECT_MAINTAINER "Henrik Hautakoski <henrik@eossweden.org>")

# --------------------------------
#  Includes
# --------------------------------

set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_LIST_DIR}/cmake" )

# --------------------------------
#  Compiler
# --------------------------------

set( CMAKE_CXX_STANDARD 11 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_CXX_EXTENSIONS OFF )

# OpenSSL 3.0 deprecates some functions we use.
# Adding this flag makes the compiler not spam warnings.
add_compile_options(-D OPENSSL_API_COMPAT=0x10100000L)

# --------------------------------
#  Library
# --------------------------------

set( LIB_NAME ${PROJECT_NAME} )

set( LIB_SOURCE
	src/base58.cpp
	src/ec.cpp
	src/WIF.cpp
)

# OpenSSL
include(OpenSSL)
set (LIB_SOURCE ${LIB_SOURCE}
	src/openssl/ec.cpp
	src/openssl/hash.cpp
)

add_library( ${LIB_NAME} STATIC ${LIB_SOURCE} )

# Skip prefix on unix.
if (UNIX)
	set_target_properties(${LIB_NAME} PROPERTIES PREFIX "")
endif()


target_link_libraries( ${LIB_NAME}
	INTERFACE
		${OPENSSL_CRYPTO_LIBRARY}
)

target_include_directories( ${LIB_NAME}
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
		$<INSTALL_INTERFACE:include>
	PRIVATE
		${OPENSSL_INCLUDE_DIR}
)

# --------------------------------
#  Tests
# --------------------------------

if (ENABLE_TESTING)
	# enable testing functionality
	include(CTest)
	enable_testing()
	add_subdirectory( tests )
endif (ENABLE_TESTING)

# --------------------------------
#  Install
# --------------------------------

# Use installpath from GNUInstallDirs as default.
include(GNUInstallDirs)

if (WIN32)
	# "Flat" install on windows.
	set( CMAKE_INSTALL_BINDIR "." )
	set( CMAKE_INSTALL_DATADIR "." )
	set( CMAKE_INSTALL_SHAREDIR "." )
	set( CMAKE_INSTALL_MANDIR "." )
else()
	set( CMAKE_INSTALL_SHAREDIR ${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME} )
endif (WIN32)

set( CMAKE_INSTALL_CMAKEMODULEDIR ${CMAKE_INSTALL_SHAREDIR}/cmake )

install(TARGETS ${LIB_NAME} EXPORT ${PROJECT_NAME}Targets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Readme and license
install(FILES README.md LICENSE LICENSE.bitcoin
		DESTINATION ${CMAKE_INSTALL_SHAREDIR})

# --------------------------------
#  CMake Package Export
# --------------------------------

set_property(TARGET ${LIB_NAME}
	PROPERTY VERSION ${PROJECT_VERSION})

include(CMakePackageConfigHelpers)

# Version file.
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
	VERSION ${PROJECT_VERSION}
	COMPATIBILITY SameMajorVersion
)

# Export targets
export(EXPORT ${PROJECT_NAME}Targets
  FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake"
)
list (APPEND LIBEOSKEYGEN_CONFIG_INCLUDES Targets)

# Generate config file.
configure_file(cmake/${PROJECT_NAME}Config.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
	@ONLY
)

# Install config and targets
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake
              ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_CMAKEMODULEDIR} )

install(EXPORT ${PROJECT_NAME}Targets DESTINATION ${CMAKE_INSTALL_CMAKEMODULEDIR})

# --------------------------------
#  CMake Package Export
# --------------------------------

set( CPACK_PACKAGE_NAME ${PROJECT_NAME}-dev )
set( CPACK_DEBIAN_PACKAGE_PRIORITY "optional" )
set( CPACK_DEBIAN_PACKAGE_SECTION "devel" )
set( CPACK_DEBIAN_PACKAGE_RECOMMENDS "libssl1.1" )

include(cpack_custom)
