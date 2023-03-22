
set(TARGET secp256k1)

add_library(${TARGET} OBJECT
	repo/src/secp256k1.c
	repo/src/precomputed_ecmult.c
	repo/src/precomputed_ecmult_gen.c
)

target_compile_definitions(${TARGET}
	PRIVATE ENABLE_MODULE_RECOVERY
)

target_include_directories(${TARGET}
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/repo/include
)
