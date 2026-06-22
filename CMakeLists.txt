add_library(aes_cipher SHARED
    AesCipher.cpp
)

target_include_directories(aes_cipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(aes_cipher PRIVATE CIPHER_PLUGIN_EXPORTS)

set_target_properties(aes_cipher PROPERTIES
    OUTPUT_NAME "aes_cipher"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
