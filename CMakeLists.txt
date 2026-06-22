add_library(vernam_cipher SHARED
    VernamCipher.cpp
)

target_include_directories(vernam_cipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(vernam_cipher PRIVATE CIPHER_PLUGIN_EXPORTS)

set_target_properties(vernam_cipher PROPERTIES
    OUTPUT_NAME "vernam_cipher"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
