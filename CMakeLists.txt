add_library(gronsfeld_cipher SHARED
    GronsfeldCipher.cpp
)

target_include_directories(gronsfeld_cipher PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_compile_definitions(gronsfeld_cipher PRIVATE CIPHER_PLUGIN_EXPORTS)

set_target_properties(gronsfeld_cipher PROPERTIES
    OUTPUT_NAME "gronsfeld_cipher"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/plugins"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)
