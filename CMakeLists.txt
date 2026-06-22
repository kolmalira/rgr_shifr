cmake_minimum_required(VERSION 3.16)

project(EncryptionAlgorithmRGR LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/plugins)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if (MSVC)
    add_compile_options(/utf-8)
endif()

add_subdirectory(plugins/gronsfeld)
add_subdirectory(plugins/vernam)
add_subdirectory(plugins/aes)

add_executable(EncryptionAlgorithmRGR
    src/main.cpp
    src/DynamicLibrary.cpp
    src/CipherPlugin.cpp
    src/FileProcessor.cpp
    src/HexUtils.cpp
)

target_include_directories(EncryptionAlgorithmRGR PRIVATE include)

if (UNIX AND NOT APPLE)
    target_link_libraries(EncryptionAlgorithmRGR PRIVATE dl)
endif()

add_dependencies(EncryptionAlgorithmRGR gronsfeld_cipher vernam_cipher aes_cipher)

# Копируем DLL/SO/DYLIB рядом с exe, чтобы программа всегда находила плагины.
add_custom_command(TARGET EncryptionAlgorithmRGR POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:EncryptionAlgorithmRGR>/plugins"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:gronsfeld_cipher>" "$<TARGET_FILE_DIR:EncryptionAlgorithmRGR>/plugins/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:vernam_cipher>" "$<TARGET_FILE_DIR:EncryptionAlgorithmRGR>/plugins/"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:aes_cipher>" "$<TARGET_FILE_DIR:EncryptionAlgorithmRGR>/plugins/"
)
