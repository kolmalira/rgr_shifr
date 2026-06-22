#ifndef CIPHER_API_H
#define CIPHER_API_H

#include <cstddef>

#ifdef _WIN32
    #ifdef CIPHER_PLUGIN_EXPORTS
        #define CIPHER_API extern "C" __declspec(dllexport)
    #else
        #define CIPHER_API extern "C" __declspec(dllimport)
    #endif
#else
    #define CIPHER_API extern "C"
#endif

using byte = unsigned char;

CIPHER_API const char* get_algorithm_name();
CIPHER_API const char* get_algorithm_description();
CIPHER_API bool validate_key(const char* key, char* error, std::size_t error_size);
CIPHER_API bool generate_key(char* buffer, std::size_t buffer_size);
CIPHER_API bool generate_key_for_size(std::size_t data_size, char* buffer, std::size_t buffer_size);

// output_capacity — размер выделенного выходного буфера.
// output_size — фактическое количество байт, записанных в output.
CIPHER_API bool encrypt_data(
    const byte* input,
    std::size_t input_size,
    const char* key,
    byte* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
);

CIPHER_API bool decrypt_data(
    const byte* input,
    std::size_t input_size,
    const char* key,
    byte* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
);

#endif
