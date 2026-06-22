#include "CipherApi.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <random>
#include <string>

namespace {
    void setError(char* error, std::size_t error_size, const std::string& message) {
        if (!error || error_size == 0) {
            return;
        }

        std::strncpy(error, message.c_str(), error_size - 1);
        error[error_size - 1] = '\0';
    }

    bool isValidKey(const char* key, std::string& error) {
        if (!key || std::strlen(key) == 0) {
            error = "ключ не может быть пустым";
            return false;
        }

        std::string key_string(key);
        bool only_digits = std::all_of(
            key_string.begin(),
            key_string.end(),
            [](unsigned char ch) { return std::isdigit(ch); }
        );

        if (!only_digits) {
            error = "для шифра Гронсфельда ключ должен состоять только из цифр";
            return false;
        }

        return true;
    }

    bool transformData(
        const byte* input,
        std::size_t input_size,
        const char* key,
        byte* output,
        char* error,
        std::size_t error_size,
        bool encrypt
    ) {
        std::string validation_error;
        if (!isValidKey(key, validation_error)) {
            setError(error, error_size, validation_error);
            return false;
        }

        if (input_size > 0 && (!input || !output)) {
            setError(error, error_size, "некорректный буфер данных");
            return false;
        }

        std::string key_string(key);
        for (std::size_t i = 0; i < input_size; ++i) {
            int shift = key_string[i % key_string.size()] - '0';
            int value = static_cast<int>(input[i]);

            if (encrypt) {
                output[i] = static_cast<byte>((value + shift) % 256);
            } else {
                output[i] = static_cast<byte>((value - shift + 256) % 256);
            }
        }

        setError(error, error_size, "");
        return true;
    }
}

CIPHER_API const char* get_algorithm_name() {
    return "Шифр Гронсфельда";
}

CIPHER_API const char* get_algorithm_description() {
    return "байтовый вариант шифра Гронсфельда с числовым ключом";
}

CIPHER_API bool validate_key(const char* key, char* error, std::size_t error_size) {
    std::string validation_error;
    bool ok = isValidKey(key, validation_error);
    setError(error, error_size, validation_error);
    return ok;
}

CIPHER_API bool generate_key(char* buffer, std::size_t buffer_size) {
    if (!buffer || buffer_size < 9) {
        return false;
    }

    std::random_device random_device;
    std::mt19937 generator(random_device());
    std::uniform_int_distribution<int> distribution(0, 9);

    for (std::size_t i = 0; i < 8; ++i) {
        buffer[i] = static_cast<char>('0' + distribution(generator));
    }
    buffer[8] = '\0';

    return true;
}


CIPHER_API bool generate_key_for_size(std::size_t, char* buffer, std::size_t buffer_size) {
    return generate_key(buffer, buffer_size);
}

CIPHER_API bool encrypt_data(
    const byte* input,
    std::size_t input_size,
    const char* key,
    byte* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
) {
    if (!output_size) {
        setError(error, error_size, "не передан размер выходных данных");
        return false;
    }
    if (output_capacity < input_size) {
        setError(error, error_size, "недостаточный размер выходного буфера");
        return false;
    }
    bool ok = transformData(input, input_size, key, output, error, error_size, true);
    if (ok) {
        *output_size = input_size;
    }
    return ok;
}

CIPHER_API bool decrypt_data(
    const byte* input,
    std::size_t input_size,
    const char* key,
    byte* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
) {
    if (!output_size) {
        setError(error, error_size, "не передан размер выходных данных");
        return false;
    }
    if (output_capacity < input_size) {
        setError(error, error_size, "недостаточный размер выходного буфера");
        return false;
    }
    bool ok = transformData(input, input_size, key, output, error, error_size, false);
    if (ok) {
        *output_size = input_size;
    }
    return ok;
}
