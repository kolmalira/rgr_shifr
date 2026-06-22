#include "CipherApi.h"

#include <cctype>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace {
    void setError(char* error, std::size_t error_size, const std::string& message) {
        if (!error || error_size == 0) {
            return;
        }
        std::strncpy(error, message.c_str(), error_size - 1);
        error[error_size - 1] = '\0';
    }

    int hexValue(char ch) {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return ch - 'a' + 10;
        }
        if (ch >= 'A' && ch <= 'F') {
            return ch - 'A' + 10;
        }
        return -1;
    }

    std::string removeSpaces(const char* text) {
        std::string result;
        if (!text) {
            return result;
        }

        for (const char* current = text; *current; ++current) {
            unsigned char ch = static_cast<unsigned char>(*current);
            if (!std::isspace(ch)) {
                result.push_back(*current);
            }
        }
        return result;
    }

    bool hexToBytes(const char* hex_text, std::vector<byte>& bytes, std::string& error) {
        std::string clean = removeSpaces(hex_text);

        if (clean.empty()) {
            error = "ключ не может быть пустым";
            return false;
        }

        if (clean.size() % 2 != 0) {
            error = "HEX-ключ должен содержать четное количество символов";
            return false;
        }

        bytes.clear();
        bytes.reserve(clean.size() / 2);

        for (std::size_t i = 0; i < clean.size(); i += 2) {
            int high = hexValue(clean[i]);
            int low = hexValue(clean[i + 1]);
            if (high < 0 || low < 0) {
                error = "ключ должен быть записан в HEX-формате";
                return false;
            }
            bytes.push_back(static_cast<byte>((high << 4) | low));
        }

        return true;
    }

    std::string bytesToHex(const std::vector<byte>& bytes) {
        std::ostringstream stream;
        stream << std::uppercase << std::hex << std::setfill('0');
        for (byte value : bytes) {
            stream << std::setw(2) << static_cast<int>(value);
        }
        return stream.str();
    }

    bool transformData(
        const byte* input,
        std::size_t input_size,
        const char* key,
        byte* output,
        char* error,
        std::size_t error_size
    ) {
        if (input_size > 0 && (!input || !output)) {
            setError(error, error_size, "некорректный буфер данных");
            return false;
        }

        std::vector<byte> key_bytes;
        std::string validation_error;
        if (!hexToBytes(key, key_bytes, validation_error)) {
            setError(error, error_size, validation_error);
            return false;
        }

        if (key_bytes.size() < input_size) {
            setError(error, error_size, "ключ Вернама должен быть не короче данных");
            return false;
        }

        for (std::size_t i = 0; i < input_size; ++i) {
            output[i] = static_cast<byte>(input[i] ^ key_bytes[i]);
        }

        setError(error, error_size, "");
        return true;
    }

    bool generateRandomHexKey(std::size_t byte_count, char* buffer, std::size_t buffer_size) {
        if (!buffer || byte_count == 0) {
            return false;
        }

        std::size_t required_size = byte_count * 2 + 1;
        if (buffer_size < required_size) {
            return false;
        }

        std::vector<byte> key(byte_count);
        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<int> distribution(0, 255);

        for (byte& value : key) {
            value = static_cast<byte>(distribution(generator));
        }

        std::string hex_key = bytesToHex(key);
        std::strncpy(buffer, hex_key.c_str(), buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        return true;
    }
}

CIPHER_API const char* get_algorithm_name() {
    return "Шифр Вернама";
}

CIPHER_API const char* get_algorithm_description() {
    return "XOR-шифрование с одноразовым HEX-ключом";
}

CIPHER_API bool validate_key(const char* key, char* error, std::size_t error_size) {
    std::vector<byte> key_bytes;
    std::string validation_error;
    bool ok = hexToBytes(key, key_bytes, validation_error);
    setError(error, error_size, validation_error);
    return ok;
}

CIPHER_API bool generate_key(char* buffer, std::size_t buffer_size) {
    return generateRandomHexKey(16, buffer, buffer_size);
}

CIPHER_API bool generate_key_for_size(std::size_t data_size, char* buffer, std::size_t buffer_size) {
    return generateRandomHexKey(data_size, buffer, buffer_size);
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
    bool ok = transformData(input, input_size, key, output, error, error_size);
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
    bool ok = transformData(input, input_size, key, output, error, error_size);
    if (ok) {
        *output_size = input_size;
    }
    return ok;
}
