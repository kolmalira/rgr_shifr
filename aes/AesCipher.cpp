#include "CipherApi.h"
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <string>
#include <random>
#include <chrono>
#include <algorithm>
#include <sstream>

using namespace std;

// ==================== ТАБЛИЦЫ S-BOX ====================
const unsigned char sBox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

const unsigned char invSBox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

const unsigned char rcon[10] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

// ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

// Умножение в поле Галуа GF(2^8)
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char res = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) res ^= a;
        bool carry = a & 0x80;
        a <<= 1;
        if (carry) a ^= 0x1B;
        b >>= 1;
    }
    return res;
}

// Преобразование байтов в HEX строку
string bytesToHex(const unsigned char* data, int len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < len; i++) {
        ss << setw(2) << (int)data[i];
    }
    return ss.str();
}

// Преобразование HEX строки в байты
vector<unsigned char> hexToBytes(const string& hex) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)stoi(byteString, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// ==================== КЛАСС AES ====================
class Aes128 {
private:
    unsigned char state[16];      // Текущее состояние (одномерный массив)
    unsigned char key[44][4];     // Расширенный ключ
    
    // SubBytes - замена через S-box
    void subBytes() {
        for (int i = 0; i < 16; i++) 
            state[i] = sBox[state[i]];
    }
    
    void invSubBytes() {
        for (int i = 0; i < 16; i++) 
            state[i] = invSBox[state[i]];
    }
    
    // ShiftRows - циклический сдвиг строк
    void shiftRows() {
        unsigned char tmp[16];
        tmp[0] = state[0]; tmp[4] = state[4]; tmp[8] = state[8]; tmp[12] = state[12];
        tmp[1] = state[5]; tmp[5] = state[9]; tmp[9] = state[13]; tmp[13] = state[1];
        tmp[2] = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
        tmp[3] = state[15]; tmp[7] = state[3]; tmp[11] = state[7]; tmp[15] = state[11];
        memcpy(state, tmp, 16);
    }
    
    void invShiftRows() {
        unsigned char tmp[16];
        tmp[0] = state[0]; tmp[4] = state[4]; tmp[8] = state[8]; tmp[12] = state[12];
        tmp[1] = state[13]; tmp[5] = state[1]; tmp[9] = state[5]; tmp[13] = state[9];
        tmp[2] = state[10]; tmp[6] = state[14]; tmp[10] = state[2]; tmp[14] = state[6];
        tmp[3] = state[7]; tmp[7] = state[11]; tmp[11] = state[15]; tmp[15] = state[3];
        memcpy(state, tmp, 16);
    }
    
    // MixColumns - перемешивание столбцов
    void mixColumns() {
        unsigned char tmp[16];
        for (int col = 0; col < 4; col++) {
            int idx = col * 4;
            tmp[idx]   = gmul(state[idx], 2) ^ gmul(state[idx+1], 3) ^ state[idx+2] ^ state[idx+3];
            tmp[idx+1] = state[idx] ^ gmul(state[idx+1], 2) ^ gmul(state[idx+2], 3) ^ state[idx+3];
            tmp[idx+2] = state[idx] ^ state[idx+1] ^ gmul(state[idx+2], 2) ^ gmul(state[idx+3], 3);
            tmp[idx+3] = gmul(state[idx], 3) ^ state[idx+1] ^ state[idx+2] ^ gmul(state[idx+3], 2);
        }
        memcpy(state, tmp, 16);
    }
    
    void invMixColumns() {
        unsigned char tmp[16];
        for (int col = 0; col < 4; col++) {
            int idx = col * 4;
            tmp[idx]   = gmul(state[idx], 14) ^ gmul(state[idx+1], 11) ^ gmul(state[idx+2], 13) ^ gmul(state[idx+3], 9);
            tmp[idx+1] = gmul(state[idx], 9) ^ gmul(state[idx+1], 14) ^ gmul(state[idx+2], 11) ^ gmul(state[idx+3], 13);
            tmp[idx+2] = gmul(state[idx], 13) ^ gmul(state[idx+1], 9) ^ gmul(state[idx+2], 14) ^ gmul(state[idx+3], 11);
            tmp[idx+3] = gmul(state[idx], 11) ^ gmul(state[idx+1], 13) ^ gmul(state[idx+2], 9) ^ gmul(state[idx+3], 14);
        }
        memcpy(state, tmp, 16);
    }
    
    // Добавление раундового ключа
    void addRoundKey(int round) {
        for (int i = 0; i < 16; i++)
            state[i] ^= key[round * 4 + i/4][i%4];
    }
    
    // Расширение ключа
    void expandKey(const unsigned char* originalKey) {
        for (int i = 0; i < 16; i++)
            key[i/4][i%4] = originalKey[i];
        
        for (int i = 4; i < 44; i++) {
            unsigned char temp[4];
            for (int j = 0; j < 4; j++) temp[j] = key[i-1][j];
            
            if (i % 4 == 0) {
                unsigned char rot[4] = {temp[1], temp[2], temp[3], temp[0]};
                for (int j = 0; j < 4; j++) rot[j] = sBox[rot[j]];
                rot[0] ^= rcon[i/4 - 1];
                for (int j = 0; j < 4; j++) temp[j] = rot[j];
            }
            
            for (int j = 0; j < 4; j++)
                key[i][j] = key[i-4][j] ^ temp[j];
        }
    }
    
public:
    Aes128(const unsigned char* k) { expandKey(k); }
    
    // Шифрование блока 16 байт
    void encryptBlock(const unsigned char* in, unsigned char* out) {
        memcpy(state, in, 16);
        addRoundKey(0);
        
        for (int round = 1; round < 10; round++) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(round);
        }
        
        subBytes();
        shiftRows();
        addRoundKey(10);
        memcpy(out, state, 16);
    }
    
    // Дешифрование блока 16 байт
    void decryptBlock(const unsigned char* in, unsigned char* out) {
        memcpy(state, in, 16);
        addRoundKey(10);
        invShiftRows();
        invSubBytes();
        
        for (int round = 9; round >= 1; round--) {
            addRoundKey(round);
            invMixColumns();
            invShiftRows();
            invSubBytes();
        }
        
        addRoundKey(0);
        memcpy(out, state, 16);
    }
};



namespace {
    void setError(char* error, std::size_t error_size, const std::string& message) {
        if (!error || error_size == 0) {
            return;
        }
        std::strncpy(error, message.c_str(), error_size - 1);
        error[error_size - 1] = '\0';
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

    bool parseAesKey(const char* key_text, unsigned char key[16], std::string& error) {
        std::string clean = removeSpaces(key_text);
        if (clean.empty()) {
            error = "ключ AES не может быть пустым";
            return false;
        }
        if (clean.size() != 32) {
            error = "ключ AES-128 должен содержать ровно 32 HEX-символа";
            return false;
        }

        try {
            for (int i = 0; i < 16; ++i) {
                std::string byte_string = clean.substr(static_cast<std::size_t>(i) * 2, 2);
                std::size_t parsed_count = 0;
                int value = std::stoi(byte_string, &parsed_count, 16);
                if (parsed_count != 2 || value < 0 || value > 255) {
                    error = "ключ AES должен быть записан в HEX-формате";
                    return false;
                }
                key[i] = static_cast<unsigned char>(value);
            }
        } catch (...) {
            error = "ключ AES должен быть записан в HEX-формате";
            return false;
        }

        return true;
    }

    bool generateRandomAesKey(char* buffer, std::size_t buffer_size) {
        if (!buffer || buffer_size < 33) {
            return false;
        }

        unsigned char key[16];
        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<int> distribution(0, 255);

        for (unsigned char& value : key) {
            value = static_cast<unsigned char>(distribution(generator));
        }

        std::string hex_key = bytesToHex(key, 16);
        std::strncpy(buffer, hex_key.c_str(), buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        return true;
    }

    std::vector<unsigned char> addSizeAndPadding(const unsigned char* input, std::size_t input_size) {
        std::vector<unsigned char> data;
        data.resize(8);

        unsigned long long original_size = static_cast<unsigned long long>(input_size);
        for (int i = 0; i < 8; ++i) {
            data[static_cast<std::size_t>(i)] = static_cast<unsigned char>((original_size >> (i * 8)) & 0xFF);
        }

        if (input_size > 0) {
            data.insert(data.end(), input, input + input_size);
        }

        while (data.size() % 16 != 0) {
            data.push_back(0);
        }

        return data;
    }
}

CIPHER_API const char* get_algorithm_name() {
    return "AES-128";
}

CIPHER_API const char* get_algorithm_description() {
    return "блочное шифрование AES-128 с HEX-ключом 16 байт";
}

CIPHER_API bool validate_key(const char* key, char* error, std::size_t error_size) {
    unsigned char parsed_key[16];
    std::string validation_error;
    bool ok = parseAesKey(key, parsed_key, validation_error);
    setError(error, error_size, validation_error);
    return ok;
}

CIPHER_API bool generate_key(char* buffer, std::size_t buffer_size) {
    return generateRandomAesKey(buffer, buffer_size);
}

CIPHER_API bool generate_key_for_size(std::size_t, char* buffer, std::size_t buffer_size) {
    return generateRandomAesKey(buffer, buffer_size);
}

CIPHER_API bool encrypt_data(
    const unsigned char* input,
    std::size_t input_size,
    const char* key,
    unsigned char* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
) {
    if (!output_size) {
        setError(error, error_size, "не передан размер выходных данных");
        return false;
    }
    if (input_size > 0 && !input) {
        setError(error, error_size, "некорректный входной буфер");
        return false;
    }
    if (!output) {
        setError(error, error_size, "некорректный выходной буфер");
        return false;
    }

    unsigned char parsed_key[16];
    std::string validation_error;
    if (!parseAesKey(key, parsed_key, validation_error)) {
        setError(error, error_size, validation_error);
        return false;
    }

    std::vector<unsigned char> prepared = addSizeAndPadding(input, input_size);
    if (output_capacity < prepared.size()) {
        setError(error, error_size, "недостаточный размер выходного буфера");
        return false;
    }

    Aes128 cipher(parsed_key);
    for (std::size_t i = 0; i < prepared.size(); i += 16) {
        cipher.encryptBlock(&prepared[i], output + i);
    }

    *output_size = prepared.size();
    setError(error, error_size, "");
    return true;
}

CIPHER_API bool decrypt_data(
    const unsigned char* input,
    std::size_t input_size,
    const char* key,
    unsigned char* output,
    std::size_t output_capacity,
    std::size_t* output_size,
    char* error,
    std::size_t error_size
) {
    if (!output_size) {
        setError(error, error_size, "не передан размер выходных данных");
        return false;
    }
    if (!input || !output) {
        setError(error, error_size, "некорректный буфер данных");
        return false;
    }
    if (input_size == 0 || input_size % 16 != 0) {
        setError(error, error_size, "для AES размер шифротекста должен быть кратен 16 байтам");
        return false;
    }

    unsigned char parsed_key[16];
    std::string validation_error;
    if (!parseAesKey(key, parsed_key, validation_error)) {
        setError(error, error_size, validation_error);
        return false;
    }

    std::vector<unsigned char> decrypted(input_size);
    Aes128 cipher(parsed_key);
    for (std::size_t i = 0; i < input_size; i += 16) {
        cipher.decryptBlock(input + i, &decrypted[i]);
    }

    unsigned long long original_size = 0;
    for (int i = 0; i < 8; ++i) {
        original_size |= static_cast<unsigned long long>(decrypted[static_cast<std::size_t>(i)]) << (i * 8);
    }

    if (original_size > decrypted.size() - 8) {
        setError(error, error_size, "не удалось восстановить исходный размер: возможно, неверный ключ или поврежденный файл");
        return false;
    }

    if (output_capacity < original_size) {
        setError(error, error_size, "недостаточный размер выходного буфера");
        return false;
    }

    std::memcpy(output, decrypted.data() + 8, static_cast<std::size_t>(original_size));
    *output_size = static_cast<std::size_t>(original_size);
    setError(error, error_size, "");
    return true;
}
