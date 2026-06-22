#ifndef CIPHER_PLUGIN_H
#define CIPHER_PLUGIN_H

#include "DynamicLibrary.h"

#include <filesystem>
#include <string>
#include <vector>

class CipherPlugin {
public:
    explicit CipherPlugin(const std::filesystem::path& library_path);

    CipherPlugin(const CipherPlugin&) = delete;
    CipherPlugin& operator=(const CipherPlugin&) = delete;
    CipherPlugin(CipherPlugin&&) noexcept = default;
    CipherPlugin& operator=(CipherPlugin&&) noexcept = default;

    const std::string& name() const noexcept;
    const std::string& description() const noexcept;

    bool validateKey(const std::string& key, std::string& error) const;
    std::string generateKey() const;
    std::string generateKeyForSize(std::size_t data_size) const;

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& input, const std::string& key) const;
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& input, const std::string& key) const;

private:
    using GetTextFunction = const char* (*)();
    using ValidateKeyFunction = bool (*)(const char*, char*, std::size_t);
    using GenerateKeyFunction = bool (*)(char*, std::size_t);
    using GenerateKeyForSizeFunction = bool (*)(std::size_t, char*, std::size_t);
    using TransformFunction = bool (*)(
        const unsigned char*,
        std::size_t,
        const char*,
        unsigned char*,
        std::size_t,
        std::size_t*,
        char*,
        std::size_t
    );

    static std::string makeErrorMessage(const char* buffer);

    DynamicLibrary library_;
    std::string name_;
    std::string description_;

    GetTextFunction get_algorithm_name_ = nullptr;
    GetTextFunction get_algorithm_description_ = nullptr;
    ValidateKeyFunction validate_key_ = nullptr;
    GenerateKeyFunction generate_key_ = nullptr;
    GenerateKeyForSizeFunction generate_key_for_size_ = nullptr;
    TransformFunction encrypt_data_ = nullptr;
    TransformFunction decrypt_data_ = nullptr;
};

#endif
