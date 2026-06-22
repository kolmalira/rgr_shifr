#include "CipherPlugin.h"

#include <array>
#include <stdexcept>

CipherPlugin::CipherPlugin(const std::filesystem::path& library_path)
    : library_(library_path) {
    get_algorithm_name_ = library_.getSymbol<GetTextFunction>("get_algorithm_name");
    get_algorithm_description_ = library_.getSymbol<GetTextFunction>("get_algorithm_description");
    validate_key_ = library_.getSymbol<ValidateKeyFunction>("validate_key");
    generate_key_ = library_.getSymbol<GenerateKeyFunction>("generate_key");
    generate_key_for_size_ = library_.getSymbol<GenerateKeyForSizeFunction>("generate_key_for_size");
    encrypt_data_ = library_.getSymbol<TransformFunction>("encrypt_data");
    decrypt_data_ = library_.getSymbol<TransformFunction>("decrypt_data");

    name_ = get_algorithm_name_();
    description_ = get_algorithm_description_();
}

const std::string& CipherPlugin::name() const noexcept {
    return name_;
}

const std::string& CipherPlugin::description() const noexcept {
    return description_;
}

bool CipherPlugin::validateKey(const std::string& key, std::string& error) const {
    std::array<char, 256> error_buffer{};
    bool result = validate_key_(key.c_str(), error_buffer.data(), error_buffer.size());
    error = makeErrorMessage(error_buffer.data());
    return result;
}

std::string CipherPlugin::generateKey() const {
    std::array<char, 128> buffer{};
    if (!generate_key_(buffer.data(), buffer.size())) {
        throw std::runtime_error("Не удалось сгенерировать ключ");
    }
    return buffer.data();
}

std::string CipherPlugin::generateKeyForSize(std::size_t data_size) const {
    if (data_size == 0) {
        throw std::runtime_error("Нельзя сгенерировать ключ для пустых данных");
    }

    std::size_t buffer_size = data_size * 2 + 1;
    if (buffer_size < 128) {
        buffer_size = 128;
    }

    std::vector<char> buffer(buffer_size, '\0');
    if (!generate_key_for_size_(data_size, buffer.data(), buffer.size())) {
        throw std::runtime_error("Не удалось сгенерировать ключ нужной длины");
    }

    return buffer.data();
}

std::vector<unsigned char> CipherPlugin::encrypt(const std::vector<unsigned char>& input, const std::string& key) const {
    std::size_t output_capacity = input.size() * 2 + 64;
    if (output_capacity < 64) {
        output_capacity = 64;
    }

    std::vector<unsigned char> output(output_capacity);
    std::size_t output_size = 0;
    std::array<char, 256> error_buffer{};

    bool ok = encrypt_data_(
        input.data(),
        input.size(),
        key.c_str(),
        output.data(),
        output.size(),
        &output_size,
        error_buffer.data(),
        error_buffer.size()
    );

    if (!ok) {
        throw std::runtime_error(makeErrorMessage(error_buffer.data()));
    }

    output.resize(output_size);
    return output;
}

std::vector<unsigned char> CipherPlugin::decrypt(const std::vector<unsigned char>& input, const std::string& key) const {
    std::size_t output_capacity = input.size() * 2 + 64;
    if (output_capacity < 64) {
        output_capacity = 64;
    }

    std::vector<unsigned char> output(output_capacity);
    std::size_t output_size = 0;
    std::array<char, 256> error_buffer{};

    bool ok = decrypt_data_(
        input.data(),
        input.size(),
        key.c_str(),
        output.data(),
        output.size(),
        &output_size,
        error_buffer.data(),
        error_buffer.size()
    );

    if (!ok) {
        throw std::runtime_error(makeErrorMessage(error_buffer.data()));
    }

    output.resize(output_size);
    return output;
}

std::string CipherPlugin::makeErrorMessage(const char* buffer) {
    if (!buffer || std::string(buffer).empty()) {
        return "Неизвестная ошибка шифрования";
    }
    return buffer;
}
