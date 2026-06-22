#include "FileProcessor.h"

#include <fstream>
#include <stdexcept>

std::vector<unsigned char> FileProcessor::readBinaryFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        throw std::runtime_error("Файл не найден: " + path.string());
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Не удалось открыть файл для чтения: " + path.string());
    }

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

void FileProcessor::writeBinaryFile(const std::filesystem::path& path, const std::vector<unsigned char>& data) {
    std::filesystem::path parent_path = path.parent_path();
    if (!parent_path.empty() && !std::filesystem::exists(parent_path)) {
        std::filesystem::create_directories(parent_path);
    }

    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Не удалось открыть файл для записи: " + path.string());
    }

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!file) {
        throw std::runtime_error("Ошибка записи в файл: " + path.string());
    }
}
