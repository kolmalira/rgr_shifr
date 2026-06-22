#ifndef FILE_PROCESSOR_H
#define FILE_PROCESSOR_H

#include <filesystem>
#include <vector>

class FileProcessor {
public:
    static std::vector<unsigned char> readBinaryFile(const std::filesystem::path& path);
    static void writeBinaryFile(const std::filesystem::path& path, const std::vector<unsigned char>& data);
};

#endif
