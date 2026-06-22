#ifndef DYNAMIC_LIBRARY_H
#define DYNAMIC_LIBRARY_H

#include <filesystem>
#include <stdexcept>
#include <string>

class DynamicLibrary {
public:
    DynamicLibrary() = default;
    explicit DynamicLibrary(const std::filesystem::path& path);

    DynamicLibrary(const DynamicLibrary&) = delete;
    DynamicLibrary& operator=(const DynamicLibrary&) = delete;

    DynamicLibrary(DynamicLibrary&& other) noexcept;
    DynamicLibrary& operator=(DynamicLibrary&& other) noexcept;

    ~DynamicLibrary();

    void load(const std::filesystem::path& path);
    void unload();
    bool isLoaded() const noexcept;

    template <typename T>
    T getSymbol(const std::string& name) const {
        if (!handle_) {
            throw std::runtime_error("Библиотека не загружена");
        }
        void* symbol = getSymbolAddress(name);
        if (!symbol) {
            throw std::runtime_error("Не найдена функция в библиотеке: " + name);
        }
        return reinterpret_cast<T>(symbol);
    }

private:
    void* getSymbolAddress(const std::string& name) const;

    void* handle_ = nullptr;
    std::filesystem::path path_;
};

#endif
