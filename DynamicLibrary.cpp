#include "DynamicLibrary.h"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <dlfcn.h>
#endif

DynamicLibrary::DynamicLibrary(const std::filesystem::path& path) {
    load(path);
}

DynamicLibrary::DynamicLibrary(DynamicLibrary&& other) noexcept
    : handle_(other.handle_), path_(std::move(other.path_)) {
    other.handle_ = nullptr;
}

DynamicLibrary& DynamicLibrary::operator=(DynamicLibrary&& other) noexcept {
    if (this != &other) {
        unload();
        handle_ = other.handle_;
        path_ = std::move(other.path_);
        other.handle_ = nullptr;
    }
    return *this;
}

DynamicLibrary::~DynamicLibrary() {
    unload();
}

void DynamicLibrary::load(const std::filesystem::path& path) {
    unload();
    path_ = path;

#ifdef _WIN32
    handle_ = reinterpret_cast<void*>(LoadLibraryW(path.wstring().c_str()));
    if (!handle_) {
        throw std::runtime_error("Не удалось загрузить библиотеку: " + path.string());
    }
#else
    handle_ = dlopen(path.string().c_str(), RTLD_NOW);
    if (!handle_) {
        std::string error = dlerror() ? dlerror() : "неизвестная ошибка";
        throw std::runtime_error("Не удалось загрузить библиотеку: " + path.string() + ". " + error);
    }
#endif
}

void DynamicLibrary::unload() {
    if (!handle_) {
        return;
    }

#ifdef _WIN32
    FreeLibrary(reinterpret_cast<HMODULE>(handle_));
#else
    dlclose(handle_);
#endif

    handle_ = nullptr;
}

bool DynamicLibrary::isLoaded() const noexcept {
    return handle_ != nullptr;
}

void* DynamicLibrary::getSymbolAddress(const std::string& name) const {
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(handle_), name.c_str()));
#else
    dlerror();
    return dlsym(handle_, name.c_str());
#endif
}
