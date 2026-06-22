#include "CipherPlugin.h"
#include "FileProcessor.h"
#include "HexUtils.h"

#include <clocale>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {
    bool isDynamicLibrary(const fs::path& path) {
        std::string extension = path.extension().string();
#ifdef _WIN32
        return extension == ".dll";
#elif __APPLE__
        return extension == ".dylib";
#else
        return extension == ".so";
#endif
    }

    fs::path getExecutableDirectory(const char* argv0) {
        fs::path executable_path = fs::absolute(argv0);
        if (fs::exists(executable_path)) {
            return executable_path.parent_path();
        }
        return fs::current_path();
    }


    bool directoryHasPlugins(const fs::path& directory) {
        if (!fs::exists(directory) || !fs::is_directory(directory)) {
            return false;
        }

        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file() && isDynamicLibrary(entry.path())) {
                return true;
            }
        }

        return false;
    }

    fs::path findPluginDirectory(const fs::path& executable_dir) {
        std::vector<fs::path> candidates = {
            executable_dir / "plugins",
            executable_dir.parent_path() / "plugins",
            executable_dir.parent_path() / "plugins" / executable_dir.filename()
        };

        for (const fs::path& candidate : candidates) {
            if (directoryHasPlugins(candidate)) {
                return candidate;
            }
        }

        return executable_dir / "plugins";
    }

    std::vector<CipherPlugin> loadPlugins(const fs::path& directory) {
        std::vector<CipherPlugin> plugins;

        if (!fs::exists(directory)) {
            throw std::runtime_error("Папка с библиотеками не найдена: " + directory.string());
        }

        for (const auto& entry : fs::directory_iterator(directory)) {
            if (!entry.is_regular_file() || !isDynamicLibrary(entry.path())) {
                continue;
            }

            try {
                plugins.emplace_back(entry.path());
            } catch (const std::exception& exception) {
                std::cout << "Предупреждение: библиотека не подключена: "
                          << entry.path().filename().string() << " — "
                          << exception.what() << '\n';
            }
        }

        if (plugins.empty()) {
            throw std::runtime_error("Не найдено ни одной корректной библиотеки шифрования");
        }

        return plugins;
    }

    std::string readLine(const std::string& prompt) {
        std::cout << prompt;
        std::string line;
        std::getline(std::cin, line);
        return line;
    }

    int readInt(const std::string& prompt, int min_value, int max_value) {
        while (true) {
            std::cout << prompt;
            std::string line;
            std::getline(std::cin, line);

            try {
                std::size_t parsed_count = 0;
                int value = std::stoi(line, &parsed_count);
                if (parsed_count == line.size() && value >= min_value && value <= max_value) {
                    return value;
                }
            } catch (...) {
            }

            std::cout << "Ошибка: введите число от " << min_value << " до " << max_value << ".\n";
        }
    }

    CipherPlugin& choosePlugin(std::vector<CipherPlugin>& plugins) {
        std::cout << "\nДоступные алгоритмы:\n";
        for (std::size_t i = 0; i < plugins.size(); ++i) {
            std::cout << i + 1 << ". " << plugins[i].name() << " — " << plugins[i].description() << '\n';
        }

        int choice = readInt("Выберите алгоритм: ", 1, static_cast<int>(plugins.size()));
        return plugins[static_cast<std::size_t>(choice - 1)];
    }

    std::string readValidKey(const CipherPlugin& plugin, std::size_t data_size, bool allow_generation) {
        while (true) {
            std::string prompt = allow_generation
                ? "Введите ключ или нажмите Enter для генерации: "
                : "Введите ключ: ";

            std::string key = readLine(prompt);

            if (key.empty() && allow_generation) {
                key = plugin.generateKeyForSize(data_size);
                std::cout << "Сгенерированный ключ:\n" << key << "\n";
                return key;
            }

            std::string error;
            if (plugin.validateKey(key, error)) {
                return key;
            }
            std::cout << "Ошибка ключа: " << error << '\n';
        }
    }

    fs::path makeAutomaticOutputPath(const fs::path& input_path, bool encrypt) {
        std::string suffix = encrypt ? "_encrypted" : "_decrypted";
        return input_path.parent_path() / (input_path.stem().string() + suffix + input_path.extension().string());
    }

    void saveGeneratedKey(const fs::path& output_path, const std::string& key) {
        fs::path key_path = output_path;
        key_path += ".key.txt";

        std::ofstream key_file(key_path);
        if (!key_file) {
            std::cout << "Предупреждение: не удалось сохранить ключ в файл. Сохраните его вручную.\n";
            return;
        }

        key_file << key << '\n';
        std::cout << "Ключ дополнительно сохранен в файл: " << key_path.string() << "\n";
    }

    void processText(std::vector<CipherPlugin>& plugins) {
        CipherPlugin& plugin = choosePlugin(plugins);
        int mode = readInt("1 — зашифровать, 2 — расшифровать: ", 1, 2);

        if (mode == 1) {
            std::string text = readLine("Введите исходный текст: ");
            if (text.empty()) {
                throw std::runtime_error("исходный текст не может быть пустым");
            }

            std::vector<unsigned char> input(text.begin(), text.end());
            std::string key = readValidKey(plugin, input.size(), true);
            std::vector<unsigned char> encrypted = plugin.encrypt(input, key);

            std::cout << "\nРезультат в HEX:\n" << HexUtils::toHex(encrypted) << "\n";
            std::cout << "Ключ нужно сохранить для последующего дешифрования.\n";
        } else {
            std::string hex_text = readLine("Введите шифротекст в HEX: ");
            std::vector<unsigned char> input = HexUtils::fromHex(hex_text);
            if (input.empty()) {
                throw std::runtime_error("шифротекст не может быть пустым");
            }

            std::string key = readValidKey(plugin, input.size(), false);
            std::vector<unsigned char> decrypted = plugin.decrypt(input, key);
            std::string result(decrypted.begin(), decrypted.end());

            std::cout << "\nРасшифрованный текст:\n" << result << "\n";
        }
    }

    void processFile(std::vector<CipherPlugin>& plugins) {
        CipherPlugin& plugin = choosePlugin(plugins);
        int mode = readInt("1 — зашифровать файл, 2 — расшифровать файл: ", 1, 2);
        bool encrypt = mode == 1;

        std::string input_prompt = encrypt
            ? "Введите путь к файлу, который нужно зашифровать: "
            : "Введите путь к зашифрованному файлу, который нужно расшифровать: ";
        fs::path input_path = readLine(input_prompt);

        std::vector<unsigned char> input = FileProcessor::readBinaryFile(input_path);
        if (input.empty()) {
            throw std::runtime_error("файл пустой, обрабатывать нечего");
        }

        std::string key = readValidKey(plugin, input.size(), encrypt);

        std::string output_prompt = encrypt
            ? "Введите путь для зашифрованного файла или нажмите Enter для автоматического имени: "
            : "Введите путь для расшифрованного файла или нажмите Enter для автоматического имени: ";
        std::string output_text = readLine(output_prompt);
        fs::path output_path = output_text.empty() ? makeAutomaticOutputPath(input_path, encrypt) : fs::path(output_text);

        std::vector<unsigned char> output = encrypt
            ? plugin.encrypt(input, key)
            : plugin.decrypt(input, key);

        FileProcessor::writeBinaryFile(output_path, output);
        std::cout << "Готово. Результат сохранен в файл: " << output_path.string() << "\n";

        if (encrypt) {
            saveGeneratedKey(output_path, key);
        }
    }

    void generateKey(std::vector<CipherPlugin>& plugins) {
        CipherPlugin& plugin = choosePlugin(plugins);

        std::cout << "\n1. Сгенерировать стандартный ключ алгоритма\n"
                  << "2. Сгенерировать ключ под размер данных в байтах\n";
        int choice = readInt("Выберите пункт: ", 1, 2);

        if (choice == 1) {
            std::cout << "Сгенерированный ключ: " << plugin.generateKey() << "\n";
            return;
        }

        int size = readInt("Введите размер данных в байтах: ", 1, 1000000);
        std::cout << "Сгенерированный ключ:\n"
                  << plugin.generateKeyForSize(static_cast<std::size_t>(size)) << "\n";
    }

    void showAlgorithms(const std::vector<CipherPlugin>& plugins) {
        std::cout << "\nПодключенные алгоритмы:\n";
        for (std::size_t i = 0; i < plugins.size(); ++i) {
            std::cout << i + 1 << ". " << plugins[i].name() << " — " << plugins[i].description() << '\n';
        }
    }
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    std::setlocale(LC_ALL, ".UTF-8");
#else
    std::setlocale(LC_ALL, "");
#endif

    try {
        fs::path executable_dir = getExecutableDirectory(argv[0]);
        fs::path plugin_dir = findPluginDirectory(executable_dir);

        std::vector<CipherPlugin> plugins = loadPlugins(plugin_dir);

        while (true) {
            std::cout << "\n===== Encryption Algorithm RGR =====\n"
                      << "1. Шифрование/дешифрование текста\n"
                      << "2. Шифрование/дешифрование файла\n"
                      << "3. Генератор ключей\n"
                      << "4. Список алгоритмов\n"
                      << "0. Выход\n";

            int choice = readInt("Выберите пункт меню: ", 0, 4);

            try {
                switch (choice) {
                    case 1:
                        processText(plugins);
                        break;
                    case 2:
                        processFile(plugins);
                        break;
                    case 3:
                        generateKey(plugins);
                        break;
                    case 4:
                        showAlgorithms(plugins);
                        break;
                    case 0:
                        std::cout << "Завершение работы.\n";
                        return 0;
                    default:
                        break;
                }
            } catch (const std::exception& exception) {
                std::cout << "Ошибка: " << exception.what() << "\n";
            }
        }
    } catch (const std::exception& exception) {
        std::cerr << "Критическая ошибка: " << exception.what() << "\n";
        return 1;
    }
}
