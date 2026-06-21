#include <iostream>
#include <fstream> //для работы с файлами
#include <string>
#include <vector>
#include <filesystem> //для работы с файловой системой (C++17)
#include <random> //для генерации случайных чисел
#include <chrono> //для работы со временем для генерации случайных чисел
#include <iomanip> //для форматированного вывода
#include <sstream>
#include <algorithm> //(remove_if)
#include <cctype> //для работы с символами (isspace)

namespace fs = std::filesystem;

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : bytes) {
        ss << std::setw(2) << (int)c;
    }
    return ss.str();
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    std::string cleanHex;
    for (char c : hex) {
        if (c != ' ' && c != '\t' && c != '\n') {
            cleanHex += c;
        }
    }
    if (cleanHex.length() % 2 != 0) {
        throw std::runtime_error("HEX строка должна иметь четную длину");
    }
    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        std::string byteStr = cleanHex.substr(i, 2);
        char* endPtr;
        long val = strtol(byteStr.c_str(), &endPtr, 16);
        if (*endPtr != '\0') {
            throw std::runtime_error("Неверный HEX формат");
        }
        bytes.push_back(static_cast<unsigned char>(val));
    }
    return bytes;
}

class VernamCipher {
private:
    std::vector<unsigned char> key;
public:
    void setKeyFromHex(const std::string& hexStr) {
        key = hexToBytes(hexStr);
    }
    std::string getKeyAsHex() const {
        return bytesToHex(key);
    }
    void generateKey(size_t length) {
        key.resize(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        for (size_t i = 0; i < length; ++i) {
            key[i] = static_cast<unsigned char>(dis(gen));
        }
    }
    
    //шифрование текста
    std::string encryptText(const std::string& plainText) const {
        if (key.empty()) throw std::runtime_error("Ключ не установлен");
        if (key.size() < plainText.length()) throw std::runtime_error("Ключ короче текста");
        
        std::vector<unsigned char> result(plainText.length());
        for (size_t i = 0; i < plainText.length(); ++i) {
            result[i] = plainText[i] ^ key[i];
        }
        return bytesToHex(result);
    }
    
    //дешифрование текста из HEX (возвращает байты!!!)
    std::vector<unsigned char> decryptTextToBytes(const std::string& hexInput) const {
        if (key.empty()) throw std::runtime_error("Ключ не установлен");
        
        std::vector<unsigned char> inputBytes = hexToBytes(hexInput);
        if (key.size() < inputBytes.size()) throw std::runtime_error("Ключ короче данных");
        
        std::vector<unsigned char> result(inputBytes.size());
        for (size_t i = 0; i < inputBytes.size(); ++i) {
            result[i] = inputBytes[i] ^ key[i];
        }
        return result;
    }
    
    //дешифрование текста HEX в HEX
    std::string decryptTextHex(const std::string& hexInput) const {
        std::vector<unsigned char> result = decryptTextToBytes(hexInput);
        return bytesToHex(result);
    }
    
    //дешифрование текста HEX в строку (UTF-8)
    std::string decryptTextUtf8(const std::string& hexInput) const {
        std::vector<unsigned char> result = decryptTextToBytes(hexInput);
        return std::string(result.begin(), result.end());
    }
    
    void processFile(const fs::path& inputPath, const fs::path& outputPath) const {
        if (!fs::exists(inputPath)) throw std::runtime_error("Файл не найден");
        if (key.empty()) throw std::runtime_error("Ключ не установлен");
        size_t fileSize = fs::file_size(inputPath);
        if (key.size() < fileSize) throw std::runtime_error("Ключ короче файла");
        
        fs::create_directories(outputPath.parent_path());
        std::ifstream in(inputPath, std::ios::binary);
        std::ofstream out(outputPath, std::ios::binary);
        if (!in.is_open()) throw std::runtime_error("Не удалось открыть файл");
        if (!out.is_open()) throw std::runtime_error("Не удалось создать файл");
        const size_t BUFFER_SIZE = 8192;
        std::vector<unsigned char> buffer(BUFFER_SIZE);
        size_t processed = 0;
        
        while (in.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE) || in.gcount() > 0) {
            size_t bytesRead = in.gcount();
            for (size_t i = 0; i < bytesRead; ++i) {
                buffer[i] ^= key[processed + i];
            }
            out.write(reinterpret_cast<const char*>(buffer.data()), bytesRead);
            processed += bytesRead;
        }
    }
};

void processText(bool encrypt) {
    VernamCipher cipher;
    std::string text, keyInput;
    std::cout << "\n=== " << (encrypt ? "ШИФРОВАНИЕ" : "ДЕШИФРОВАНИЕ") << " ТЕКСТА ===\n";
    if (encrypt) {
        std::cout << "Введите текст для шифрования: ";
        std::getline(std::cin, text);
        if (text.empty()) {
            std::cout << "Ошибка: текст не может быть пустым\n";
            return;
        }
        
        std::cout << "Введите ключ (HEX) или Enter для генерации: ";
        std::getline(std::cin, keyInput);
        if (keyInput.empty()) {
            cipher.generateKey(text.length());
            std::cout << "Сгенерирован ключ (HEX): " << cipher.getKeyAsHex() << "\n";
            std::cout << "Длина ключа: " << text.length() << " байт\n";
        } else {
            try {
                cipher.setKeyFromHex(keyInput);
                if (cipher.getKeyAsHex().length()/2 < text.length()) {
                    std::cout << "Предупреждение: ключ короче текста, будет обрезано\n";
                    text = text.substr(0, cipher.getKeyAsHex().length()/2);
                }
            } catch (const std::exception& e) {
                std::cout << "Ошибка: " << e.what() << "\n";
                return;
            }
        }
        
        try {
            std::string encryptedHex = cipher.encryptText(text);
            std::cout << "Зашифрованный текст (HEX): " << encryptedHex << "\n";
            std::cout << "Сохраните ключ для дешифрования: " << cipher.getKeyAsHex() << "\n";
            std::cout << "\nВажно! Для дешифрования используйте HEX значение из поля выше.\n";
        } catch (const std::exception& e) {
            std::cout << "Ошибка: " << e.what() << "\n";
        }
        
    } else {
        std::cout << "Введите зашифрованный текст (HEX): ";
        std::getline(std::cin, text);
        if (text.empty()) {
            std::cout << "Ошибка: текст не может быть пустым\n";
            return;
        }
        
        //удаляем пробелы из HEX строки
        text.erase(std::remove_if(text.begin(), text.end(), 
            [](unsigned char c) { return std::isspace(c); }), text.end());
        std::cout << "Введите ключ (HEX): ";
        std::getline(std::cin, keyInput);
        if (keyInput.empty()) {
            std::cout << "Ошибка: ключ не может быть пустым\n";
            return;
        }
        
        try {
            cipher.setKeyFromHex(keyInput);
            
            std::string decryptedHex = cipher.decryptTextHex(text);
            std::cout << "Расшифрованный текст (HEX): " << decryptedHex << "\n";
            std::string decryptedUtf8 = cipher.decryptTextUtf8(text);
            std::cout << "Расшифрованный текст: " << decryptedUtf8 << "\n";
        } catch (const std::exception& e) {
            std::cout << "Ошибка: " << e.what() << "\n";
        }
    }
}

void processFile(bool encrypt) {
    VernamCipher cipher;
    std::string inputPath, outputPath, keyInput;
    
    std::cout << "\n=== " << (encrypt ? "ШИФРОВАНИЕ" : "ДЕШИФРОВАНИЕ") << " ФАЙЛА ===\n";
    std::cout << "Введите путь к файлу: ";
    std::getline(std::cin, inputPath);
    if (!fs::exists(inputPath)) {
        std::cout << "Ошибка: файл не найден\n";
        return;
    }
    std::cout << "Введите путь для результата (или Enter для автоматического): ";
    std::getline(std::cin, outputPath);
    if (outputPath.empty()) {
        fs::path in(inputPath);
        std::string suffix = encrypt ? "_encrypted" : "_decrypted";
        outputPath = (in.parent_path() / (in.stem().string() + suffix + in.extension().string())).string();
    }
    if (encrypt) {
        std::cout << "Введите ключ (HEX) или Enter для генерации: ";
        std::getline(std::cin, keyInput);
        if (keyInput.empty()) {
            size_t fileSize = fs::file_size(inputPath);
            cipher.generateKey(fileSize);
            std::cout << "Сгенерирован ключ (HEX): " << cipher.getKeyAsHex() << "\n";
            std::cout << "Длина ключа: " << fileSize << " байт\n";
        } else {
            try {
                cipher.setKeyFromHex(keyInput);
                if (cipher.getKeyAsHex().length()/2 < fs::file_size(inputPath)) {
                    std::cout << "Предупреждение: ключ короче файла\n";
                }
            } catch (const std::exception& e) {
                std::cout << "Ошибка: " << e.what() << "\n";
                return;
            }
        }
    } else {
        std::cout << "Введите ключ (HEX): ";
        std::getline(std::cin, keyInput);
        if (keyInput.empty()) {
            std::cout << "Ошибка: ключ не может быть пустым\n";
            return;
        }
        try {
            cipher.setKeyFromHex(keyInput);
            if (cipher.getKeyAsHex().length()/2 < fs::file_size(inputPath)) {
                std::cout << "Ошибка: ключ короче файла\n";
                return;
            }
        } catch (const std::exception& e) {
            std::cout << "Ошибка: " << e.what() << "\n";
            return;
        }
    }
    
    try {
        cipher.processFile(inputPath, outputPath);
        std::cout << "Готово! Результат: " << outputPath << "\n";
    } catch (const std::exception& e) {
        std::cout << "Ошибка: " << e.what() << "\n";
    }
}

void keyGenerator() {
    std::cout << "\n=== ГЕНЕРАТОР КЛЮЧЕЙ ===\n";
    std::cout << "1. Для текста\n";
    std::cout << "2. Для файла\n";
    std::cout << "3. Заданной длины\n";
    std::cout << "Выберите: ";
    
    int choice;
    std::cin >> choice;
    std::cin.ignore();
    
    VernamCipher cipher;
    
    switch (choice) {
        case 1: {
            std::cout << "Введите текст: ";
            std::string text;
            std::getline(std::cin, text);
            if (!text.empty()) {
                cipher.generateKey(text.length());
                std::cout << "Ключ (HEX): " << cipher.getKeyAsHex() << "\n";
                std::cout << "Длина ключа: " << text.length() << " байт\n";
            }
            break;
        }
        case 2: {
            std::cout << "Введите путь к файлу: ";
            std::string path;
            std::getline(std::cin, path);
            if (fs::exists(path)) {
                size_t size = fs::file_size(path);
                cipher.generateKey(size);
                std::cout << "Ключ (HEX): " << cipher.getKeyAsHex() << "\n";
                std::cout << "Длина ключа: " << size << " байт\n";
            } else {
                std::cout << "Файл не найден\n";
            }
            break;
        }
        case 3: {
            std::cout << "Введите длину: ";
            size_t len;
            std::cin >> len;
            if (len > 0) {
                cipher.generateKey(len);
                std::cout << "Ключ (HEX): " << cipher.getKeyAsHex() << "\n";
                std::cout << "Длина ключа: " << len << " байт\n";
            } else {
                std::cout << "Некорректная длина\n";
            }
            break;
        }
        default:
            std::cout << "Неверный выбор\n";
    }
}

int main() {
    setlocale(LC_ALL, "ru_RU.UTF-8");
    std::locale::global(std::locale("ru_RU.UTF-8"));
    
    while (true) {
        std::cout << "\n╔═══════════════════════════════════╗\n";
        std::cout << "║       ШИФР ВЕРНАМА (XOR)          ║\n";
        std::cout << "╠═══════════════════════════════════╣\n";
        std::cout << "║  1. Шифровать текст               ║\n";
        std::cout << "║  2. Дешифровать текст             ║\n";
        std::cout << "║  3. Шифровать файл                ║\n";
        std::cout << "║  4. Дешифровать файл              ║\n";
        std::cout << "║  5. Генератор ключей              ║\n";
        std::cout << "║  0. Выход                         ║\n";
        std::cout << "╚═══════════════════════════════════╝\n";
        std::cout << "Выберите: ";
        
        int choice;
        std::cin >> choice;
        std::cin.ignore(); //\n
        
        switch (choice) {
            case 1: processText(true); break;
            case 2: processText(false); break;
            case 3: processFile(true); break;
            case 4: processFile(false); break;
            case 5: keyGenerator(); break;
            case 0: 
                std::cout << "До свидания!\n";
                return 0;
            default:
                std::cout << "Неверный выбор\n";
        }
        std::cout << "\nНажмите Enter...";
        std::cin.get();
    }
}