#include "HexUtils.h"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {
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
        throw std::runtime_error("HEX-строка содержит недопустимый символ");
    }
}

std::string HexUtils::toHex(const std::vector<unsigned char>& data) {
    std::ostringstream stream;
    stream << std::uppercase << std::hex << std::setfill('0');

    for (unsigned char byte : data) {
        stream << std::setw(2) << static_cast<int>(byte);
    }

    return stream.str();
}

std::vector<unsigned char> HexUtils::fromHex(const std::string& hex_text) {
    std::string clean;
    for (char ch : hex_text) {
        if (!std::isspace(static_cast<unsigned char>(ch))) {
            clean.push_back(ch);
        }
    }

    if (clean.empty()) {
        return {};
    }

    if (clean.size() % 2 != 0) {
        throw std::runtime_error("HEX-строка должна содержать четное количество символов");
    }

    std::vector<unsigned char> result;
    result.reserve(clean.size() / 2);

    for (std::size_t i = 0; i < clean.size(); i += 2) {
        int high = hexValue(clean[i]);
        int low = hexValue(clean[i + 1]);
        result.push_back(static_cast<unsigned char>((high << 4) | low));
    }

    return result;
}
