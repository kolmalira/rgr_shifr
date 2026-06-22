#ifndef HEX_UTILS_H
#define HEX_UTILS_H

#include <string>
#include <vector>

namespace HexUtils {
    std::string toHex(const std::vector<unsigned char>& data);
    std::vector<unsigned char> fromHex(const std::string& hex_text);
}

#endif
