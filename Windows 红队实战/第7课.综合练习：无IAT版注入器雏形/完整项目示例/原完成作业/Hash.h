#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

class NHash32 {
public:
    static constexpr uint32_t kDefaultSeed = 0x12345678u;

    static uint32_t hash(const void* data, size_t len,
                         uint32_t seed = kDefaultSeed) noexcept {
        if (data == nullptr) {
            // 保证 p 为 null 时长度也为 0，避免后续 p+offset 的 UB
            return hashImpl(nullptr, 0, seed);
        }
        return hashImpl(static_cast<const uint8_t*>(data), len, seed);
    }

    static uint32_t hash(std::string_view sv,
                         uint32_t seed = kDefaultSeed) noexcept {
        return hashImpl(reinterpret_cast<const uint8_t*>(sv.data()),
                        sv.size(), seed);
    }

    static uint32_t hash(const char* str,
                         uint32_t seed = kDefaultSeed) noexcept {
        if (str == nullptr) return 0;
        return hashImpl(reinterpret_cast<const uint8_t*>(str),
                        std::strlen(str), seed);
    }

private:

    static inline uint32_t rotl32(uint32_t x, int r) noexcept {
        r &= 31;
        return (x << r) | (x >> ((32 - r) & 31));
    }

    static inline uint32_t rd32le(const uint8_t* p) noexcept {
        return  static_cast<uint32_t>(p[0])
             | (static_cast<uint32_t>(p[1]) << 8)
             | (static_cast<uint32_t>(p[2]) << 16)
             | (static_cast<uint32_t>(p[3]) << 24);
    }

    static uint32_t hashImpl(const uint8_t* p, size_t len,
                             uint32_t seed) noexcept {
        uint32_t h = seed ^ (static_cast<uint32_t>(len) * 0x9E3779B9u);

        const uint32_t C1 = 0x7F4A7C15u;
        const uint32_t C2 = 0x8F1BBCDCu;
        const uint32_t C3 = 0xCC6699B3u;
        const uint32_t C4 = 0x5BD1E995u;
        const uint32_t C5 = 0x1B56C4E9u;
        const uint32_t C6 = 0xA5B4C3D2u;

        size_t n = len >> 2;
        if (p != nullptr) {
            for (size_t i = 0; i < n; ++i) {
                uint32_t k = rd32le(p + i * 4);

                k ^= k >> 15;
                k *= C1;
                k ^= k >> 12;
                k *= C2;
                k ^= k >> 16;

                h ^= k;
                h = rotl32(h, 7);
                h = h * 3 + C3;
            }

            if (len & 3) {
                const uint8_t* tail = p + (n << 2);
                uint32_t k = 0;
                switch (len & 3) {
                    case 3:
                        k ^= static_cast<uint32_t>(tail[2]) << 16;
                        [[fallthrough]];
                    case 2:
                        k ^= static_cast<uint32_t>(tail[1]) << 8;
                        [[fallthrough]];
                    case 1:
                        k ^= static_cast<uint32_t>(tail[0]);
                        k ^= k >> 15;
                        k *= C1;
                        k ^= k >> 12;
                        k *= C2;
                        h ^= k;
                        break;
                    default:
                        break;
                }
            }
        }

        h ^= static_cast<uint32_t>(len);
        h ^= h >> 16;
        h *= C4;
        h ^= h >> 13;
        h *= C5;
        h ^= h >> 16;
        h *= C6;
        h ^= h >> 15;

        return h;
    }
};