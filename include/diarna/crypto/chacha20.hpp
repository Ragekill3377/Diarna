#pragma once
#include <diarna/compiler_port.hpp>
#include <cstdint>
#include <vector>
#include <array>
#include <cstring>
#include <span>

namespace diarna::crypto {

class ChaCha20Poly1305 {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 12;
    static constexpr size_t TAG_SIZE = 16;

    ChaCha20Poly1305(std::span<const uint8_t, KEY_SIZE> key);

    std::vector<uint8_t> encrypt(std::span<const uint8_t> plaintext,
                                  std::span<const uint8_t, NONCE_SIZE> nonce,
                                  std::span<const uint8_t> aad = {});
    bool decrypt(std::span<const uint8_t> ciphertext_tag,
                 std::span<const uint8_t, NONCE_SIZE> nonce,
                 std::vector<uint8_t>& out_plaintext,
                 std::span<const uint8_t> aad = {});

    static std::array<uint8_t, KEY_SIZE> generate_key();

private:
    std::array<uint8_t, KEY_SIZE> key_;

    static void chacha20_block(const uint32_t* key_u32, uint32_t counter,
                                const uint32_t* nonce_u32, uint32_t* out);
    static void chacha20_encrypt(const uint8_t* key, uint32_t counter,
                                  const uint8_t* nonce, const uint8_t* input,
                                  uint8_t* output, size_t len);
    static void poly1305_mac(const uint8_t* key, const uint8_t* data,
                              size_t len, uint8_t* mac);
    static void poly1305_key_gen(const uint8_t* key, const uint8_t* nonce,
                                  uint8_t* poly_key);
    static void pad16(std::vector<uint8_t>& buf);
};

} // namespace diarna::crypto
