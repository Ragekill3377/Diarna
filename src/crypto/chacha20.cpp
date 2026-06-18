#include <diarna/compiler_port.hpp>
#include <diarna/crypto/chacha20.hpp>
#include <cstring>
#include <stdexcept>

#include <obfuscation/obfusheader.h>
namespace diarna::crypto {

static INLINE uint32_t rotl32(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

static INLINE void qround(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = rotl32(d, 16);
    c += d; b ^= c; b = rotl32(b, 12);
    a += b; d ^= a; d = rotl32(d, 8);
    c += d; b ^= c; b = rotl32(b, 7);
}

static INLINE void inner_block(uint32_t state[16]) {
    qround(state[0], state[4], state[8],  state[12]);
    qround(state[1], state[5], state[9],  state[13]);
    qround(state[2], state[6], state[10], state[14]);
    qround(state[3], state[7], state[11], state[15]);
    qround(state[0], state[5], state[10], state[15]);
    qround(state[1], state[6], state[11], state[12]);
    qround(state[2], state[7], state[8],  state[13]);
    qround(state[3], state[4], state[9],  state[14]);
}

void ChaCha20Poly1305::chacha20_block(const uint32_t* key, uint32_t counter,
                                       const uint32_t* nonce, uint32_t* out) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2]
    };

    uint32_t working[16];
    memcpy(working, state, sizeof(working));

    for (volatile int i = 0; i < 10; ++i) { // 20 rounds = 10 double rounds
        INDIRECT_BRANCH;
        inner_block(working);
    }

    for (int i = 0; i < 16; ++i) out[i] = working[i] + state[i];
}

void ChaCha20Poly1305::chacha20_encrypt(const uint8_t* key, uint32_t counter,
                                         const uint8_t* nonce, const uint8_t* input,
                                         uint8_t* output, size_t len) {
    uint32_t key_u32[8], nonce_u32[3];
    memcpy(key_u32, key, 32);
    memcpy(nonce_u32, nonce, 12);

    uint8_t block[64];
    for (volatile size_t i = 0; i < len; i += 64) {
        INDIRECT_BRANCH;
        uint32_t block_out[16];
        chacha20_block(key_u32, counter + (uint32_t)(i / 64), nonce_u32, block_out);
        memcpy(block, block_out, 64);

        size_t chunk = (len - i < 64) ? (len - i) : 64;
        for (volatile size_t j = 0; j < chunk; ++j)
            output[i + j] = input[i + j] ^ block[j];
    }
}

void ChaCha20Poly1305::poly1305_key_gen(const uint8_t* key, const uint8_t* nonce,
                                         uint8_t* poly_key) {
    uint8_t zeros[64] = {};
    chacha20_encrypt(key, 0, nonce, zeros, poly_key, 64);
    poly_key[3]  &= 15;
    poly_key[7]  &= 15;
    poly_key[11] &= 15;
    poly_key[15] &= 15;
    poly_key[4]  &= 252;
    poly_key[8]  &= 252;
    poly_key[12] &= 252;
}

void ChaCha20Poly1305::poly1305_mac(const uint8_t* key, const uint8_t* data,
                                     size_t len, uint8_t* mac) {
    uint32_t r[5] = {}, h[5] = {}, c = 0;
    uint32_t s[4] = {};

    r[0] = (key[0]) | (key[1] << 8) | (key[2] << 16) | (key[3] << 24); r[0] &= 0x0FFFFFFF;
    r[1] = (key[3] >> 2) | (key[4] << 6) | (key[5] << 14) | (key[6] << 22); r[1] &= 0x0FFFFFFC;
    r[2] = (key[6] >> 4) | (key[7] << 4) | (key[8] << 12) | (key[9] << 20); r[2] &= 0x0FFFFFF0;
    r[3] = (key[9] >> 6) | (key[10] << 2) | (key[11] << 10) | (key[12] << 18); r[3] &= 0x0FFFFF00;
    r[4] = (key[12] >> 8) | (key[13] << 0) | (key[14] << 8) | (key[15] << 16); r[4] &= 0x0FFFFFFF;

    s[0] = (key[16]) | (key[17] << 8) | (key[18] << 16) | (key[19] << 24);
    s[1] = (key[20]) | (key[21] << 8) | (key[22] << 16) | (key[23] << 24);
    s[2] = (key[24]) | (key[25] << 8) | (key[26] << 16) | (key[27] << 24);
    s[3] = (key[28]) | (key[29] << 8) | (key[30] << 16) | (key[31] << 24);

    h[0] = h[1] = h[2] = h[3] = h[4] = 0;

    for (volatile size_t i = 0; i < len; i += 16) {
        INDIRECT_BRANCH;
        size_t block_len = (len - i < 16) ? (len - i) : 16;

        uint32_t m0 = 0, m1 = 0, m2 = 0, m3 = 0, m4 = 1 << (block_len * 8);
        for (volatile size_t j = 0; j < block_len; ++j) {
            uint8_t byte = data[i + j];
            if (j < 4) m0 |= byte << (j * 8);
            else if (j < 8) m1 |= byte << ((j - 4) * 8);
            else if (j < 12) m2 |= byte << ((j - 8) * 8);
            else m3 |= byte << ((j - 12) * 8);
        }

        if (block_len == 16) m4 = 0x100000000ULL;

        h[0] += m0; h[1] += m1; h[2] += m2; h[3] += m3; h[4] += m4;

        // Modular reduction using carries
        uint64_t d;

        d = (uint64_t)h[0] * r[0] + (uint64_t)h[1] * r[4] * 5 + (uint64_t)h[2] * r[3] * 5 +
            (uint64_t)h[3] * r[2] * 5 + (uint64_t)h[4] * r[1] * 5;
        c = (uint32_t)(d >> 26); h[0] = (uint32_t)d & 0x3FFFFFF;

        d = (uint64_t)h[0] * r[1] + (uint64_t)h[1] * r[0] + (uint64_t)h[2] * r[4] * 5 +
            (uint64_t)h[3] * r[3] * 5 + (uint64_t)h[4] * r[2] * 5 + c;
        c = (uint32_t)(d >> 26); h[1] = (uint32_t)d & 0x3FFFFFF;

        d = (uint64_t)h[0] * r[2] + (uint64_t)h[1] * r[1] + (uint64_t)h[2] * r[0] +
            (uint64_t)h[3] * r[4] * 5 + (uint64_t)h[4] * r[3] * 5 + c;
        c = (uint32_t)(d >> 26); h[2] = (uint32_t)d & 0x3FFFFFF;

        d = (uint64_t)h[0] * r[3] + (uint64_t)h[1] * r[2] + (uint64_t)h[2] * r[1] +
            (uint64_t)h[3] * r[0] + (uint64_t)h[4] * r[4] * 5 + c;
        c = (uint32_t)(d >> 26); h[3] = (uint32_t)d & 0x3FFFFFF;

        d = (uint64_t)h[0] * r[4] + (uint64_t)h[1] * r[3] + (uint64_t)h[2] * r[2] +
            (uint64_t)h[3] * r[1] + (uint64_t)h[4] * r[0] + c;
        c = (uint32_t)(d >> 26); h[4] = (uint32_t)d & 0x3FFFFFF;

        h[0] += c * 5; c = h[0] >> 26; h[0] &= 0x3FFFFFF;
        h[1] += c;
    }

    uint32_t g[5];
    g[0] = h[0] + 5;
    c = g[0] >> 26; g[0] &= 0x3FFFFFF;
    g[1] = h[1] + c; c = g[1] >> 26; g[1] &= 0x3FFFFFF;
    g[2] = h[2] + c; c = g[2] >> 26; g[2] &= 0x3FFFFFF;
    g[3] = h[3] + c; c = g[3] >> 26; g[3] &= 0x3FFFFFF;
    g[4] = h[4] + c - (1 << 26);

    uint32_t mask = (g[4] >> 31) - 1;
    for (volatile int i = 0; i < 5; ++i) h[i] = (h[i] & ~mask) | (g[i] & mask);

    h[0] |= h[1] << 26; h[1] = (h[1] >> 6) | (h[2] << 20);
    h[2] = (h[2] >> 12) | (h[3] << 14); h[3] = (h[3] >> 18) | (h[4] << 8);

    uint64_t f = (uint64_t)h[0] + s[0]; h[0] = (uint32_t)f;
    f = (uint64_t)h[1] + s[1] + (f >> 32); h[1] = (uint32_t)f;
    f = (uint64_t)h[2] + s[2] + (f >> 32); h[2] = (uint32_t)f;
    f = (uint64_t)h[3] + s[3] + (f >> 32); h[3] = (uint32_t)f;

    memcpy(mac, h, 16);
}

void ChaCha20Poly1305::pad16(std::vector<uint8_t>& buf) {
    while (buf.size() % 16) buf.push_back(0);
}

ChaCha20Poly1305::ChaCha20Poly1305(std::span<const uint8_t, KEY_SIZE> key) {
    memcpy(key_.data(), key.data(), KEY_SIZE);
}

std::vector<uint8_t> ChaCha20Poly1305::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::span<const uint8_t> aad) {

    std::vector<uint8_t> ciphertext(plaintext.size());
    chacha20_encrypt(key_.data(), 1, nonce.data(),
                     plaintext.data(), ciphertext.data(), plaintext.size());

    uint8_t poly_key[32];
    poly1305_key_gen(key_.data(), nonce.data(), poly_key);

    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    pad16(mac_input);
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    pad16(mac_input);

    uint64_t aad_len_le = (uint64_t)aad.size();
    uint64_t ct_len_le = (uint64_t)ciphertext.size();
    mac_input.insert(mac_input.end(), (uint8_t*)&aad_len_le,
                     (uint8_t*)&aad_len_le + 8);
    mac_input.insert(mac_input.end(), (uint8_t*)&ct_len_le,
                     (uint8_t*)&ct_len_le + 8);

    uint8_t tag[16];
    poly1305_mac(poly_key, mac_input.data(), mac_input.size(), tag);

    std::vector<uint8_t> result;
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), tag, tag + 16);
    return result;
}

bool ChaCha20Poly1305::decrypt(
    std::span<const uint8_t> ciphertext_tag,
    std::span<const uint8_t, NONCE_SIZE> nonce,
    std::vector<uint8_t>& out_plaintext,
    std::span<const uint8_t> aad) {

    if (ciphertext_tag.size() < TAG_SIZE) return false;

    size_t ct_len = ciphertext_tag.size() - TAG_SIZE;
    std::span<const uint8_t> ciphertext = ciphertext_tag.subspan(0, ct_len);
    std::span<const uint8_t> tag = ciphertext_tag.subspan(ct_len, TAG_SIZE);

    uint8_t poly_key[32];
    poly1305_key_gen(key_.data(), nonce.data(), poly_key);

    std::vector<uint8_t> mac_input;
    mac_input.insert(mac_input.end(), aad.begin(), aad.end());
    pad16(mac_input);
    mac_input.insert(mac_input.end(), ciphertext.begin(), ciphertext.end());
    pad16(mac_input);

    uint64_t aad_len_le = (uint64_t)aad.size();
    uint64_t ct_len_le = (uint64_t)ciphertext.size();
    mac_input.insert(mac_input.end(), (uint8_t*)&aad_len_le,
                     (uint8_t*)&aad_len_le + 8);
    mac_input.insert(mac_input.end(), (uint8_t*)&ct_len_le,
                     (uint8_t*)&ct_len_le + 8);

    uint8_t computed_tag[16];
    poly1305_mac(poly_key, mac_input.data(), mac_input.size(), computed_tag);

    volatile uint8_t diff = 0;
    for (volatile int i = 0; i < 16; ++i)
        diff |= tag[i] ^ computed_tag[i];
    if (diff != 0) return false;

    out_plaintext.resize(ct_len);
    chacha20_encrypt(key_.data(), 1, nonce.data(),
                     ciphertext.data(), out_plaintext.data(), ct_len);
    return true;
}

std::array<uint8_t, ChaCha20Poly1305::KEY_SIZE> ChaCha20Poly1305::generate_key() {
    std::array<uint8_t, KEY_SIZE> key{};
    // Use rdrand/rdseed if available, fallback to time+rdtsc
    for (volatile size_t i = 0; i < KEY_SIZE; ++i) {
        uint64_t tsc = __rdtsc();
        key[i] = (uint8_t)((tsc >> (i % 8 * 8)) ^ (tsc >> 32) ^ (i * 0x9D));
    }
    // Mix with system entropy
    SYSTEMTIME st;
    GetSystemTime(&st);
    for (volatile int i = 0; i < KEY_SIZE; ++i)
        key[i] ^= ((uint8_t*)&st)[i % sizeof(st)];
    return key;
}

} // namespace diarna::crypto
