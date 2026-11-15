// Independent C++ compatibility oracle for the OpenSSE Diana primitive flow.
// Semantics pinned to OpenSSE/opensse-schemes master tree
// 084e80bb1223560d30024b7d20b165e3dfc64426 and crypto-tk submodule
// 60b0db0bbdf2b2c0257cc11e3f06b10ff90636a5.
// Uses OpenSSL primitives to independently reproduce the upstream construction;
// this is not the upstream OpenSSE executable or a formal proof of conformance.
#include <openssl/evp.h>
#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

Bytes blake2b512(const Bytes& message) {
  Bytes output(64);
  unsigned int written = 0;
  EVP_MD_CTX* context = EVP_MD_CTX_new();
  if (!context) throw std::runtime_error("EVP_MD_CTX_new failed");
  if (EVP_DigestInit_ex(context, EVP_blake2b512(), nullptr) != 1 ||
      EVP_DigestUpdate(context, message.data(), message.size()) != 1 ||
      EVP_DigestFinal_ex(context, output.data(), &written) != 1) {
    EVP_MD_CTX_free(context);
    throw std::runtime_error("BLAKE2b failed");
  }
  EVP_MD_CTX_free(context);
  output.resize(written);
  return output;
}

// OpenSSE crypto-tk's HMac<Hash> is standard HMAC with a 128-byte BLAKE2b
// block size and 64-byte digest, then the Diana PRF truncates to output size.
Bytes hmacBlake2b(const Bytes& key, const Bytes& message, size_t outputLength) {
  Bytes padded(128, 0);
  std::copy(key.begin(), key.end(), padded.begin());
  Bytes inner(128 + message.size());
  for (size_t i = 0; i < 128; ++i) inner[i] = padded[i] ^ 0x36;
  std::copy(message.begin(), message.end(), inner.begin() + 128);
  const Bytes innerDigest = blake2b512(inner);
  Bytes outer(128 + innerDigest.size());
  for (size_t i = 0; i < 128; ++i) outer[i] = padded[i] ^ 0x5c;
  std::copy(innerDigest.begin(), innerDigest.end(), outer.begin() + 128);
  Bytes result = blake2b512(outer);
  result.resize(outputLength);
  return result;
}

// OpenSSE crypto-tk uses original ChaCha20 with an all-zero 8-byte nonce,
// 64-bit block counter, and byte offsets into the resulting stream.
Bytes chacha20(const Bytes& key, size_t offset, size_t length) {
  const uint64_t block = offset / 64;
  const size_t withinBlock = offset % 64;
  Bytes input(withinBlock + length, 0), output(input.size());
  uint8_t iv[16] = {};
  for (int i = 0; i < 8; ++i) iv[i] = static_cast<uint8_t>(block >> (8 * i));
  EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
  if (!context) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  int written = 0, finalWritten = 0;
  if (EVP_EncryptInit_ex(context, EVP_chacha20(), nullptr, key.data(), iv) != 1 ||
      EVP_EncryptUpdate(context, output.data(), &written, input.data(),
                        static_cast<int>(input.size())) != 1 ||
      EVP_EncryptFinal_ex(context, output.data() + written, &finalWritten) != 1) {
    EVP_CIPHER_CTX_free(context);
    throw std::runtime_error("ChaCha20 failed");
  }
  EVP_CIPHER_CTX_free(context);
  return Bytes(output.begin() + withinBlock,
               output.begin() + withinBlock + length);
}

Bytes deriveBranch(const Bytes& key, int branch) {
  return chacha20(key, static_cast<size_t>(branch) * 32, 32);
}

Bytes evaluateLeaf(Bytes nodeKey, uint64_t leaf) {
  for (int bit = 46; bit >= 0; --bit) {
    const int branch = static_cast<int>((leaf >> bit) & 1U);
    if (bit == 0) return chacha20(nodeKey, static_cast<size_t>(branch) * 32, 32);
    nodeKey = deriveBranch(nodeKey, branch);
  }
  throw std::runtime_error("unreachable leaf evaluation");
}

std::string hex(const Bytes& bytes) {
  std::ostringstream out;
  for (uint8_t byte : bytes)
    out << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<unsigned int>(byte);
  return out.str();
}

Bytes repeated(uint8_t value) { return Bytes(32, value); }

int main() {
  const std::string keyword = "cloud";
  const Bytes keywordDigest = blake2b512(Bytes(keyword.begin(), keyword.end()));
  const Bytes keywordIndex(keywordDigest.begin(), keywordDigest.begin() + 16);
  const Bytes rootKey = hmacBlake2b(repeated(0x11), keywordIndex, 32);
  const Bytes keywordToken = hmacBlake2b(repeated(0x22), keywordIndex, 32);

  std::cout << "{\n"
            << "  \"keyword\": \"" << keyword << "\",\n"
            << "  \"keywordIndex\": \"" << hex(keywordIndex) << "\",\n"
            << "  \"rootKey\": \"" << hex(rootKey) << "\",\n"
            << "  \"keywordToken\": \"" << hex(keywordToken) << "\",\n"
            << "  \"leaves\": [\n";
  for (uint64_t leaf = 0; leaf < 3; ++leaf) {
    const Bytes leafKey = evaluateLeaf(rootKey, leaf);
    const Bytes stream = chacha20(leafKey, 0, 24);
    const Bytes token(stream.begin(), stream.begin() + 16);
    const Bytes mask(stream.begin() + 16, stream.end());
    std::cout << "    { \"leaf\": " << leaf
              << ", \"leafKey\": \"" << hex(leafKey)
              << "\", \"updateToken\": \"" << hex(token)
              << "\", \"mask\": \"" << hex(mask) << "\" }"
              << (leaf == 2 ? "\n" : ",\n");
  }
  std::cout << "  ]\n}\n";
}
