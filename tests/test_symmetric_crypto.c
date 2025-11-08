// tests/test_symmetric_crypto.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// --- 测试辅助宏 ---
#define TEST_ASSERT(condition, message) do { \
    if (!(condition)) { \
        fprintf(stderr, "TEST FAILED: %s (%s:%d)\n", message, __FILE__, __LINE__); \
        return -1; \
    } \
} while(0)

// --- 测试用例 ---

/**
 * @brief 测试 AEAD 加密的正常往返流程 (加密 -> 解密)
 */
int test_aead_roundtrip() {
    printf("  Running test: test_aead_roundtrip...\n");
    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "This is a secret message for the AEAD roundtrip test.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    TEST_ASSERT(ciphertext != NULL, "malloc for ciphertext failed");
    unsigned long long ciphertext_len;

    // 加密
    int res_encrypt = encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key);
    TEST_ASSERT(res_encrypt == 0, "encrypt_symmetric_aead should succeed");
    TEST_ASSERT(ciphertext_len > message_len, "Ciphertext length should be greater than message length");

    // 解密
    unsigned char* decrypted_message = malloc(message_len + 1);
    TEST_ASSERT(decrypted_message != NULL, "malloc for decrypted_message failed");
    unsigned long long decrypted_message_len;

    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key);
    TEST_ASSERT(res_decrypt == 0, "decrypt_symmetric_aead should succeed");
    TEST_ASSERT(decrypted_message_len == message_len, "Decrypted length should match original length");
    
    decrypted_message[decrypted_message_len] = '\0';
    TEST_ASSERT(strcmp((const char*)decrypted_message, message) == 0, "Decrypted message must match original");

    free(ciphertext);
    free(decrypted_message);
    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试使用错误的密钥解密，预期失败
 */
int test_aead_wrong_key() {
    printf("  Running test: test_aead_wrong_key...\n");
    unsigned char key_a[SESSION_KEY_BYTES];
    unsigned char key_b[SESSION_KEY_BYTES];
    randombytes_buf(key_a, sizeof(key_a));
    randombytes_buf(key_b, sizeof(key_b));
    assert(sodium_memcmp(key_a, key_b, sizeof(key_a)) != 0);

    const char* message = "A message encrypted with key A.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    // 使用密钥 A 加密
    encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key_a);
    
    // 尝试使用密钥 B 解密
    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_message_len;
    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key_b);
    TEST_ASSERT(res_decrypt == -1, "Decryption with wrong key must fail");

    free(ciphertext);
    free(decrypted_message);
    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试密文被篡改后，解密应失败
 */
int test_aead_tampered_ciphertext() {
    printf("  Running test: test_aead_tampered_ciphertext...\n");
    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "Untampered data.";
    size_t message_len = strlen(message);
    
    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key);

    // 篡改密文的一个字节 (跳过 nonce 部分)
    size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    TEST_ASSERT(ciphertext_len > nonce_len, "Ciphertext must be longer than nonce");
    ciphertext[nonce_len] ^= 0x01; // Flip a bit

    // 尝试解密
    unsigned char* decrypted_message = malloc(message_len);
    unsigned long long decrypted_message_len;
    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key);
    TEST_ASSERT(res_decrypt == -1, "Decryption of tampered ciphertext must fail");

    free(ciphertext);
    free(decrypted_message);
    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试加密一个空消息
 */
int test_aead_empty_message() {
    printf("  Running test: test_aead_empty_message...\n");
    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "";
    size_t message_len = 0;

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    unsigned char* ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    int res_encrypt = encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key);
    TEST_ASSERT(res_encrypt == 0, "Encryption of empty message should succeed");

    unsigned char* decrypted_message = malloc(1); // Malloc at least 1 for null terminator
    unsigned long long decrypted_message_len;

    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key);
    TEST_ASSERT(res_decrypt == 0, "Decryption of empty message should succeed");
    TEST_ASSERT(decrypted_message_len == 0, "Decrypted length for empty message must be 0");

    free(ciphertext);
    free(decrypted_message);
    printf("    ... PASSED\n");
    return 0;
}


int main() {
    if (crypto_client_init() != 0) {
        fprintf(stderr, "Fatal: crypto_client_init failed\n");
        return 1;
    }

    printf("--- Running Symmetric Cryptography Test Suite ---\n");
    if (test_aead_roundtrip() != 0) return 1;
    if (test_aead_wrong_key() != 0) return 1;
    if (test_aead_tampered_ciphertext() != 0) return 1;
    if (test_aead_empty_message() != 0) return 1;

    printf("--- Symmetric Cryptography Test Suite: ALL PASSED ---\n\n");
    return 0;
}