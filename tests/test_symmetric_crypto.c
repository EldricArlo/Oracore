// tests/test_symmetric_crypto.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// [委员会修改] 移除了原有的 TEST_ASSERT 宏。

// --- 测试用例 ---

/**
 * @brief 测试 AEAD 加密的正常往返流程 (加密 -> 解密)
 */
int test_aead_roundtrip() {
    printf("  Running test: test_aead_roundtrip...\n");
    int ret = -1; // [修改]
    unsigned char* ciphertext = NULL;
    unsigned char* decrypted_message = NULL;

    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "This is a secret message for the AEAD roundtrip test.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    ciphertext = malloc(ciphertext_buf_len);
    if (!ciphertext) {
        fprintf(stderr, "TEST FAILED: malloc for ciphertext failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    unsigned long long ciphertext_len;

    // 加密
    if (encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key) != 0) {
        fprintf(stderr, "TEST FAILED: encrypt_symmetric_aead should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (ciphertext_len <= message_len) {
        fprintf(stderr, "TEST FAILED: Ciphertext length should be greater than message length (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // 解密
    decrypted_message = malloc(message_len + 1);
    if (!decrypted_message) {
        fprintf(stderr, "TEST FAILED: malloc for decrypted_message failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    unsigned long long decrypted_message_len;

    if (decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key) != 0) {
        fprintf(stderr, "TEST FAILED: decrypt_symmetric_aead should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (decrypted_message_len != message_len) {
        fprintf(stderr, "TEST FAILED: Decrypted length should match original length (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    decrypted_message[decrypted_message_len] = '\0';
    if (strcmp((const char*)decrypted_message, message) != 0) {
        fprintf(stderr, "TEST FAILED: Decrypted message must match original (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ciphertext);
    free(decrypted_message);
    return ret;
}

/**
 * @brief 测试使用错误的密钥解密，预期失败
 */
int test_aead_wrong_key() {
    printf("  Running test: test_aead_wrong_key...\n");
    int ret = -1; // [修改]
    unsigned char* ciphertext = NULL;
    unsigned char* decrypted_message = NULL;
    // [委员会修正] 添加缺失的变量声明
    unsigned long long decrypted_message_len;

    unsigned char key_a[SESSION_KEY_BYTES];
    unsigned char key_b[SESSION_KEY_BYTES];
    randombytes_buf(key_a, sizeof(key_a));
    randombytes_buf(key_b, sizeof(key_b));
    assert(sodium_memcmp(key_a, key_b, sizeof(key_a)) != 0);

    const char* message = "A message encrypted with key A.";
    size_t message_len = strlen(message);

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    ciphertext = malloc(ciphertext_buf_len);
    unsigned long long ciphertext_len;

    // 使用密钥 A 加密
    encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key_a);
    
    // 尝试使用密钥 B 解密
    decrypted_message = malloc(message_len);
    if (!decrypted_message) goto cleanup;

    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key_b);
    if (res_decrypt != -1) {
        fprintf(stderr, "TEST FAILED: Decryption with wrong key must fail (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ciphertext);
    free(decrypted_message);
    return ret;
}

/**
 * @brief 测试密文被篡改后，解密应失败
 */
int test_aead_tampered_ciphertext() {
    printf("  Running test: test_aead_tampered_ciphertext...\n");
    int ret = -1; // [修改]
    unsigned char* ciphertext = NULL;
    unsigned char* decrypted_message = NULL;

    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "Untampered data.";
    size_t message_len = strlen(message);
    
    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    ciphertext = malloc(ciphertext_buf_len);
    if (!ciphertext) goto cleanup;
    unsigned long long ciphertext_len;

    encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key);

    // 篡改密文的一个字节 (跳过 nonce 部分)
    size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    if (ciphertext_len <= nonce_len) {
        fprintf(stderr, "TEST FAILED: Ciphertext must be longer than nonce (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    ciphertext[nonce_len] ^= 0x01; // Flip a bit

    // 尝试解密
    decrypted_message = malloc(message_len);
    if (!decrypted_message) goto cleanup;
    unsigned long long decrypted_message_len;

    int res_decrypt = decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key);
    if (res_decrypt != -1) {
        fprintf(stderr, "TEST FAILED: Decryption of tampered ciphertext must fail (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ciphertext);
    free(decrypted_message);
    return ret;
}

/**
 * @brief 测试加密一个空消息
 */
int test_aead_empty_message() {
    printf("  Running test: test_aead_empty_message...\n");
    int ret = -1; // [修改]
    unsigned char* ciphertext = NULL;
    unsigned char* decrypted_message = NULL;

    unsigned char key[SESSION_KEY_BYTES];
    randombytes_buf(key, sizeof(key));

    const char* message = "";
    size_t message_len = 0;

    size_t ciphertext_buf_len = message_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    ciphertext = malloc(ciphertext_buf_len);
    if (!ciphertext) goto cleanup;
    unsigned long long ciphertext_len;

    if (encrypt_symmetric_aead(ciphertext, &ciphertext_len, (const unsigned char*)message, message_len, key) != 0) {
        fprintf(stderr, "TEST FAILED: Encryption of empty message should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    decrypted_message = malloc(1); // Malloc at least 1 for null terminator
    if (!decrypted_message) goto cleanup;
    unsigned long long decrypted_message_len;

    if (decrypt_symmetric_aead(decrypted_message, &decrypted_message_len, ciphertext, ciphertext_len, key) != 0) {
        fprintf(stderr, "TEST FAILED: Decryption of empty message should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (decrypted_message_len != 0) {
        fprintf(stderr, "TEST FAILED: Decrypted length for empty message must be 0 (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free(ciphertext);
    free(decrypted_message);
    return ret;
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