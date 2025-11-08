// tests/test_asymmetric_crypto.c

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
 * @brief 测试密钥对的生成与释放
 */
int test_key_generation() {
    printf("  Running test: test_key_generation...\n");
    master_key_pair mkp;
    mkp.sk = NULL;

    int res = generate_master_key_pair(&mkp);
    TEST_ASSERT(res == 0, "generate_master_key_pair should succeed");
    TEST_ASSERT(mkp.sk != NULL, "Secret key pointer should not be NULL");
    
    // 创建一个公钥副本，以验证私钥释放后公钥依然存在
    unsigned char pk_copy[MASTER_PUBLIC_KEY_BYTES];
    memcpy(pk_copy, mkp.pk, sizeof(pk_copy));

    free_master_key_pair(&mkp);
    TEST_ASSERT(mkp.sk == NULL, "Secret key pointer should be NULL after free");

    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试密钥封装与解封装的正常往返流程
 */
int test_key_encapsulation_roundtrip() {
    printf("  Running test: test_key_encapsulation_roundtrip...\n");
    master_key_pair alice_kp, bob_kp;
    alice_kp.sk = NULL;
    bob_kp.sk = NULL;

    TEST_ASSERT(generate_master_key_pair(&alice_kp) == 0, "Alice keygen failed");
    TEST_ASSERT(generate_master_key_pair(&bob_kp) == 0, "Bob keygen failed");

    // Alice 要发送给 Bob 的会话密钥
    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // Alice 使用 Bob 的公钥和自己的私钥来封装会话密钥
    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    unsigned char* encapsulated_key = malloc(enc_buf_len);
    size_t encapsulated_len;
    int res_enc = encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk);
    TEST_ASSERT(res_enc == 0, "encapsulate_session_key should succeed");

    // Bob 使用自己的私钥和 Alice 的公钥来解封装
    unsigned char* decrypted_session_key = secure_alloc(sizeof(session_key));
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, alice_kp.pk, bob_kp.sk);
    TEST_ASSERT(res_dec == 0, "decapsulate_session_key should succeed");

    // 验证恢复的密钥与原始密钥一致
    TEST_ASSERT(sodium_memcmp(session_key, decrypted_session_key, sizeof(session_key)) == 0, "Decapsulated key must match original");

    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);

    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试使用错误的接收者私钥解封装，预期失败
 */
int test_decapsulation_wrong_recipient() {
    printf("  Running test: test_decapsulation_wrong_recipient...\n");
    master_key_pair alice_kp, bob_kp, eve_kp; // Eve 是恶意第三方
    alice_kp.sk = NULL;
    bob_kp.sk = NULL;
    eve_kp.sk = NULL;

    TEST_ASSERT(generate_master_key_pair(&alice_kp) == 0, "Alice keygen failed");
    TEST_ASSERT(generate_master_key_pair(&bob_kp) == 0, "Bob keygen failed");
    TEST_ASSERT(generate_master_key_pair(&eve_kp) == 0, "Eve keygen failed");

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // Alice 为 Bob 封装密钥
    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    unsigned char* encapsulated_key = malloc(enc_buf_len);
    size_t encapsulated_len;
    encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk);

    // Eve 截获了消息，并试图用自己的私钥解封装
    unsigned char* decrypted_session_key = secure_alloc(sizeof(session_key));
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, alice_kp.pk, eve_kp.sk);
    TEST_ASSERT(res_dec == -1, "Decapsulation with wrong recipient key must fail");

    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free_master_key_pair(&eve_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);

    printf("    ... PASSED\n");
    return 0;
}

/**
 * @brief 测试解封装时提供了错误的发送者公钥，预期失败
 */
int test_decapsulation_wrong_sender() {
    printf("  Running test: test_decapsulation_wrong_sender...\n");
    master_key_pair alice_kp, bob_kp, eve_kp;
    alice_kp.sk = NULL;
    bob_kp.sk = NULL;
    eve_kp.sk = NULL;

    TEST_ASSERT(generate_master_key_pair(&alice_kp) == 0, "Alice keygen failed");
    TEST_ASSERT(generate_master_key_pair(&bob_kp) == 0, "Bob keygen failed");
    TEST_ASSERT(generate_master_key_pair(&eve_kp) == 0, "Eve keygen failed");

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // Alice 为 Bob 封装密钥
    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    unsigned char* encapsulated_key = malloc(enc_buf_len);
    size_t encapsulated_len;
    encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk);

    // Bob 收到消息，但他错误地以为是 Eve 发来的，并使用了 Eve 的公钥解封装
    unsigned char* decrypted_session_key = secure_alloc(sizeof(session_key));
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, eve_kp.pk, bob_kp.sk);
    TEST_ASSERT(res_dec == -1, "Decapsulation with wrong sender key must fail");
    
    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free_master_key_pair(&eve_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);

    printf("    ... PASSED\n");
    return 0;
}


int main() {
    if (crypto_client_init() != 0) {
        fprintf(stderr, "Fatal: crypto_client_init failed\n");
        return 1;
    }

    printf("--- Running Asymmetric Cryptography Test Suite ---\n");
    if (test_key_generation() != 0) return 1;
    if (test_key_encapsulation_roundtrip() != 0) return 1;
    if (test_decapsulation_wrong_recipient() != 0) return 1;
    if (test_decapsulation_wrong_sender() != 0) return 1;
    
    printf("--- Asymmetric Cryptography Test Suite: ALL PASSED ---\n\n");
    return 0;
}