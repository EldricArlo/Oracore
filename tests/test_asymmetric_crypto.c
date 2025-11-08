// tests/test_asymmetric_crypto.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"

// [委员会修改] 移除了原有的 TEST_ASSERT 宏，因为它会导致资源泄漏。
// 测试用例将直接使用 if 语句和 goto cleanup 模式。


// --- 测试用例 ---

/**
 * @brief 测试密钥对的生成与释放
 */
int test_key_generation() {
    printf("  Running test: test_key_generation...\n");
    int ret = -1; // [修改] 默认为失败
    master_key_pair mkp = { .sk = NULL };

    if (generate_master_key_pair(&mkp) != 0) {
        fprintf(stderr, "TEST FAILED: generate_master_key_pair should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (mkp.sk == NULL) {
        fprintf(stderr, "TEST FAILED: Secret key pointer should not be NULL (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // 释放并验证
    free_master_key_pair(&mkp);
    if (mkp.sk != NULL) {
        fprintf(stderr, "TEST FAILED: Secret key pointer should be NULL after free (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    ret = 0; // [修改] 所有检查通过
    printf("    ... PASSED\n");

cleanup:
    // [修改] 确保即使失败，资源也能被清理
    free_master_key_pair(&mkp);
    return ret;
}

/**
 * @brief 测试密钥封装与解封装的正常往返流程
 */
int test_key_encapsulation_roundtrip() {
    printf("  Running test: test_key_encapsulation_roundtrip...\n");
    int ret = -1; // [修改]
    master_key_pair alice_kp = { .sk = NULL };
    master_key_pair bob_kp = { .sk = NULL };
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    if (generate_master_key_pair(&alice_kp) != 0) {
        fprintf(stderr, "TEST FAILED: Alice keygen failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (generate_master_key_pair(&bob_kp) != 0) {
        fprintf(stderr, "TEST FAILED: Bob keygen failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) {
        fprintf(stderr, "TEST FAILED: malloc failed for encapsulated_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    size_t encapsulated_len;
    if (encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk) != 0) {
        fprintf(stderr, "TEST FAILED: encapsulate_session_key should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) {
        fprintf(stderr, "TEST FAILED: secure_alloc failed for decrypted_session_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    if (decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, alice_kp.pk, bob_kp.sk) != 0) {
        fprintf(stderr, "TEST FAILED: decapsulate_session_key should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    if (sodium_memcmp(session_key, decrypted_session_key, sizeof(session_key)) != 0) {
        fprintf(stderr, "TEST FAILED: Decapsulated key must match original (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);
    return ret;
}

/**
 * @brief 测试使用错误的接收者私钥解封装，预期失败
 */
int test_decapsulation_wrong_recipient() {
    printf("  Running test: test_decapsulation_wrong_recipient...\n");
    int ret = -1; // [修改]
    master_key_pair alice_kp = { .sk = NULL };
    master_key_pair bob_kp = { .sk = NULL };
    master_key_pair eve_kp = { .sk = NULL };
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    if (generate_master_key_pair(&alice_kp) != 0 || generate_master_key_pair(&bob_kp) != 0 || generate_master_key_pair(&eve_kp) != 0) {
        fprintf(stderr, "TEST FAILED: Key generation failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) goto cleanup;

    size_t encapsulated_len;
    encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk);

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) goto cleanup;

    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, alice_kp.pk, eve_kp.sk);
    if (res_dec != -1) {
        fprintf(stderr, "TEST FAILED: Decapsulation with wrong recipient key must fail (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free_master_key_pair(&eve_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);
    return ret;
}

/**
 * @brief 测试解封装时提供了错误的发送者公钥，预期失败
 */
int test_decapsulation_wrong_sender() {
    printf("  Running test: test_decapsulation_wrong_sender...\n");
    int ret = -1; // [修改]
    master_key_pair alice_kp = { .sk = NULL };
    master_key_pair bob_kp = { .sk = NULL };
    master_key_pair eve_kp = { .sk = NULL };
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    if (generate_master_key_pair(&alice_kp) != 0 || generate_master_key_pair(&bob_kp) != 0 || generate_master_key_pair(&eve_kp) != 0) {
        fprintf(stderr, "TEST FAILED: Key generation failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    size_t enc_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) goto cleanup;

    size_t encapsulated_len;
    encapsulate_session_key(encapsulated_key, &encapsulated_len, session_key, sizeof(session_key), bob_kp.pk, alice_kp.sk);

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) goto cleanup;

    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, eve_kp.pk, bob_kp.sk);
    if (res_dec != -1) {
        fprintf(stderr, "TEST FAILED: Decapsulation with wrong sender key must fail (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    ret = 0;
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&alice_kp);
    free_master_key_pair(&bob_kp);
    free_master_key_pair(&eve_kp);
    free(encapsulated_key);
    secure_free(decrypted_session_key);
    return ret;
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