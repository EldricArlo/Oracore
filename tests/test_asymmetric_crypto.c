/* --- START OF FILE tests/test_asymmetric_crypto.c --- */

// tests/test_asymmetric_crypto.c

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h> 

#include "core_crypto/crypto_client.h"
#include "common/secure_memory.h"
// [FIX]: 引入 hsc_kernel.h 以获取 HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES 常量
#include "../include/hsc_kernel.h"

// --- 测试用例 ---

/**
 * @brief 测试密钥对的生成与释放
 */
int test_key_generation() {
    printf("  Running test: test_key_generation...\n");
    int ret = -1; 
    
    master_key_pair mkp = { .identity_sk = NULL, .encryption_sk = NULL };

    if (generate_master_key_pair(&mkp) != 0) {
        fprintf(stderr, "TEST FAILED: generate_master_key_pair should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    if (mkp.identity_sk == NULL) {
        fprintf(stderr, "TEST FAILED: Identity secret key pointer should not be NULL (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    if (mkp.encryption_sk == NULL) {
        fprintf(stderr, "TEST FAILED: Encryption secret key pointer should not be NULL (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    free_master_key_pair(&mkp);
    
    if (mkp.identity_sk != NULL || mkp.encryption_sk != NULL) {
        fprintf(stderr, "TEST FAILED: Secret key pointers should be NULL after free (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }
    
    ret = 0; 
    printf("    ... PASSED\n");

cleanup:
    free_master_key_pair(&mkp);
    return ret;
}

/**
 * @brief 测试密钥封装与解封装的正常往返流程 (Ephemeral KEM)
 */
int test_key_encapsulation_roundtrip() {
    printf("  Running test: test_key_encapsulation_roundtrip...\n");
    int ret = -1; 
    
    master_key_pair alice_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair bob_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    // 这里的 Alice 即使作为发送者，实际上在封装阶段不需要她的 KP，
    // 但为了模拟真实场景（且后续可能扩展），我们还是生成一下。
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

    // [FIX]: 使用正确的 Overhead 常量 (包含 Ephemeral PK)
    size_t enc_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) {
        fprintf(stderr, "TEST FAILED: malloc failed for encapsulated_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // [FIX]: 更新参数 - Ephemeral KEM 不需要发送者私钥
    // recipient_pk -> bob_kp.identity_pk (函数内部会转换为 X25519)
    size_t encapsulated_len;
    if (encapsulate_session_key(encapsulated_key, &encapsulated_len, 
                                session_key, sizeof(session_key), 
                                bob_kp.identity_pk) != 0) {
        fprintf(stderr, "TEST FAILED: encapsulate_session_key should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) {
        fprintf(stderr, "TEST FAILED: secure_alloc failed for decrypted_session_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // [FIX]: 更新参数 - 解密不需要发送者公钥
    // recipient_sk -> bob_kp.encryption_sk (直接使用加密私钥)
    if (decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, 
                                bob_kp.encryption_sk) != 0) {
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
    int ret = -1; 
    
    master_key_pair alice_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair bob_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair eve_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    if (generate_master_key_pair(&alice_kp) != 0 || generate_master_key_pair(&bob_kp) != 0 || generate_master_key_pair(&eve_kp) != 0) {
        fprintf(stderr, "TEST FAILED: Key generation failed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // [FIX]: 使用正确的缓冲区大小
    size_t enc_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) goto cleanup;

    size_t encapsulated_len;
    // Encrypt for Bob
    encapsulate_session_key(encapsulated_key, &encapsulated_len, 
                            session_key, sizeof(session_key), 
                            bob_kp.identity_pk);

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) goto cleanup;

    // [FIX]: 使用 Eve 的 encryption_sk 进行解密，预期失败
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, 
                                          eve_kp.encryption_sk);
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

// [FIX]: 移除了 'test_decapsulation_wrong_sender'
// 原因: Ephemeral KEM 是匿名加密协议，解密时不再验证发送者身份。
// 发送者身份验证应由上层协议（如对密文的签名）负责，不在核心 KEM 层的测试范围内。

int main() {
    // [修复] 适配新的 crypto_client_init 签名
    if (crypto_client_init(NULL) != 0) {
        fprintf(stderr, "Fatal: crypto_client_init failed\n");
        return 1;
    }

    printf("--- Running Asymmetric Cryptography Test Suite (Ephemeral KEM) ---\n");
    if (test_key_generation() != 0) return 1;
    if (test_key_encapsulation_roundtrip() != 0) return 1;
    if (test_decapsulation_wrong_recipient() != 0) return 1;
    
    printf("--- Asymmetric Cryptography Test Suite: ALL PASSED ---\n\n");
    return 0;
}
/* --- END OF FILE tests/test_asymmetric_crypto.c --- */