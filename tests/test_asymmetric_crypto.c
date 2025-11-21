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
 * @brief 测试密钥封装与解封装的正常往返流程 (Authenticated Ephemeral KEM)
 */
int test_key_encapsulation_roundtrip() {
    printf("  Running test: test_key_encapsulation_roundtrip...\n");
    int ret = -1; 
    
    master_key_pair alice_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair bob_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    
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

    // [FIX]: 此时 HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES 已在头文件中更新，包含签名长度
    size_t enc_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) {
        fprintf(stderr, "TEST FAILED: malloc failed for encapsulated_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // [FIX]: Authenticated KEM - Alice 作为发送者，必须提供自己的 MKP 用于签名
    size_t encapsulated_len;
    if (encapsulate_session_key(encapsulated_key, &encapsulated_len, 
                                session_key, sizeof(session_key), 
                                bob_kp.identity_pk,
                                &alice_kp) != 0) { // Passed sender_mkp
        fprintf(stderr, "TEST FAILED: encapsulate_session_key should succeed (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) {
        fprintf(stderr, "TEST FAILED: secure_alloc failed for decrypted_session_key (%s:%d)\n", __FILE__, __LINE__);
        goto cleanup;
    }

    // [FIX]: Authenticated KEM - Bob 解密时，必须提供 Alice 的公钥用于验签
    if (decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, 
                                bob_kp.encryption_sk,
                                alice_kp.identity_pk) != 0) { // Passed sender_pk
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

    size_t enc_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) goto cleanup;

    size_t encapsulated_len;
    // Alice encrypts for Bob
    encapsulate_session_key(encapsulated_key, &encapsulated_len, 
                            session_key, sizeof(session_key), 
                            bob_kp.identity_pk,
                            &alice_kp); // Sender is Alice

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) goto cleanup;

    // Eve tries to decrypt (Wrong Recipient SK)
    // Note: Sender PK is correct (Alice), but Recipient SK is Eve's.
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, 
                                          eve_kp.encryption_sk, 
                                          alice_kp.identity_pk);
                                          
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
 * @brief [新增] 测试发送者身份验证 (Anti-Spoofing)
 * 场景: Alice 发送给 Bob。Bob 试图验证该消息是否来自 Eve。
 * 预期: 签名验证失败，解密被拒绝。
 */
int test_decapsulation_wrong_sender_signature() {
    printf("  Running test: test_decapsulation_wrong_sender_signature...\n");
    int ret = -1; 
    
    master_key_pair alice_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair bob_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    master_key_pair eve_kp = { .identity_sk = NULL, .encryption_sk = NULL };
    
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_session_key = NULL;

    if (generate_master_key_pair(&alice_kp) != 0 || generate_master_key_pair(&bob_kp) != 0 || generate_master_key_pair(&eve_kp) != 0) {
        goto cleanup;
    }

    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    size_t enc_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    encapsulated_key = malloc(enc_buf_len);
    if (!encapsulated_key) goto cleanup;

    size_t encapsulated_len;
    
    // 1. Alice 加密给 Bob (使用 Alice 的私钥签名)
    encapsulate_session_key(encapsulated_key, &encapsulated_len, 
                            session_key, sizeof(session_key), 
                            bob_kp.identity_pk,
                            &alice_kp); 

    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) goto cleanup;

    // 2. Bob 尝试解密，但他被误导（或受到攻击），认为发送者是 Eve
    // 他传入了 Eve 的公钥来验证签名
    int res_dec = decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_len, 
                                          bob_kp.encryption_sk, // Recipient SK is correct
                                          eve_kp.identity_pk);  // [WRONG] Expected Sender PK
                                          
    if (res_dec != -1) {
        fprintf(stderr, "TEST FAILED: Signature verification should fail when verifying against wrong sender PK (%s:%d)\n", __FILE__, __LINE__);
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
    // [修复] 适配新的 crypto_client_init 签名
    if (crypto_client_init(NULL) != 0) {
        fprintf(stderr, "Fatal: crypto_client_init failed\n");
        return 1;
    }

    printf("--- Running Asymmetric Cryptography Test Suite (Authenticated Ephemeral KEM) ---\n");
    if (test_key_generation() != 0) return 1;
    if (test_key_encapsulation_roundtrip() != 0) return 1;
    if (test_decapsulation_wrong_recipient() != 0) return 1;
    // [FIX]: 重新启用并更新了身份验证测试
    if (test_decapsulation_wrong_sender_signature() != 0) return 1;
    
    printf("--- Asymmetric Cryptography Test Suite: ALL PASSED ---\n\n");
    return 0;
}
/* --- END OF FILE tests/test_asymmetric_crypto.c --- */