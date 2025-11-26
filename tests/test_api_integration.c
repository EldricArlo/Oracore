// tests/test_api_integration.c
// [REVISED BY COMMITTEE - FIX VERIFICATION]
// This file tests the high-level public API functions, focusing on the
// end-to-end hybrid stream encryption/decryption workflow and API robustness.
// Now enforces Authenticated Encryption (Sign-then-Encrypt).

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h> // For unlink()
#include <stdbool.h> 

#include "hsc_kernel.h"

// --- 测试框架宏 ---
int tests_run = 0;
int tests_failed = 0;

#define FAIL() printf("\033[31m[FAIL]\033[0m %s:%d\n", __FILE__, __LINE__)
#define _assert(test) do { if (!(test)) { FAIL(); tests_failed++; return; } } while(0)
#define RUN_TEST(test) do { \
    printf("  Running test: %s...", #test); \
    int prev_fails = tests_failed; \
    test(); \
    tests_run++; \
    if(tests_failed == prev_fails) printf("\033[32m [PASS]\033[0m\n"); \
} while(0)

// --- 测试辅助函数 (无修改) ---

static bool create_temp_file(const char* path, const char* content) {
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    size_t content_len = content ? strlen(content) : 0;
    if (content_len > 0) {
        if (fwrite(content, 1, content_len, f) != content_len) {
            fclose(f);
            return false;
        }
    }
    fclose(f);
    return true;
}

static bool compare_files(const char* path1, const char* path2) {
    FILE *f1 = fopen(path1, "rb");
    FILE *f2 = fopen(path2, "rb");
    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return false;
    }
    fseek(f1, 0, SEEK_END);
    long len1 = ftell(f1);
    fseek(f2, 0, SEEK_END);
    long len2 = ftell(f2);
    if (len1 != len2) {
        fclose(f1); fclose(f2);
        return false;
    }
    fseek(f1, 0, SEEK_SET);
    fseek(f2, 0, SEEK_SET);
    char buf1[4096], buf2[4096];
    size_t bytes_read1, bytes_read2;
    bool result = true;
    while ((bytes_read1 = fread(buf1, 1, sizeof(buf1), f1)) > 0) {
        bytes_read2 = fread(buf2, 1, sizeof(buf2), f2);
        if (bytes_read1 != bytes_read2 || memcmp(buf1, buf2, bytes_read1) != 0) {
            result = false;
            break;
        }
    }
    fclose(f1);
    fclose(f2);
    return result;
}

static bool tamper_file(const char* path) {
    FILE* f = fopen(path, "r+b");
    if (!f) return false;
    if (fseek(f, 100, SEEK_SET) != 0) {
        fclose(f);
        return true; 
    }
    char byte;
    if (fread(&byte, 1, 1, f) == 1) {
        byte ^= 0xFF;
        fseek(f, -1, SEEK_CUR);
        fwrite(&byte, 1, 1, f);
    }
    fclose(f);
    return true;
}


// --- 测试用例 (已修复 Authenticated Encryption 逻辑) ---

void test_hybrid_stream_roundtrip_ok() {
    // 1. 准备双方密钥
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* sender_kp = hsc_generate_master_key_pair(); // [FIX] 需要发送方密钥
    _assert(recipient_kp && sender_kp);

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    _assert(hsc_get_master_public_key(recipient_kp, recipient_pk, sizeof(recipient_pk)) == HSC_OK);

    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    _assert(hsc_get_master_public_key(sender_kp, sender_pk, sizeof(sender_pk)) == HSC_OK);

    const char* original_content = "This is a test of the hybrid streaming encryption. It should work perfectly.";
    _assert(create_temp_file("test_in.txt", original_content));

    // [FIX]: 加密需传入 sender_kp (用于签名)
    int res_enc = hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk, sender_kp);
    _assert(res_enc == HSC_OK);

    // [FIX]: 解密需传入 sender_pk (用于验签)
    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec.txt", "test_out.hsc", recipient_kp, sender_pk);
    _assert(res_dec == HSC_OK);

    _assert(compare_files("test_in.txt", "test_dec.txt"));

    hsc_free_master_key_pair(&recipient_kp);
    hsc_free_master_key_pair(&sender_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec.txt");
}

void test_hybrid_stream_decrypt_wrong_key() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* sender_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* attacker_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp && sender_kp && attacker_kp);
    
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(recipient_kp, recipient_pk, sizeof(recipient_pk));

    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(sender_kp, sender_pk, sizeof(sender_pk));

    unsigned char attacker_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(attacker_kp, attacker_pk, sizeof(attacker_pk));

    _assert(create_temp_file("test_in.txt", "secret"));
    
    // 合法发送: Sender -> Recipient
    _assert(hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk, sender_kp) == HSC_OK);

    // 场景 A: 错误的接收者私钥 (Attacker 尝试解密)
    // 预期: 失败 (Decrypt Error)
    int res_dec_1 = hsc_hybrid_decrypt_stream_raw("test_dec_fail1.txt", "test_out.hsc", attacker_kp, sender_pk);
    _assert(res_dec_1 != HSC_OK);

    // 场景 B: [关键修复验证] 错误的发送者公钥
    // Recipient 尝试解密，但声称这封信是 Attacker 发的 (提供 Attacker PK 用于验签)
    // 预期: 失败 (Signature Verification Error)
    int res_dec_2 = hsc_hybrid_decrypt_stream_raw("test_dec_fail2.txt", "test_out.hsc", recipient_kp, attacker_pk);
    _assert(res_dec_2 != HSC_OK);

    hsc_free_master_key_pair(&recipient_kp);
    hsc_free_master_key_pair(&sender_kp);
    hsc_free_master_key_pair(&attacker_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec_fail1.txt");
    unlink("test_dec_fail2.txt");
}

void test_hybrid_stream_decrypt_tampered_file() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* sender_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp && sender_kp);

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(recipient_kp, recipient_pk, sizeof(recipient_pk));

    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(sender_kp, sender_pk, sizeof(sender_pk));

    _assert(create_temp_file("test_in.txt", "some data that is long enough to be tampered with"));
    _assert(hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk, sender_kp) == HSC_OK);
    
    _assert(tamper_file("test_out.hsc"));

    // 篡改后的文件解密应失败 (可能是 AEAD Tag 错误，也可能是签名验证错误，取决于篡改位置)
    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec.txt", "test_out.hsc", recipient_kp, sender_pk);
    _assert(res_dec != HSC_OK);

    hsc_free_master_key_pair(&recipient_kp);
    hsc_free_master_key_pair(&sender_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec.txt");
}

void test_hybrid_stream_empty_file() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* sender_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp && sender_kp);

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(recipient_kp, recipient_pk, sizeof(recipient_pk));
    
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // [FIX] Updated API call with public_key_max_len
    hsc_get_master_public_key(sender_kp, sender_pk, sizeof(sender_pk));

    _assert(create_temp_file("test_in_empty.txt", ""));

    int res_enc = hsc_hybrid_encrypt_stream_raw("test_out_empty.hsc", "test_in_empty.txt", recipient_pk, sender_kp);
    _assert(res_enc == HSC_OK);

    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec_empty.txt", "test_out_empty.hsc", recipient_kp, sender_pk);
    _assert(res_dec == HSC_OK);

    _assert(compare_files("test_in_empty.txt", "test_dec_empty.txt"));

    hsc_free_master_key_pair(&recipient_kp);
    hsc_free_master_key_pair(&sender_kp);
    unlink("test_in_empty.txt");
    unlink("test_out_empty.hsc");
    unlink("test_dec_empty.txt");
}

void test_api_null_arguments() {
    unsigned char dummy_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_master_key_pair* dummy_kp = hsc_generate_master_key_pair();
    _assert(dummy_kp);

    // Encrypt: (out, in, recipient_pk, sender_mkp)
    _assert(hsc_hybrid_encrypt_stream_raw(NULL, "in", dummy_pk, dummy_kp) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_encrypt_stream_raw("out", NULL, dummy_pk, dummy_kp) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_encrypt_stream_raw("out", "in", NULL, dummy_kp) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_encrypt_stream_raw("out", "in", dummy_pk, NULL) == HSC_ERROR_INVALID_ARGUMENT);
    
    // Decrypt: (out, in, recipient_kp, sender_pk)
    _assert(hsc_hybrid_decrypt_stream_raw(NULL, "in", dummy_kp, dummy_pk) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_decrypt_stream_raw("out", NULL, dummy_kp, dummy_pk) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_decrypt_stream_raw("out", "in", NULL, dummy_pk) == HSC_ERROR_INVALID_ARGUMENT);
    // [FIX] Corrected parameter from dummy_kp (struct*) to dummy_pk (unsigned char*)
    _assert(hsc_hybrid_decrypt_stream_raw("out", "in", dummy_kp, NULL) == HSC_ERROR_INVALID_ARGUMENT);

    hsc_free_master_key_pair(&dummy_kp);
}


void run_all_tests() {
    printf("--- Running API Integration & Robustness Tests (Authenticated PFS) ---\n");
    RUN_TEST(test_hybrid_stream_roundtrip_ok);
    RUN_TEST(test_hybrid_stream_decrypt_wrong_key);
    RUN_TEST(test_hybrid_stream_decrypt_tampered_file);
    RUN_TEST(test_hybrid_stream_empty_file);
    RUN_TEST(test_api_null_arguments);
    printf("--- Test Suite Finished ---\n");
}

int main() {
    if (hsc_init(NULL, NULL) != HSC_OK) {
        printf("Fatal: Could not initialize hsc_kernel for tests.\n");
        return 1;
    }

    run_all_tests();
    
    if (tests_failed > 0) {
        printf("\n\033[31mRESULT: %d assertion(s) FAILED in API integration tests.\033[0m\n", tests_failed);
        return 1;
    } else {
        printf("\n\033[32mRESULT: All %d API integration test functions PASSED.\033[0m\n", tests_run);
        return 0;
    }
}