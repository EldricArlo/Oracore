/* --- START OF FILE tests/test_api_integration.c --- */

// tests/test_api_integration.c
// [REVISED BY COMMITTEE TO USE PUBLIC API - PFS UPDATE]
// This file tests the high-level public API functions, focusing on the
// end-to-end hybrid stream encryption/decryption workflow and API robustness.

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


// --- 测试用例 (已修复 PFS 逻辑) ---

void test_hybrid_stream_roundtrip_ok() {
    // [FIX]: PFS 变更 - 只需要接收者密钥对
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp);

    // 使用新的API函数合法地获取公钥
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    _assert(hsc_get_master_public_key(recipient_kp, recipient_pk) == HSC_OK);

    const char* original_content = "This is a test of the hybrid streaming encryption. It should work perfectly.";
    _assert(create_temp_file("test_in.txt", original_content));

    // [FIX]: 加密不再需要 sender_kp
    int res_enc = hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk);
    _assert(res_enc == HSC_OK);

    // [FIX]: 解密不再需要 sender_pk
    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec.txt", "test_out.hsc", recipient_kp);
    _assert(res_dec == HSC_OK);

    _assert(compare_files("test_in.txt", "test_dec.txt"));

    hsc_free_master_key_pair(&recipient_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec.txt");
}

void test_hybrid_stream_decrypt_wrong_key() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    hsc_master_key_pair* attacker_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp && attacker_kp);
    
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    _assert(hsc_get_master_public_key(recipient_kp, recipient_pk) == HSC_OK);

    _assert(create_temp_file("test_in.txt", "secret"));
    
    // 加密给 recipient
    _assert(hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk) == HSC_OK);

    // 尝试用 attacker_kp 解密 (应该失败)
    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec.txt", "test_out.hsc", attacker_kp);
    _assert(res_dec == HSC_ERROR_CRYPTO_OPERATION);

    hsc_free_master_key_pair(&recipient_kp);
    hsc_free_master_key_pair(&attacker_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec.txt");
}

void test_hybrid_stream_decrypt_tampered_file() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp);

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    _assert(hsc_get_master_public_key(recipient_kp, recipient_pk) == HSC_OK);

    _assert(create_temp_file("test_in.txt", "some data that is long enough to be tampered with"));
    _assert(hsc_hybrid_encrypt_stream_raw("test_out.hsc", "test_in.txt", recipient_pk) == HSC_OK);
    
    _assert(tamper_file("test_out.hsc"));

    // 篡改后的文件解密应失败
    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec.txt", "test_out.hsc", recipient_kp);
    _assert(res_dec == HSC_ERROR_CRYPTO_OPERATION);

    hsc_free_master_key_pair(&recipient_kp);
    unlink("test_in.txt");
    unlink("test_out.hsc");
    unlink("test_dec.txt");
}

void test_hybrid_stream_empty_file() {
    hsc_master_key_pair* recipient_kp = hsc_generate_master_key_pair();
    _assert(recipient_kp);

    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    _assert(hsc_get_master_public_key(recipient_kp, recipient_pk) == HSC_OK);

    _assert(create_temp_file("test_in_empty.txt", ""));

    int res_enc = hsc_hybrid_encrypt_stream_raw("test_out_empty.hsc", "test_in_empty.txt", recipient_pk);
    _assert(res_enc == HSC_OK);

    int res_dec = hsc_hybrid_decrypt_stream_raw("test_dec_empty.txt", "test_out_empty.hsc", recipient_kp);
    _assert(res_dec == HSC_OK);

    _assert(compare_files("test_in_empty.txt", "test_dec_empty.txt"));

    hsc_free_master_key_pair(&recipient_kp);
    unlink("test_in_empty.txt");
    unlink("test_out_empty.hsc");
    unlink("test_dec_empty.txt");
}

void test_api_null_arguments() {
    unsigned char dummy_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_master_key_pair* dummy_kp = hsc_generate_master_key_pair();
    _assert(dummy_kp);

    // [FIX]: 更新参数检查，移除已被删除的参数
    // Encrypt: (out, in, recipient_pk)
    _assert(hsc_hybrid_encrypt_stream_raw(NULL, "in", dummy_pk) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_encrypt_stream_raw("out", NULL, dummy_pk) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_encrypt_stream_raw("out", "in", NULL) == HSC_ERROR_INVALID_ARGUMENT);
    
    // Decrypt: (out, in, recipient_kp)
    _assert(hsc_hybrid_decrypt_stream_raw(NULL, "in", dummy_kp) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_decrypt_stream_raw("out", NULL, dummy_kp) == HSC_ERROR_INVALID_ARGUMENT);
    _assert(hsc_hybrid_decrypt_stream_raw("out", "in", NULL) == HSC_ERROR_INVALID_ARGUMENT);

    hsc_free_master_key_pair(&dummy_kp);
}


void run_all_tests() {
    printf("--- Running API Integration & Robustness Tests (PFS Enabled) ---\n");
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
/* --- END OF FILE tests/test_api_integration.c --- */