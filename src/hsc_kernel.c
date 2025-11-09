/**
 * @file hsc_kernel.c
 * @brief 高安全性混合加密内核库公共 API 的实现。
 *
 * @details
 * 本文件作为连接公共 API (hsc_kernel.h) 与内部具体实现模块
 * (core_crypto, pki, common) 的桥梁。它实现了 Facade 设计模式，
 * 将所有内部复杂性封装起来，为用户提供一个稳定、简洁且统一的接口。
 */

#include "hsc_kernel.h"

// 包含所有内部模块的头文件
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

#include <string.h>
#include <curl/curl.h>
#include <sodium.h>
#include <stdlib.h>
#include <stdio.h> // for FILE operations

// =============================================================================
// --- 不透明结构体的内部定义 (Opaque Struct Definitions) ---
// =============================================================================

/**
 * @brief hsc_master_key_pair 的具体实现。
 * @details 这是一个包装结构体，其内部持有一个由 core_crypto 模块定义的密钥对。
 *          这种包装方式是实现不透明指针的关键。
 */
struct hsc_master_key_pair_s {
    master_key_pair internal_kp;
};

/**
 * @brief hsc_crypto_stream_state 的具体实现。
 * @details 包装了 libsodium 的流加密状态结构体。
 */
struct hsc_crypto_stream_state_s {
    crypto_secretstream_xchacha20poly1305_state internal_state;
};


// =============================================================================
// --- 导出公共常量 (Exported Public Constants) ---
// =============================================================================

/// @brief 将 libsodium 的内部常量导出为公共 API 的一部分。
const uint8_t HSC_STREAM_TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_FINAL;


// =============================================================================
// --- 内部辅助函数 (Internal Helper Functions) ---
// =============================================================================

/**
 * @brief 从文件中读取固定长度的密钥。
 * @details 这是一个经过安全加固的文件读取函数。它不仅读取数据，还通过尝试
 *          读取一个额外字节来验证文件大小是否与期望值完全相等。这可以防止
 *          因文件过长或过短导致的安全问题。
 *
 * @param[in]  filename     要读取的文件名。
 * @param[out] buffer       用于存储文件内容的缓冲区。
 * @param[in]  expected_len 期望读取的字节数。
 * @return 成功读取且文件长度完全符合预期时返回 true，否则返回 false。
 */
static bool read_key_file(const char* filename, void* buffer, size_t expected_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        return false;
    }

    size_t bytes_read = fread(buffer, 1, expected_len, f);
    
    // 验证是否已读到文件末尾，且文件没有多余的数据
    char dummy_byte;
    bool is_eof = (fread(&dummy_byte, 1, 1, f) == 0 && feof(f));
    
    fclose(f);
    
    return (bytes_read == expected_len && is_eof);
}

/**
 * @brief 将数据写入文件。
 * @details
 * @security_note
 *   对于私钥等敏感文件，调用者在写入成功后，应负责设置严格的文件权限
 *   (例如，在 POSIX 系统上使用 `chmod(filename, 0600)`)，以防止
 *   其他用户访问。本函数不处理文件权限以保持跨平台兼容性。
 *
 * @param[in] filename 要写入的文件名。
 * @param[in] data     指向要写入数据的指针。
 * @param[in] len      要写入的字节数。
 * @return 成功写入所有数据时返回 true，否则返回 false。
 */
static bool write_key_file(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        return false;
    }
    
    bool success = (fwrite(data, 1, len, f) == len);
    
    // 确保数据被刷新到磁盘，尽管 fclose 通常会这样做，但这是一种更明确的保证。
    fflush(f);
    
    fclose(f);
    return success;
}

// =============================================================================
// --- API 实现: 初始化与通用功能 ---
// =============================================================================

int hsc_init() {
    // 依次初始化所有依赖的底层库
    if (crypto_client_init() != 0) return -1;
    if (pki_init() != 0) return -1;
    return 0;
}

void hsc_cleanup() {
    // 注意：libsodium 和 OpenSSL 通常不需要显式的全局清理函数。
    // libcurl 则需要，以释放网络相关的全局状态。
    curl_global_cleanup();
}

void hsc_random_bytes(void* buf, size_t size) {
    randombytes_buf(buf, size);
}

// =============================================================================
// --- API 实现: 主密钥管理 ---
// =============================================================================

hsc_master_key_pair* hsc_generate_master_key_pair() {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) {
        return NULL; // 内存分配失败
    }
    
    // 在调用生成函数前将内部指针设为NULL，是一种安全的编程习惯
    kp->internal_kp.sk = NULL; 
    
    if (generate_master_key_pair(&kp->internal_kp) != 0) {
        free(kp); // 如果内部生成失败，释放外层包装结构体
        return NULL;
    }
    
    return kp;
}

hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path) {
    // 1. 分配外层结构体
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) {
        return NULL;
    }
    
    // 2. 为私钥分配受保护内存
    kp->internal_kp.sk = secure_alloc(HSC_MASTER_SECRET_KEY_BYTES);
    if (!kp->internal_kp.sk) {
        free(kp); // 清理步骤1分配的内存
        return NULL;
    }
    
    // 3. 从文件读取私钥
    if (!read_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        secure_free(kp->internal_kp.sk); // 清理步骤2分配的内存
        free(kp);                        // 清理步骤1分配的内存
        return NULL;
    }
    
    // 4. 从私钥派生出公钥
    crypto_sign_ed25519_sk_to_pk(kp->internal_kp.pk, kp->internal_kp.sk);
    
    return kp;
}

int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path) {
    if (kp == NULL || kp->internal_kp.sk == NULL) {
        return -1;
    }
    
    // 分别写入公钥和私钥，任何一步失败都返回错误
    if (!write_key_file(pub_key_path, kp->internal_kp.pk, HSC_MASTER_PUBLIC_KEY_BYTES) ||
        !write_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        return -1;
    }
    
    return 0;
}

void hsc_free_master_key_pair(hsc_master_key_pair** kp) {
    if (kp == NULL || *kp == NULL) {
        return;
    }
    
    // 1. 调用内部函数释放安全内存
    free_master_key_pair(&(*kp)->internal_kp);
    
    // 2. 释放外层包装结构体
    free(*kp);
    
    // 3. 将调用者的指针设置为NULL，防止悬挂指针
    *kp = NULL;
}

// =============================================================================
// --- API 实现: PKI 与证书 ---
// =============================================================================

int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL) return -1;
    // 直接将调用转发到 pki_handler 模块
    return generate_csr(&mkp->internal_kp, username, out_csr_pem);
}

void hsc_free_pem_string(char* pem_string) {
    // 转发调用到 pki_handler 模块，由其负责释放通过OpenSSL的BIO分配的内存
    free_csr_pem(pem_string);
}

int hsc_verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username) {
    return verify_user_certificate(user_cert_pem, trusted_ca_cert_pem, expected_username);
}

int hsc_extract_public_key_from_cert(const char* user_cert_pem, unsigned char* public_key_out) {
    return extract_public_key_from_cert(user_cert_pem, public_key_out);
}

// =============================================================================
// --- API 实现: 密钥封装 ---
// =============================================================================

int hsc_encapsulate_session_key(unsigned char* encrypted_output, size_t* encrypted_output_len, const unsigned char* session_key, size_t session_key_len, const unsigned char* recipient_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return encapsulate_session_key(encrypted_output, encrypted_output_len, session_key, session_key_len, recipient_pk, my_kp->internal_kp.sk);
}

int hsc_decapsulate_session_key(unsigned char* decrypted_output, const unsigned char* encrypted_input, size_t encrypted_input_len, const unsigned char* sender_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return decapsulate_session_key(decrypted_output, encrypted_input, encrypted_input_len, sender_pk, my_kp->internal_kp.sk);
}

// =============================================================================
// --- API 实现: 单次对称加解密 ---
// =============================================================================

int hsc_aead_encrypt(unsigned char* ciphertext, unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key) {
    return encrypt_symmetric_aead(ciphertext, ciphertext_len, message, message_len, key);
}

int hsc_aead_decrypt(unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key) {
    return decrypt_symmetric_aead(decrypted_message, decrypted_message_len, ciphertext, ciphertext_len, key);
}

// =============================================================================
// --- API 实现: 流式加解密 ---
// =============================================================================

hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(unsigned char* header, const unsigned char* key) {
    if (header == NULL || key == NULL) return NULL;
    
    hsc_crypto_stream_state* state = malloc(sizeof(hsc_crypto_stream_state));
    if (state == NULL) return NULL;
    
    if (crypto_secretstream_xchacha20poly1305_init_push(&state->internal_state, header, key) != 0) {
        free(state);
        return NULL;
    }
    return state;
}

hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(const unsigned char* header, const unsigned char* key) {
    if (header == NULL || key == NULL) return NULL;
    
    hsc_crypto_stream_state* state = malloc(sizeof(hsc_crypto_stream_state));
    if (state == NULL) return NULL;
    
    if (crypto_secretstream_xchacha20poly1305_init_pull(&state->internal_state, header, key) != 0) {
        free(state);
        return NULL; // 失败可能是因为 header 无效或 key 错误
    }
    return state;
}

void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state) {
    if (state == NULL || *state == NULL) return;
    
    // 安全关键点：在释放内存之前，先用零擦除整个状态对象，
    // 确保内存中不留下任何敏感的密钥材料。
    sodium_memzero(*state, sizeof(hsc_crypto_stream_state));
    
    free(*state);
    *state = NULL;
}

int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, const unsigned char* in, size_t in_len, uint8_t tag) {
    if (state == NULL) return -1;
    // 第7和第8个参数 (ad, ad_len) 用于附加关联数据，此处未使用
    return crypto_secretstream_xchacha20poly1305_push(&state->internal_state, out, out_len, in, in_len, NULL, 0, tag);
}

int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len) {
    if (state == NULL) return -1;
    return crypto_secretstream_xchacha20poly1305_pull(&state->internal_state, out, out_len, tag, in, in_len, NULL, 0);
}

// =============================================================================
// --- API 实现: 安全内存管理 ---
// =============================================================================

void* hsc_secure_alloc(size_t size) {
    return secure_alloc(size);
}

void hsc_secure_free(void* ptr) {
    secure_free(ptr);
}