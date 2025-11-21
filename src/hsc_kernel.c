/* --- START OF FILE src/hsc_kernel.c --- */

#include "hsc_kernel.h"

// 包含所有内部模块的头文件
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"
#include "common/internal_logger.h"

#include <string.h>
#include <curl/curl.h>
#include <sodium.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h> // [FIX] Added for errno reporting in hsc_init

// [FIX]: 引入资源限制头文件以禁用 Core Dumps (Mitigation for Finding #2)
#ifndef _WIN32
    #include <sys/time.h>
    #include <sys/resource.h>
#endif

// --- 不透明结构体的内部定义 ---

struct hsc_master_key_pair_s {
    master_key_pair internal_kp;
};

struct hsc_crypto_stream_state_s {
    crypto_secretstream_xchacha20poly1305_state internal_state;
};


// --- 导出公共常量 ---
const uint8_t HSC_STREAM_TAG_FINAL = crypto_secretstream_xchacha20poly1305_TAG_FINAL;


// --- 内部辅助函数 ---

static void store64_le(unsigned char* dst, uint64_t w) {
    dst[0] = (unsigned char)w; w >>= 8; dst[1] = (unsigned char)w; w >>= 8;
    dst[2] = (unsigned char)w; w >>= 8; dst[3] = (unsigned char)w; w >>= 8;
    dst[4] = (unsigned char)w; w >>= 8; dst[5] = (unsigned char)w; w >>= 8;
    dst[6] = (unsigned char)w; w >>= 8; dst[7] = (unsigned char)w;
}

static uint64_t load64_le(const unsigned char* src) {
    uint64_t w = src[7];
    w = (w << 8) | src[6]; w = (w << 8) | src[5]; w = (w << 8) | src[4];
    w = (w << 8) | src[3]; w = (w << 8) | src[2]; w = (w << 8) | src[1];
    w = (w << 8) | src[0]; return w;
}

static int _perform_stream_encryption(FILE* f_in, FILE* f_out, hsc_crypto_stream_state* st) {
    unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE];
    unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
    size_t bytes_read;
    unsigned long long out_len;
    uint8_t tag;

    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) {
            return HSC_ERROR_FILE_IO;
        }
        tag = feof(f_in) ? HSC_STREAM_TAG_FINAL : 0;
        if (hsc_crypto_stream_push(st, buf_out, &out_len, buf_in, bytes_read, tag) != HSC_OK) {
            return HSC_ERROR_CRYPTO_OPERATION;
        }
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
            return HSC_ERROR_FILE_IO;
        }
    } while (!feof(f_in));
    
    return HSC_OK;
}

static int _perform_stream_decryption(FILE* f_in, FILE* f_out, hsc_crypto_stream_state* st, bool* stream_finished_flag) {
    unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
    unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE];
    size_t bytes_read;
    unsigned long long out_len;
    unsigned char tag;
    *stream_finished_flag = false;
    
    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) {
            return HSC_ERROR_FILE_IO;
        }
        if (bytes_read == 0 && feof(f_in)) break;

        if (hsc_crypto_stream_pull(st, buf_out, &out_len, &tag, buf_in, bytes_read) != HSC_OK) {
            return HSC_ERROR_CRYPTO_OPERATION;
        }
        if (tag == HSC_STREAM_TAG_FINAL) {
            *stream_finished_flag = true;
        }
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
            return HSC_ERROR_FILE_IO;
        }
    } while (!feof(f_in));
    
    return HSC_OK;
}

static bool read_key_file(const char* filename, void* buffer, size_t expected_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size < 0 || (size_t)file_size != expected_len) {
        fclose(f);
        return false;
    }
    
    size_t bytes_read = fread(buffer, 1, expected_len, f);
    fclose(f);
    
    return (bytes_read == expected_len);
}

static bool write_key_file(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) return false;
    bool success = (fwrite(data, 1, len, f) == len);
    fclose(f); return success;
}

// --- API 实现：初始化与清理 ---

// [FIX]: 接收配置参数和显式Pepper，透传给 crypto_client_init
int hsc_init(const hsc_pki_config* config, const char* pepper_hex) {
    
    // [FIX]: Mitigation for Finding #2 - 禁用 Core Dumps
    // 在内存中可能包含敏感数据（如 OpenSSL 堆中的私钥副本）的情况下，防止崩溃时数据泄露到磁盘。
    #ifndef _WIN32
    struct rlimit core_limits;
    core_limits.rlim_cur = 0;
    core_limits.rlim_max = 0;
    if (setrlimit(RLIMIT_CORE, &core_limits) != 0) {
        // [FIX]: Remediation for Finding #2 (Fail-Closed)
        // 之前只是打印警告，现在升级为致命错误。
        // 必须确保环境安全（不产生Core Dump）才能启动，否则视为不安全状态。
        fprintf(stderr, "[Oracipher Core] FATAL: Failed to disable core dumps (errno=%d). Aborting initialization to protect secrets.\n", errno);
        return HSC_ERROR_GENERAL; 
    }
    #endif

    if (crypto_client_init(pepper_hex) != 0) return HSC_ERROR_CRYPTO_OPERATION;
    if (pki_init(config) != 0) return HSC_ERROR_PKI_OPERATION;
    return HSC_OK;
}

void hsc_cleanup() {
    crypto_client_cleanup();
    curl_global_cleanup();
}

void hsc_random_bytes(void* buf, size_t size) {
    randombytes_buf(buf, size);
}

// --- API 实现：主密钥管理 ---

hsc_master_key_pair* hsc_generate_master_key_pair() {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) return NULL;
    
    // [修复] 初始化新的分离指针
    kp->internal_kp.identity_sk = NULL;
    kp->internal_kp.encryption_sk = NULL;

    // 调用更新后的底层函数，它会处理内存分配和双密钥生成
    if (generate_master_key_pair(&kp->internal_kp) != 0) {
        hsc_free_master_key_pair(&kp);
        return NULL;
    }
    return kp;
}

// [修复] 彻底重构加载逻辑以支持密钥分离
hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path) {
    if (priv_key_path == NULL) return NULL;
    
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to allocate memory for key pair structure.");
        return NULL;
    }
    
    // 安全初始化
    kp->internal_kp.identity_sk = NULL;
    kp->internal_kp.encryption_sk = NULL;

    // 1. 分配并加载身份私钥 (Identity Key - Ed25519)
    kp->internal_kp.identity_sk = secure_alloc(HSC_MASTER_SECRET_KEY_BYTES);
    if (!kp->internal_kp.identity_sk) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to allocate secure memory for identity private key.");
        free(kp);
        return NULL;
    }

    if (!read_key_file(priv_key_path, kp->internal_kp.identity_sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to read private key file: %s", priv_key_path);
        hsc_free_master_key_pair(&kp);
        return NULL;
    }

    // 2. 派生身份公钥
    if (crypto_sign_ed25519_sk_to_pk(kp->internal_kp.identity_pk, kp->internal_kp.identity_sk) != 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive identity public key.");
        hsc_free_master_key_pair(&kp);
        return NULL;
    }

    // 3. [关键修复] 分配并派生隔离的加密私钥 (Encryption Key - X25519)
    // 即使是从磁盘加载，我们也需要在内存中创建第二份独立的密钥材料
    kp->internal_kp.encryption_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
    if (!kp->internal_kp.encryption_sk) {
         _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to allocate secure memory for encryption private key.");
         hsc_free_master_key_pair(&kp);
         return NULL;
    }

    // 执行 Ed25519 SK -> X25519 SK 转换
    if (crypto_sign_ed25519_sk_to_curve25519(kp->internal_kp.encryption_sk, kp->internal_kp.identity_sk) != 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive encryption private key.");
        hsc_free_master_key_pair(&kp);
        return NULL;
    }

    // 执行 Ed25519 PK -> X25519 PK 转换 (填充结构体中的 encryption_pk)
    if (crypto_sign_ed25519_pk_to_curve25519(kp->internal_kp.encryption_pk, kp->internal_kp.identity_pk) != 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive encryption public key.");
        hsc_free_master_key_pair(&kp);
        return NULL;
    }

    return kp;
}

int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path) {
    // [修复] 使用 identity_sk/pk 进行持久化，保持与现有磁盘格式兼容
    if (kp == NULL || kp->internal_kp.identity_sk == NULL || pub_key_path == NULL || priv_key_path == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    if (!write_key_file(pub_key_path, kp->internal_kp.identity_pk, HSC_MASTER_PUBLIC_KEY_BYTES) ||
        !write_key_file(priv_key_path, kp->internal_kp.identity_sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        return HSC_ERROR_FILE_IO;
    }
    return HSC_OK;
}

void hsc_free_master_key_pair(hsc_master_key_pair** kp) {
    if (kp == NULL || *kp == NULL) return;
    // 这里的 free_master_key_pair 现在会同时擦除 identity_sk 和 encryption_sk
    free_master_key_pair(&(*kp)->internal_kp); 
    free(*kp); 
    *kp = NULL;
}

int hsc_get_master_public_key(const hsc_master_key_pair* kp, unsigned char* public_key_out) {
    if (kp == NULL || public_key_out == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    // 返回身份公钥
    memcpy(public_key_out, kp->internal_kp.identity_pk, HSC_MASTER_PUBLIC_KEY_BYTES);
    return HSC_OK;
}

// --- API 实现：PKI与证书管理 ---

int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL) return HSC_ERROR_INVALID_ARGUMENT;
    // PKI 模块需要使用 Identity Key 进行签名
    return generate_csr(&mkp->internal_kp, username, out_csr_pem);
}

void hsc_free_pem_string(char* pem_string) {
    free_csr_pem(pem_string);
}

int hsc_verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username) {
    return verify_user_certificate(user_cert_pem, trusted_ca_cert_pem, expected_username);
}

int hsc_extract_public_key_from_cert(const char* user_cert_pem, unsigned char* public_key_out) {
    return extract_public_key_from_cert(user_cert_pem, public_key_out);
}

// --- API 实现：非对称加密 (密钥封装) ---

int hsc_encapsulate_session_key(unsigned char* encrypted_output, size_t* encrypted_output_len, const unsigned char* session_key, size_t session_key_len, const unsigned char* recipient_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return HSC_ERROR_INVALID_ARGUMENT;
    // [关键修复] 传入明确的 encryption_sk，不再传入 identity_sk
    int result = encapsulate_session_key(encrypted_output, encrypted_output_len, session_key, session_key_len, recipient_pk, my_kp->internal_kp.encryption_sk);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_decapsulate_session_key(unsigned char* decrypted_output, const unsigned char* encrypted_input, size_t encrypted_input_len, const unsigned char* sender_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return HSC_ERROR_INVALID_ARGUMENT;
    // [关键修复] 传入明确的 encryption_sk，不再传入 identity_sk
    int result = decapsulate_session_key(decrypted_output, encrypted_input, encrypted_input_len, sender_pk, my_kp->internal_kp.encryption_sk);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// --- API 实现：单次对称加解密 ---

int hsc_aead_encrypt(unsigned char* ciphertext, unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key) {
    int result = encrypt_symmetric_aead(ciphertext, ciphertext_len, message, message_len, key);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_aead_decrypt(unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key) {
    int result = decrypt_symmetric_aead(decrypted_message, decrypted_message_len, ciphertext, ciphertext_len, key);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// --- API 实现：流式加解密 ---

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
        return NULL;
    }
    return state;
}

void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state) {
    if (state == NULL || *state == NULL) return;
    sodium_memzero(*state, sizeof(hsc_crypto_stream_state));
    free(*state);
    *state = NULL;
}

int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, const unsigned char* in, size_t in_len, uint8_t tag) {
    if (state == NULL) return HSC_ERROR_INVALID_ARGUMENT;
    int result = crypto_secretstream_xchacha20poly1305_push(&state->internal_state, out, out_len, in, in_len, NULL, 0, tag);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len) {
    if (state == NULL) return HSC_ERROR_INVALID_ARGUMENT;
    int result = crypto_secretstream_xchacha20poly1305_pull(&state->internal_state, out, out_len, tag, in, in_len, NULL, 0);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}


// --- API 实现：高级混合加解密 (原始密钥模式) ---

int hsc_hybrid_encrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const unsigned char* recipient_pk,
                                    const hsc_master_key_pair* sender_kp)
{
    if (output_path == NULL || input_path == NULL || recipient_pk == NULL || sender_kp == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    int ret_code = HSC_ERROR_GENERAL;
    FILE *f_in = NULL, *f_out = NULL;
    hsc_crypto_stream_state* st = NULL;
    unsigned char* session_key = NULL;
    session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (!session_key) {
        ret_code = HSC_ERROR_ALLOCATION_FAILED;
        goto cleanup;
    }
    unsigned char encapsulated_key[HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES];
    size_t actual_encapsulated_len;
    hsc_random_bytes(session_key, HSC_SESSION_KEY_BYTES);
    
    // [修复] API 已经更新，内部会自动使用 encryption_sk，这里无需变更调用，只需确保 hsc_encapsulate_session_key 传递正确
    if (hsc_encapsulate_session_key(encapsulated_key, &actual_encapsulated_len,
                                session_key, HSC_SESSION_KEY_BYTES,
                                recipient_pk, sender_kp) != HSC_OK) {
        ret_code = HSC_ERROR_CRYPTO_OPERATION;
        goto cleanup;
    }
    f_in = fopen(input_path, "rb");
    if (!f_in) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }
    f_out = fopen(output_path, "wb");
    if (!f_out) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }
    unsigned char key_len_buf[8]; 
    store64_le(key_len_buf, actual_encapsulated_len);
    if (fwrite(key_len_buf, 1, sizeof(key_len_buf), f_out) != sizeof(key_len_buf) ||
        fwrite(encapsulated_key, 1, actual_encapsulated_len, f_out) != actual_encapsulated_len) {
        ret_code = HSC_ERROR_FILE_IO; goto cleanup;
    }
    unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
    st = hsc_crypto_stream_state_new_push(stream_header, session_key);
    if (st == NULL) { ret_code = HSC_ERROR_CRYPTO_OPERATION; goto cleanup; }
    if (fwrite(stream_header, 1, sizeof(stream_header), f_out) != sizeof(stream_header)) {
        ret_code = HSC_ERROR_FILE_IO; goto cleanup;
    }
    ret_code = _perform_stream_encryption(f_in, f_out, st);
    if (ret_code != HSC_OK) {
        goto cleanup;
    }
    ret_code = HSC_OK;
cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    if (ret_code != HSC_OK && output_path != NULL) remove(output_path);
    hsc_crypto_stream_state_free(&st);
    hsc_secure_free(session_key);
    return ret_code;
}

int hsc_hybrid_decrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const unsigned char* sender_pk,
                                    const hsc_master_key_pair* recipient_kp)
{
    if (output_path == NULL || input_path == NULL || sender_pk == NULL || recipient_kp == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    int ret_code = HSC_ERROR_GENERAL;
    FILE *f_in = NULL, *f_out = NULL;
    hsc_crypto_stream_state* st = NULL;
    unsigned char* encapsulated_key = NULL;
    unsigned char* dec_session_key = NULL;
    f_in = fopen(input_path, "rb");
    if (!f_in) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }
    unsigned char key_len_buf[8];
    if (fread(key_len_buf, 1, sizeof(key_len_buf), f_in) != sizeof(key_len_buf)) {
        ret_code = HSC_ERROR_INVALID_FORMAT; goto cleanup;
    }
    size_t enc_key_len = load64_le(key_len_buf);
    if (enc_key_len == 0 || enc_key_len > HSC_MAX_ENCAPSULATED_KEY_SIZE) {
        ret_code = HSC_ERROR_INVALID_FORMAT; goto cleanup;
    }
    encapsulated_key = hsc_secure_alloc(enc_key_len);
    if (!encapsulated_key) { ret_code = HSC_ERROR_ALLOCATION_FAILED; goto cleanup; }
    if (fread(encapsulated_key, 1, enc_key_len, f_in) != enc_key_len) {
        ret_code = HSC_ERROR_INVALID_FORMAT; goto cleanup;
    }
    dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (!dec_session_key) { ret_code = HSC_ERROR_ALLOCATION_FAILED; goto cleanup; }
    
    // [修复] 内部自动使用 encryption_sk 进行解封装
    if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key, enc_key_len, sender_pk, recipient_kp) != HSC_OK) {
        ret_code = HSC_ERROR_CRYPTO_OPERATION; goto cleanup;
    }
    unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
    if (fread(stream_header, 1, sizeof(stream_header), f_in) != sizeof(stream_header)) {
        ret_code = HSC_ERROR_INVALID_FORMAT; goto cleanup;
    }
    st = hsc_crypto_stream_state_new_pull(stream_header, dec_session_key);
    if (st == NULL) { ret_code = HSC_ERROR_CRYPTO_OPERATION; goto cleanup; }
    f_out = fopen(output_path, "wb");
    if (!f_out) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }
    bool stream_finished = false;
    ret_code = _perform_stream_decryption(f_in, f_out, st, &stream_finished);
    if (ret_code != HSC_OK) {
        goto cleanup;
    }
    if (!stream_finished) {
        ret_code = HSC_ERROR_INVALID_FORMAT;
        goto cleanup;
    }
    ret_code = HSC_OK;
cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    if (ret_code != HSC_OK && output_path != NULL) remove(output_path);
    hsc_secure_free(encapsulated_key);
    hsc_crypto_stream_state_free(&st);
    hsc_secure_free(dec_session_key);
    return ret_code;
}

// --- API 实现：安全内存管理 ---

void* hsc_secure_alloc(size_t size) {
    return secure_alloc(size);
}

void hsc_secure_free(void* ptr) {
    secure_free(ptr);
}

// --- API 实现：日志回调管理 ---

static hsc_log_callback g_log_callback = NULL;

void hsc_set_log_callback(hsc_log_callback callback) {
    g_log_callback = callback;
}

#define HSC_LOG_BUFFER_SIZE 2048

void _hsc_log(int level, const char* format, ...) {
    if (g_log_callback == NULL) {
        return;
    }

    char buffer[HSC_LOG_BUFFER_SIZE];

    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    g_log_callback(level, buffer);
}

// =======================================================================
// --- 专家级API实现 ---
// =======================================================================

int hsc_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                   const char* password, const unsigned char* salt) {
    if (derived_key == NULL || password == NULL || salt == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    
    size_t pepper_len = 0;
    const unsigned char* pepper = get_global_pepper(&pepper_len);
    if (pepper == NULL || pepper_len == 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "FATAL: Global pepper is not available. Was hsc_init() called and successful?");
        return HSC_ERROR_GENERAL;
    }

    int result = derive_key_from_password(
        derived_key, derived_key_len,
        password,
        salt,
        g_argon2_opslimit,
        g_argon2_memlimit,
        pepper, pepper_len
    );
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out, const unsigned char* ed25519_pk_in) {
    if (x25519_pk_out == NULL || ed25519_pk_in == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk_out, ed25519_pk_in) != 0) {
        return HSC_ERROR_CRYPTO_OPERATION;
    }
    return HSC_OK;
}

int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out, const unsigned char* ed25519_sk_in) {
    if (x25519_sk_out == NULL || ed25519_sk_in == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    if (crypto_sign_ed25519_sk_to_curve25519(x25519_sk_out, ed25519_sk_in) != 0) {
        return HSC_ERROR_CRYPTO_OPERATION;
    }
    return HSC_OK;
}

int hsc_aead_encrypt_detached_safe(unsigned char* ciphertext, unsigned char* tag_out, unsigned char* nonce_out,
                                   const unsigned char* message, size_t message_len,
                                   const unsigned char* additional_data, size_t ad_len,
                                   const unsigned char* key) {
    if (ciphertext == NULL || tag_out == NULL || nonce_out == NULL || message == NULL || key == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    
    hsc_random_bytes(nonce_out, HSC_AEAD_NONCE_BYTES);
    
    int result = encrypt_symmetric_aead_detached(ciphertext, tag_out, message, message_len,
                                                 additional_data, ad_len, nonce_out, key);

    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext, size_t ciphertext_len,
                              const unsigned char* tag,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key) {
    if (decrypted_message == NULL || ciphertext == NULL || tag == NULL || nonce == NULL || key == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    int result = decrypt_symmetric_aead_detached(decrypted_message, ciphertext, ciphertext_len,
                                                 tag, additional_data, ad_len, nonce, key);
    return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}
/* --- END OF FILE src/hsc_kernel.c --- */