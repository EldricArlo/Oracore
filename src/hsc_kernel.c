// --- START OF FILE src/hsc_kernel.c (CORRECTED VERSION) ---

#include "hsc_kernel.h"

// 包含所有内部模块的头文件
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

#include <string.h>
#include <curl/curl.h>
#include <sodium.h> // For crypto functions and constants
#include <stdlib.h> // For malloc/free

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

static bool read_key_file(const char* filename, void* buffer, size_t expected_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    // [COMMITTEE FIX] Use robust fread instead of ftell to support non-regular files
    // and ensure the file has the exact expected length.
    size_t bytes_read = fread(buffer, 1, expected_len, f);
    char dummy_byte;
    bool is_eof = (fread(&dummy_byte, 1, 1, f) == 0 && feof(f));
    fclose(f);
    return (bytes_read == expected_len && is_eof);
}

static bool write_key_file(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) return false;
    bool success = (fwrite(data, 1, len, f) == len);
    fclose(f); return success;
}


// --- API 实现：初始化与清理 ---

int hsc_init() {
    if (crypto_client_init() != 0) return -1;
    if (pki_init() != 0) return -1;
    return 0;
}

void hsc_cleanup() {
    curl_global_cleanup();
}

void hsc_random_bytes(void* buf, size_t size) {
    randombytes_buf(buf, size);
}


// --- API 实现：主密钥管理 ---

hsc_master_key_pair* hsc_generate_master_key_pair() {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) return NULL;
    kp->internal_kp.sk = NULL;
    if (generate_master_key_pair(&kp->internal_kp) != 0) {
        free(kp); return NULL;
    }
    return kp;
}

hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path) {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) return NULL;
    kp->internal_kp.sk = secure_alloc(HSC_MASTER_SECRET_KEY_BYTES);
    if (!kp->internal_kp.sk) {
        free(kp); return NULL;
    }
    if (!read_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        secure_free(kp->internal_kp.sk); free(kp); return NULL;
    }
    crypto_sign_ed25519_sk_to_pk(kp->internal_kp.pk, kp->internal_kp.sk);
    return kp;
}

int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path) {
    if (kp == NULL || kp->internal_kp.sk == NULL) return -1;
    if (!write_key_file(pub_key_path, kp->internal_kp.pk, HSC_MASTER_PUBLIC_KEY_BYTES) ||
        !write_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        return -1;
    }
    return 0;
}

void hsc_free_master_key_pair(hsc_master_key_pair** kp) {
    if (kp == NULL || *kp == NULL) return;
    free_master_key_pair(&(*kp)->internal_kp);
    free(*kp); *kp = NULL;
}


// --- API 实现：PKI与证书管理 ---

int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL) return -1;
    // This is a wrapper call to the actual implementation in pki_handler.c
    return generate_csr(&mkp->internal_kp, username, out_csr_pem);
}

void hsc_free_pem_string(char* pem_string) {
    // This is a wrapper call to the actual implementation in pki_handler.c
    free_csr_pem(pem_string);
}

int hsc_verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username) {
    // This is a wrapper call to the actual implementation in pki_handler.c
    return verify_user_certificate(user_cert_pem, trusted_ca_cert_pem, expected_username);
}

int hsc_extract_public_key_from_cert(const char* user_cert_pem, unsigned char* public_key_out) {
    // This is a wrapper call to the actual implementation in pki_handler.c
    return extract_public_key_from_cert(user_cert_pem, public_key_out);
}


// --- API 实现：非对称加密 (密钥封装) ---

int hsc_encapsulate_session_key(unsigned char* encrypted_output, size_t* encrypted_output_len, const unsigned char* session_key, size_t session_key_len, const unsigned char* recipient_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return encapsulate_session_key(encrypted_output, encrypted_output_len, session_key, session_key_len, recipient_pk, my_kp->internal_kp.sk);
}

int hsc_decapsulate_session_key(unsigned char* decrypted_output, const unsigned char* encrypted_input, size_t encrypted_input_len, const unsigned char* sender_pk, const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return decapsulate_session_key(decrypted_output, encrypted_input, encrypted_input_len, sender_pk, my_kp->internal_kp.sk);
}


// --- API 实现：单次对称加解密 ---

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
    if (state == NULL) return -1;
    return crypto_secretstream_xchacha20poly1305_push(&state->internal_state, out, out_len, in, in_len, NULL, 0, tag);
}

int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len) {
    if (state == NULL) return -1;
    return crypto_secretstream_xchacha20poly1305_pull(&state->internal_state, out, out_len, tag, in, in_len, NULL, 0);
}

// --- API 实现：安全内存管理 ---

void* hsc_secure_alloc(size_t size) {
    return secure_alloc(size);
}

void hsc_secure_free(void* ptr) {
    secure_free(ptr);
}
// --- END OF FILE src/hsc_kernel.c (CORRECTED VERSION) ---