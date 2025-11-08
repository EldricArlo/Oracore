// --- START OF FILE src/hsc_kernel.c (FINAL & CORRECT) ---

#include "hsc_kernel.h" // [FIX] Corrected the include path

// 包含所有内部模块的头文件
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

#include <string.h>
#include <curl/curl.h>
#include <sodium.h> // For crypto_sign_ed25519_sk_to_pk
#include <stdlib.h> // For malloc/free

// [FIXED] 将hsc_master_key_pair的定义放在.c文件中，使其对外部完全不透明
struct hsc_master_key_pair_s {
    master_key_pair internal_kp;
};

// 内部辅助函数，用于安全地读取固定大小的文件
static bool read_key_file(const char* filename, void* buffer, size_t expected_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    bool success = false;
    if (len >= 0 && (size_t)len == expected_len) {
        if (fread(buffer, 1, expected_len, f) == expected_len) {
            success = true;
        }
    }
    fclose(f);
    return success;
}

// 内部辅助函数，用于写入文件
static bool write_key_file(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) return false;
    bool success = (fwrite(data, 1, len, f) == len);
    fclose(f);
    return success;
}


// --- API 实现 ---

int hsc_init() {
    if (crypto_client_init() != 0) return -1;
    if (pki_init() != 0) return -1;
    return 0;
}

void hsc_cleanup() {
    curl_global_cleanup();
}

hsc_master_key_pair* hsc_generate_master_key_pair() {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) return NULL;
    
    kp->internal_kp.sk = NULL;
    if (generate_master_key_pair(&kp->internal_kp) != 0) {
        free(kp);
        return NULL;
    }
    return kp;
}

hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path) {
    hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
    if (!kp) return NULL;

    kp->internal_kp.sk = secure_alloc(HSC_MASTER_SECRET_KEY_BYTES);
    if (!kp->internal_kp.sk) {
        free(kp);
        return NULL;
    }
    
    if (!read_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        secure_free(kp->internal_kp.sk);
        free(kp);
        return NULL;
    }

    // 从私钥派生出公钥
    crypto_sign_ed25519_sk_to_pk(kp->internal_kp.pk, kp->internal_kp.sk);
    
    return kp;
}

int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path) {
    if (kp == NULL) return -1;
    if (!write_key_file(pub_key_path, kp->internal_kp.pk, HSC_MASTER_PUBLIC_KEY_BYTES) ||
        !write_key_file(priv_key_path, kp->internal_kp.sk, HSC_MASTER_SECRET_KEY_BYTES)) {
        return -1;
    }
    return 0;
}

void hsc_free_master_key_pair(hsc_master_key_pair** kp) {
    if (kp == NULL || *kp == NULL) return;
    free_master_key_pair(&(*kp)->internal_kp);
    free(*kp);
    *kp = NULL;
}

int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL) return -1;
    return generate_csr(&mkp->internal_kp, username, out_csr_pem);
}

void hsc_free_pem_string(char* pem_string) {
    free_csr_pem(pem_string);
}

int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username) {
    return verify_user_certificate(user_cert_pem, trusted_ca_cert_pem, expected_username);
}

int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out) {
    return extract_public_key_from_cert(user_cert_pem, public_key_out);
}

int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return encapsulate_session_key(encrypted_output, encrypted_output_len,
                                   session_key, session_key_len,
                                   recipient_pk, my_kp->internal_kp.sk);
}

int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const unsigned char* sender_pk,
                                const hsc_master_key_pair* my_kp) {
    if (my_kp == NULL) return -1;
    return decapsulate_session_key(decrypted_output,
                                   encrypted_input, encrypted_input_len,
                                   sender_pk, my_kp->internal_kp.sk);
}

// --- END OF FILE src/hsc_kernel.c (FINAL & CORRECT) ---