/**
 * @file main.c
 * @brief hsc_kernel 库的端到端功能演示程序。
 *
 * @details
 * 本程序通过一个完整的场景展示了 hsc_kernel 库的核心功能：
 * 1.  **身份创建**: 模拟用户 "Alice" 生成主密钥对，创建 CSR。
 * 2.  **证书签发**: 模拟一个本地 CA 签发 Alice 的证书。
 * 3.  **混合加密**: Alice 使用混合加密模型加密一条消息。
 *     - 生成一次性的会话密钥 (Session Key)。
 *     - 使用会话密钥通过 AEAD (对称) 加密消息内容。
 *     - 使用自己的私钥和公钥 (在此例中，发送给自己) 来封装 (非对称加密) 会话密钥。
 * 4.  **混合解密**: Alice (作为接收者) 解密消息。
 *     - 解封装会话密钥。
 *     - 使用恢复的会话密钥解密消息内容。
 * 5.  **验证与清理**: 验证解密后的内容与原文是否一致，并安全地清理所有资源。
 *
 * 本文件旨在作为如何正确使用 hsc_kernel API 的示例代码。
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// OpenSSL 头文件用于模拟 CA
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
// libsodium 头文件用于内存比较
#include <sodium.h> 

// 核心库的唯一公共入口
#include "hsc_kernel.h"

// =============================================================================
// --- 辅助函数 (演示用途) ---
// =============================================================================

// 打印十六进制数据的辅助函数
void print_hex(const char* label, const unsigned char* data, size_t len);

// [模拟 CA] 为证书添加 X.509 v3 扩展
static int add_ext(X509 *cert, int nid, char *value);

// [模拟 CA] 生成一个自签名的测试 CA
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem);

// [模拟 CA] 使用 CA 密钥签署一个 CSR，生成用户证书
int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem);


// =============================================================================
// --- 演示流程的阶段性函数 ---
// =============================================================================

/**
 * @brief 阶段一：模拟用户身份创建和证书签发流程。
 */
static int demonstration_phase_one_identity(
    hsc_master_key_pair** out_alice_mkp,
    char** out_alice_cert_pem,
    char** out_ca_cert_pem,
    const char* alice_username
) {
    printf("--- 阶段一: 'Alice' 账户创建与证书签发 ---\n");
    int ret = -1;
    char* alice_csr_pem = NULL;
    char* ca_key_pem = NULL;

    // 1. Alice 生成她的主密钥对 (Ed25519)
    *out_alice_mkp = hsc_generate_master_key_pair();
    if (*out_alice_mkp == NULL) {
        fprintf(stderr, "错误: 生成 Alice 的主密钥对失败。\n");
        goto cleanup;
    }
    printf("  > Alice 的主密钥对已生成。\n");

    // 2. Alice 基于她的密钥对和用户名生成一个 CSR
    if (hsc_generate_csr(*out_alice_mkp, alice_username, &alice_csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 Alice 的 CSR 失败。\n");
        goto cleanup;
    }
    printf("  > 已为 Alice 生成 CSR。\n");
    
    // 3. [模拟CA] 创建一个本地的、自签名的根 CA
    if (generate_test_ca(&ca_key_pem, out_ca_cert_pem) != 0) {
        fprintf(stderr, "测试错误: 创建模拟 CA 失败。\n");
        goto cleanup;
    }
    printf("  > 模拟根 CA 已创建。\n");

    // 4. [模拟CA] CA 使用自己的私钥签署 Alice 的 CSR，从而颁发证书
    if (sign_csr_with_ca(out_alice_cert_pem, alice_csr_pem, ca_key_pem, *out_ca_cert_pem) != 0) {
        fprintf(stderr, "测试错误: 签署用户证书失败。\n");
        goto cleanup;
    }
    printf("'Alice' 的证书已成功签发。\n\n");
    
    ret = 0;

cleanup:
    hsc_free_pem_string(alice_csr_pem);
    free(ca_key_pem); // CA 私钥仅用于签名，在此之后不再需要
    return ret;
}

/**
 * @brief 阶段二：模拟 Alice 加密文件并准备分享。
 */
static int demonstration_phase_two_encryption(
    const char* file_content,
    const hsc_master_key_pair* alice_mkp,
    const char* alice_cert_pem,
    const char* ca_cert_pem,
    const char* alice_username,
    unsigned char** out_encrypted_file,
    unsigned long long* out_encrypted_file_len,
    unsigned char** out_encapsulated_key,
    size_t* out_encapsulated_key_len
) {
    printf("--- 端到端共享演示: Alice 加密文件并分享给自己 ---\n");
    int ret = -1;

    // 1. 生成一次性的会话密钥 (Symmetric Key)
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));
    print_hex("  > [明文] 会话密钥", session_key, sizeof(session_key));
    
    // 2. 使用会话密钥和 AEAD 对称加密文件内容
    printf("1. 本地文件加密...\n");
    printf("  > [明文] 文件内容: \"%s\"\n", file_content);
    size_t file_content_len = strlen(file_content);
    size_t enc_file_buf_len = file_content_len + HSC_AEAD_OVERHEAD_BYTES;
    *out_encrypted_file = malloc(enc_file_buf_len);
    if (!*out_encrypted_file) { fprintf(stderr, "内存分配失败！\n"); goto cleanup; }
    
    if (hsc_aead_encrypt(*out_encrypted_file, out_encrypted_file_len, (const unsigned char*)file_content, file_content_len, session_key) != 0) {
        fprintf(stderr, "严重错误: 对称加密文件失败！\n");
        goto cleanup;
    }
    printf("  > 文件内容已使用 AEAD 对称加密。\n\n");
    
    // 3. 在发送前，强制验证接收者 (此处为 Alice 自己) 的证书
    printf("2. 验证接收者 ('Alice') 的证书...\n");
    if (hsc_verify_user_certificate(alice_cert_pem, ca_cert_pem, alice_username) != 0) {
        fprintf(stderr, "严重错误: 接收者证书验证失败！中止共享。\n");
        goto cleanup;
    }
    printf("  > 接收者证书验证成功！\n\n");
    
    // 4. 从已验证的证书中提取接收者的公钥
    printf("3. 从证书中提取接收者公钥...\n");
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(alice_cert_pem, recipient_pk) != 0) {
        fprintf(stderr, "严重错误: 无法从证书中提取公钥！\n");
        goto cleanup;
    }
    print_hex("  > 提取到的接收者公钥", recipient_pk, sizeof(recipient_pk));
    printf("\n");

    // 5. 使用接收者的公钥和自己的私钥，封装(非对称加密)会话密钥
    printf("4. 为接收者封装会话密钥...\n");
    size_t encapsulated_key_buf_len = sizeof(session_key) + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES;
    *out_encapsulated_key = malloc(encapsulated_key_buf_len);
    if (!*out_encapsulated_key) { fprintf(stderr, "内存分配失败！\n"); goto cleanup; }
    
    if (hsc_encapsulate_session_key(*out_encapsulated_key, out_encapsulated_key_len, session_key, sizeof(session_key),
                                recipient_pk, alice_mkp) != 0) {
        fprintf(stderr, "严重错误: 封装会话密钥失败！\n");
        goto cleanup;
    }
    printf("  > 会话密钥已使用非对称加密封装。\n\n");
    
    printf("--- 文件上传包准备就绪 ---\n");
    printf("  - 加密的文件内容 (AEAD)\n");
    printf("  - 为接收者'Alice'封装的会话密钥\n");
    printf("--------------------------\n\n");
    ret = 0;

cleanup:
    // 清理此阶段内部生成的会话密钥
    sodium_memzero(session_key, sizeof(session_key));
    return ret;
}

/**
 * @brief 阶段三：模拟 Alice (作为接收者) 解密文件。
 */
static int demonstration_phase_three_decryption(
    const char* original_content,
    const hsc_master_key_pair* alice_mkp,
    const char* alice_cert_pem,
    const unsigned char* encrypted_file,
    unsigned long long encrypted_file_len,
    const unsigned char* encapsulated_key,
    size_t encapsulated_key_len
) {
    printf("--- 作为接收者 'Alice' 解密文件 ---\n");
    int ret = -1;
    unsigned char* decrypted_session_key = NULL;
    unsigned char* decrypted_file_content = NULL;

    // 1. 解封装会话密钥
    printf("1. 解封装会话密钥...\n");
    // 将恢复的会话密钥存储在受保护内存中
    decrypted_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (!decrypted_session_key) { fprintf(stderr, "安全内存分配失败！\n"); goto cleanup; }

    // 解封装需要发送者的公钥，我们从发送者（Alice自己）的证书中提取
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(alice_cert_pem, sender_pk) != 0) {
        fprintf(stderr, "错误：无法从发送者证书提取公钥！\n"); goto cleanup;
    }

    if (hsc_decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_key_len,
                                sender_pk, alice_mkp) != 0) {
        fprintf(stderr, "解密错误: 无法解封装会话密钥！可能是密钥错误或数据被篡改。\n");
        goto cleanup;
    }
    print_hex("  > [解密] 恢复的会话密钥", decrypted_session_key, HSC_SESSION_KEY_BYTES);
    printf("  > 验证成功: 会话密钥已恢复。\n\n");

    // 2. 使用恢复的会话密钥解密文件内容
    printf("2. 使用恢复的会话密钥解密文件内容...\n");
    size_t original_content_len = strlen(original_content);
    decrypted_file_content = malloc(original_content_len + 1);
    if (!decrypted_file_content) { fprintf(stderr, "内存分配失败！\n"); goto cleanup; }
    unsigned long long actual_dec_file_len;
    
    if (hsc_aead_decrypt(decrypted_file_content, &actual_dec_file_len,
                         encrypted_file, encrypted_file_len,
                         decrypted_session_key) != 0) {
        fprintf(stderr, "解密错误: 无法解密文件内容！数据可能被篡改。\n");
        goto cleanup;
    }
    decrypted_file_content[actual_dec_file_len] = '\0';
    
    // 3. 验证最终结果
    printf("  > [解密] 恢复的文件内容: \"%s\"\n", (char*)decrypted_file_content);
    if (strcmp(original_content, (char*)decrypted_file_content) == 0) {
        printf("  > 验证成功: 恢复的文件内容与原始内容匹配。\n\n");
    } else {
        printf("  > 验证失败: 恢复的文件内容与原始内容不匹配！\n\n");
        goto cleanup;
    }
    
    ret = 0;

cleanup:
    hsc_secure_free(decrypted_session_key);
    free(decrypted_file_content);
    return ret;
}

// =============================================================================
// --- Main 函数 ---
// =============================================================================

int main() {
    int ret = 1; // 默认返回失败

    // --- 资源声明 ---
    // 将所有需要清理的资源在 main 函数顶部声明为 NULL
    hsc_master_key_pair* alice_mkp = NULL;
    char* ca_cert_pem = NULL;
    char* alice_cert_pem = NULL;
    unsigned char* encrypted_file = NULL;
    unsigned char* encapsulated_session_key = NULL;
    
    // --- 初始化 ---
    printf("--- 高安全性混合加密系统 v4.2 内核库演示 ---\n");
    if (hsc_init() != 0) {
        fprintf(stderr, "错误: 高安全内核库初始化失败！\n");
        goto cleanup;
    }
    printf("密码学库初始化成功。\n\n");

    // --- 执行演示流程 ---
    const char* alice_username = "alice@example.com";
    const char* file_content = "这是文件的机密内容。This is the secret content of the file.";

    if (demonstration_phase_one_identity(&alice_mkp, &alice_cert_pem, &ca_cert_pem, alice_username) != 0) {
        goto cleanup;
    }

    unsigned long long encrypted_file_len;
    size_t encapsulated_key_len;
    if (demonstration_phase_two_encryption(file_content, alice_mkp, alice_cert_pem, ca_cert_pem, alice_username,
                                          &encrypted_file, &encrypted_file_len,
                                          &encapsulated_session_key, &encapsulated_key_len) != 0) {
        goto cleanup;
    }
    
    if (demonstration_phase_three_decryption(file_content, alice_mkp, alice_cert_pem,
                                             encrypted_file, encrypted_file_len,
                                             encapsulated_session_key, encapsulated_key_len) != 0) {
        goto cleanup;
    }
    
    // --- 成功 ---
    ret = 0; 
    printf("\033[32m--- 演示成功完成 ---\033[0m\n");

cleanup:
    // --- 统一清理 ---
    printf("\n--- 清理所有资源 ---\n");
    // 释放所有在此函数作用域内分配的资源
    free(ca_cert_pem);
    free(alice_cert_pem);
    hsc_free_master_key_pair(&alice_mkp);
    free(encrypted_file);
    free(encapsulated_session_key);

    hsc_cleanup();
    printf("清理完成。\n");

    return ret;
}


// =============================================================================
// --- 辅助函数实现 (保持不变) ---
// =============================================================================

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex) return 0;
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

int generate_test_ca(char** ca_key_pem, char** ca_cert_pem) {
    int ret = -1;
    EVP_PKEY *pkey = NULL; X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    
    // 初始化输出参数为 NULL
    *ca_key_pem = NULL; *ca_cert_pem = NULL;

    // 使用确定性的种子，以便测试可重复
    unsigned char ca_sk_seed[32];
    memset(ca_sk_seed, 0xCA, sizeof(ca_sk_seed));
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ca_sk_seed, sizeof(ca_sk_seed));
    if (!pkey) goto cleanup;

    cert = X509_new(); if (!cert) goto cleanup;

    X509_set_version(cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L); // 1年有效期
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Test System Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // 添加使其成为合格 CA 的 v3 扩展
    add_ext(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    add_ext(cert, NID_subject_key_identifier, "hash");

    if (!X509_sign(cert, pkey, NULL)) goto cleanup;

    // 将密钥和证书写入内存 BIO
    key_bio = BIO_new(BIO_s_mem()); cert_bio = BIO_new(BIO_s_mem());
    if(!key_bio || !cert_bio) goto cleanup;
    if(!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL)) goto cleanup;
    if(!PEM_write_bio_X509(cert_bio, cert)) goto cleanup;
    
    // 从 BIO 中提取 PEM 字符串
    BUF_MEM *key_mem, *cert_mem;
    BIO_get_mem_ptr(key_bio, &key_mem);
    *ca_key_pem = (char*)malloc(key_mem->length + 1);
    if (!*ca_key_pem) goto cleanup;
    memcpy(*ca_key_pem, key_mem->data, key_mem->length);
    (*ca_key_pem)[key_mem->length] = '\0';

    BIO_get_mem_ptr(cert_bio, &cert_mem);
    *ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    if (!*ca_cert_pem) { free(*ca_key_pem); *ca_key_pem = NULL; goto cleanup; }
    memcpy(*ca_cert_pem, cert_mem->data, cert_mem->length);
    (*ca_cert_pem)[cert_mem->length] = '\0';
    
    ret = 0;

cleanup:
    EVP_PKEY_free(pkey); X509_free(cert);
    BIO_free(key_bio); BIO_free(cert_bio);
    return ret;
}

int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL; EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;
    EVP_PKEY* req_pubkey = NULL;

    *user_cert_pem = NULL;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    if(!csr_bio || !ca_key_bio || !ca_cert_bio) goto cleanup;

    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if(!req || !ca_key || !ca_cert) goto cleanup;

    user_cert = X509_new(); if(!user_cert) goto cleanup;

    X509_set_version(user_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), 2); // 简单序列号
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), 31536000L);
    
    req_pubkey = X509_REQ_get_pubkey(req);
    if (!req_pubkey) goto cleanup;
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    
    // **[安全强化]** 将 OCSP URI 从 http 更改为 https，以防止元数据泄露。
    add_ext(user_cert, NID_info_access, "OCSP;URI:https://ocsp.example.com");

    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem()); if(!out_bio) goto cleanup;

    if(!PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
    BUF_MEM *out_mem;
    BIO_get_mem_ptr(out_bio, &out_mem);
    *user_cert_pem = (char*)malloc(out_mem->length + 1);
    if (!*user_cert_pem) goto cleanup;
    memcpy(*user_cert_pem, out_mem->data, out_mem->length);
    (*user_cert_pem)[out_mem->length] = '\0';
    ret = 0;

cleanup:
    if (ret != 0) { free(*user_cert_pem); *user_cert_pem = NULL; }
    EVP_PKEY_free(req_pubkey);
    BIO_free(csr_bio); BIO_free(ca_key_bio); BIO_free(ca_cert_bio); BIO_free(out_bio);
    X509_REQ_free(req); EVP_PKEY_free(ca_key); X509_free(ca_cert); X509_free(user_cert);
    return ret;
}