// --- START OF FILE src/main.c (FIXED by Code Review Committee) ---

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// [委员会建议] 为了清晰，将外部库头文件放在前面
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

// [委员会建议] 接着是项目内部的头文件
#include "hsc_kernel.h" // 假设已遵循P0建议，未来应只包含此文件
// 当前为保持兼容，暂时保留内部包含
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"


// --- 用于演示的辅助函数 ---
void print_hex(const char* label, const unsigned char* data, size_t len);

// [测试辅助] 添加 X.509 v3 扩展的辅助函数
static int add_ext(X509 *cert, int nid, char *value);

// [测试辅助] 生成一个自签名的根 CA 证书。在真实世界中，这在离线HSM中完成。
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem);

// [测试辅助] 使用 CA 签署用户的 CSR 来生成用户证书。在真实世界中，这是CA服务器的工作。
int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem);


int main() {
    // [委员会修改] 1. 统一资源管理模式：默认返回码为失败
    int ret = 1;

    // [委员会修改] 2. 声明所有需要清理的资源，并初始化为安全状态 (NULL)
    //    这确保了无论何时跳转到 cleanup，free() 调用都是安全的。
    hsc_master_key_pair* alice_mkp = NULL;
    char* alice_csr_pem = NULL;
    char* ca_key_pem = NULL;
    char* ca_cert_pem = NULL;
    char* alice_cert_pem = NULL;
    unsigned char* encrypted_file = NULL;
    unsigned char* encapsulated_session_key = NULL;
    unsigned char* decrypted_session_key = NULL;
    unsigned char* decrypted_file_content = NULL;

    // --- 初始化 ---
    printf("--- 高安全性混合加密系统 v4.0 内核库演示 ---\n");
    // [委员会建议] hsc_init() 是更符合架构的API
    if (hsc_init() != 0) {
        fprintf(stderr, "错误: 高安全内核库初始化失败！\n");
        goto cleanup;
    }
    printf("密码学库初始化成功。\n\n");

    // --- 阶段一 & 模拟 CA ---
    printf("--- 阶段一: 'Alice' 账户创建与证书签发 ---\n");
    const char* alice_username = "alice@example.com";
    
    // [委员会建议] hsc_generate_master_key_pair() 是正确的API
    alice_mkp = hsc_generate_master_key_pair();
    if (alice_mkp == NULL) {
        fprintf(stderr, "错误: 生成 Alice 的主密钥对失败。\n");
        goto cleanup;
    }
    
    // [委员会建议] hsc_generate_csr() 是正确的API
    if (hsc_generate_csr(alice_mkp, alice_username, &alice_csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 Alice 的 CSR 失败。\n");
        goto cleanup;
    }
    
    if (generate_test_ca(&ca_key_pem, &ca_cert_pem) != 0) {
        fprintf(stderr, "测试错误: 创建模拟 CA 失败。\n");
        goto cleanup;
    }

    if (sign_csr_with_ca(&alice_cert_pem, alice_csr_pem, ca_key_pem, ca_cert_pem) != 0) {
        fprintf(stderr, "测试错误: 签署用户证书失败。\n");
        goto cleanup;
    }
    printf("'Alice' 的证书已成功签发。\n\n");


    // 阶段三：文件加密与安全共享 (端到端演示)
    printf("--- 端到端共享演示: Alice 加密文件并分享给自己 ---\n");

    // 1. 本地加密 (生成会话密钥，加密文件内容)
    printf("1. 本地文件加密...\n");
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));
    print_hex("  > [明文] 会话密钥", session_key, sizeof(session_key));
    
    const char* file_content = "这是文件的机密内容。This is the secret content of the file.";
    printf("  > [明文] 文件内容: \"%s\"\n", file_content);
    
    size_t file_content_len = strlen(file_content);
    // [委员会建议] 使用 security_spec.h 或 hsc_kernel.h 中定义的常量
    size_t enc_file_buf_len = file_content_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    encrypted_file = malloc(enc_file_buf_len);
    if (!encrypted_file) {
        fprintf(stderr, "内存分配失败！\n");
        goto cleanup;
    }
    unsigned long long actual_enc_file_len;
    // [委员会注] 此处暂时保留内部调用，待架构重构后替换
    if (encrypt_symmetric_aead(encrypted_file, &actual_enc_file_len, (unsigned char*)file_content, file_content_len, session_key) != 0) {
        fprintf(stderr, "严重错误: 对称加密文件失败！\n");
        goto cleanup;
    }
    printf("  > 文件内容已使用 AEAD 对称加密。\n\n");
    
    // 2. 安全获取并验证接收者证书
    printf("2. 验证接收者 ('Alice') 的证书...\n");
    if (hsc_verify_user_certificate(alice_cert_pem, ca_cert_pem, alice_username) != 0) {
        fprintf(stderr, "严重错误: 接收者证书验证失败！中止共享。\n");
        goto cleanup;
    }
    printf("  > 接收者证书验证成功！\n\n");
    
    // 3. 从证书中提取接收者公钥
    printf("3. 从证书中提取接收者公钥...\n");
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(alice_cert_pem, recipient_pk) != 0) {
        fprintf(stderr, "严重错误: 无法从证书中提取公钥！\n");
        goto cleanup;
    }
    print_hex("  > 提取到的接收者公钥", recipient_pk, sizeof(recipient_pk));
    printf("\n");

    // 4. 封装会话密钥
    printf("4. 为接收者封装会话密钥...\n");
    size_t encapsulated_key_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_session_key = malloc(encapsulated_key_buf_len);
    if (!encapsulated_session_key) {
        fprintf(stderr, "内存分配失败！\n");
        goto cleanup;
    }
    
    size_t actual_encapsulated_len;
    if (hsc_encapsulate_session_key(encapsulated_session_key, &actual_encapsulated_len, session_key, sizeof(session_key),
                                recipient_pk, alice_mkp) != 0) {
        fprintf(stderr, "严重错误: 封装会话密钥失败！\n");
        goto cleanup;
    }
    printf("  > 会话密钥已使用 `crypto_box` (非对称加密) 封装。\n\n");
    
    printf("--- 文件上传包准备就绪 ---\n");
    printf("  - 加密的文件内容 (AEAD)\n");
    printf("  - 为接收者'Alice'封装的会话密钥 (crypto_box)\n");
    printf("--------------------------\n\n");

    // 演示：作为接收者解密
    printf("--- 作为接收者 'Alice' 解密文件 ---\n");

    // 1. 解封装会话密钥
    printf("1. 解封装会话密钥...\n");
    decrypted_session_key = secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) {
        fprintf(stderr, "安全内存分配失败！\n");
        goto cleanup;
    }

    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    // 为了自解密，我们需要从我们自己的密钥对中提取公钥
    hsc_extract_public_key_from_cert(alice_cert_pem, sender_pk);

    if (hsc_decapsulate_session_key(decrypted_session_key,
                                encapsulated_session_key, actual_encapsulated_len,
                                sender_pk,  // 发送者公钥
                                alice_mkp) != 0) { // 接收者密钥对
        fprintf(stderr, "解密错误: 无法解封装会话密钥！\n");
        goto cleanup;
    }
    print_hex("  > [解密] 恢复的会话密钥", decrypted_session_key, sizeof(session_key));

    if (sodium_memcmp(session_key, decrypted_session_key, sizeof(session_key)) != 0) {
        fprintf(stderr, "验证失败: 恢复的会话密钥与原始密钥不匹配！\n");
        // 这是一个验证失败，也应视为整体失败
        goto cleanup;
    } else {
        printf("  > 验证成功: 恢复的会话密钥与原始密钥匹配。\n\n");
    }

    // 2. 使用恢复的会话密钥解密文件内容
    printf("2. 使用恢复的会话密钥解密文件内容...\n");
    decrypted_file_content = malloc(file_content_len + 1);
     if (!decrypted_file_content) {
        fprintf(stderr, "内存分配失败！\n");
        goto cleanup;
    }
    unsigned long long actual_dec_file_len;
    // [委员会注] 暂时保留内部调用
    if (decrypt_symmetric_aead(decrypted_file_content, &actual_dec_file_len,
                               encrypted_file, actual_enc_file_len,
                               decrypted_session_key) != 0) {
        fprintf(stderr, "解密错误: 无法解密文件内容！\n");
        goto cleanup;
    }
    decrypted_file_content[actual_dec_file_len] = '\0';
    
    printf("  > [解密] 恢复的文件内容: \"%s\"\n", (char*)decrypted_file_content);
    if (strcmp(file_content, (char*)decrypted_file_content) == 0) {
        printf("  > 验证成功: 恢复的文件内容与原始内容匹配。\n\n");
    } else {
        printf("  > 验证失败: 恢复的文件内容与原始内容不匹配！\n\n");
        goto cleanup;
    }
    
    // [委员会修改] 3. 所有操作成功，设置成功返回码
    ret = 0; 
    printf("\033[32m--- 演示成功完成 ---\033[0m\n");

cleanup:
    // [委员会修改] 4. 统一的清理代码块，负责释放所有资源
    printf("\n--- 清理所有资源 ---\n");
    free(ca_key_pem);
    free(ca_cert_pem);
    
    // [委员会建议] hsc_free_pem_string() 是正确的API
    hsc_free_pem_string(alice_csr_pem);
    
    free(alice_cert_pem);

    // [委员会建议] hsc_free_master_key_pair() 是正确的API
    hsc_free_master_key_pair(&alice_mkp);
    
    free(encrypted_file);
    free(encapsulated_session_key);
    secure_free(decrypted_session_key);
    free(decrypted_file_content);

    // [委员会建议] hsc_cleanup() 是正确的API
    hsc_cleanup();
    printf("清理完成。\n");

    return ret;
}


// --- 辅助函数的实现 (这些函数无需修改，但为了完整性而保留) ---

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
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    
    // 初始化指针为 NULL
    *ca_key_pem = NULL;
    *ca_cert_pem = NULL;

    unsigned char ca_sk_seed[crypto_sign_SEEDBYTES];
    memset(ca_sk_seed, 0xCA, sizeof(ca_sk_seed));

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ca_sk_seed, sizeof(ca_sk_seed));
    if (!pkey) goto cleanup;

    cert = X509_new();
    if (!cert) goto cleanup;

    X509_set_version(cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 31536000L);
    X509_set_pubkey(cert, pkey);

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Test System Root CA", -1, -1, 0);
    X509_set_issuer_name(cert, name);

    add_ext(cert, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(cert, NID_key_usage, "critical,digitalSignature,keyCertSign,cRLSign");
    add_ext(cert, NID_subject_key_identifier, "hash");

    if (!X509_sign(cert, pkey, NULL)) goto cleanup;

    key_bio = BIO_new(BIO_s_mem());
    cert_bio = BIO_new(BIO_s_mem());
    if(!key_bio || !cert_bio) goto cleanup;

    if(!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL)) goto cleanup;
    if(!PEM_write_bio_X509(cert_bio, cert)) goto cleanup;
    
    BUF_MEM *key_mem, *cert_mem;
    BIO_get_mem_ptr(key_bio, &key_mem);
    *ca_key_pem = (char*)malloc(key_mem->length + 1);
    if (!*ca_key_pem) goto cleanup;
    memcpy(*ca_key_pem, key_mem->data, key_mem->length);
    (*ca_key_pem)[key_mem->length] = '\0';

    BIO_get_mem_ptr(cert_bio, &cert_mem);
    *ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    if (!*ca_cert_pem) goto cleanup;
    memcpy(*ca_cert_pem, cert_mem->data, cert_mem->length);
    (*ca_cert_pem)[cert_mem->length] = '\0';
    
    ret = 0;

cleanup:
    if (ret != 0) { // 如果失败，确保释放已分配的内存
        free(*ca_key_pem);
        *ca_key_pem = NULL;
        free(*ca_cert_pem);
        *ca_cert_pem = NULL;
    }
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(key_bio);
    BIO_free(cert_bio);
    return ret;
}

int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem, const char* ca_key_pem, const char* ca_cert_pem) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
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

    user_cert = X509_new();
    if(!user_cert) goto cleanup;

    X509_set_version(user_cert, 2L);
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), 2);
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), 31536000L);
    
    req_pubkey = X509_REQ_get_pubkey(req);
    if (!req_pubkey) goto cleanup;
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    
    // 为测试OCSP添加AIA扩展
    add_ext(user_cert, NID_info_access, "OCSP;URI:http://ocsp.example.com");

    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem());
    if(!out_bio) goto cleanup;

    if(!PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
    BUF_MEM *out_mem;
    BIO_get_mem_ptr(out_bio, &out_mem);
    *user_cert_pem = (char*)malloc(out_mem->length + 1);
    if (!*user_cert_pem) goto cleanup;
    memcpy(*user_cert_pem, out_mem->data, out_mem->length);
    (*user_cert_pem)[out_mem->length] = '\0';

    ret = 0;

cleanup:
    if (ret != 0) {
        free(*user_cert_pem);
        *user_cert_pem = NULL;
    }
    EVP_PKEY_free(req_pubkey);
    BIO_free(csr_bio);
    BIO_free(ca_key_bio);
    BIO_free(ca_cert_bio);
    BIO_free(out_bio);
    X509_REQ_free(req);
    EVP_PKEY_free(ca_key);
    X509_free(ca_cert);
    X509_free(user_cert);
    return ret;
}

// --- END OF FILE src/main.c (FIXED by Code Review Committee) ---