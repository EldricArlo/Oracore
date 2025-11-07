#include "pki_handler.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h> // 【新增】包含 provider 头文件
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// --- 新增的初始化函数 ---
int pki_init() {
    // 为 OpenSSL 3.x 加载默认的算法提供者。
    // 这对于确保像 Ed25519 这样的算法可用至关重要。
    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        fprintf(stderr, "PKI Error: Failed to load OpenSSL default provider.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    // 对于一个长时间运行的程序，可以在程序退出时调用 OSSL_PROVIDER_unload(provider)。
    // 对于我们的客户端应用，在程序生命周期内保持加载状态是完全可以的。
    return 0;
}


void free_csr_pem(char* csr_pem) {
    if (csr_pem != NULL) {
        // PEM 字符串是由 OpenSSL 的 BIO 内存操作分配的，
        // 但最终可以通过标准 free() 释放。
        free(csr_pem);
    }
}

int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem) {
    assert(mkp != NULL && mkp->sk != NULL && username != NULL && out_csr_pem != NULL);
    *out_csr_pem = NULL;

    int ret = -1; // 默认返回失败
    
    // --- 步骤 1: 将 libsodium 的 raw key 转换为 OpenSSL 的 EVP_PKEY 结构 ---
    // 主密钥对现在是 Ed25519，专门用于签名。
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, mkp->sk, MASTER_SECRET_KEY_BYTES);
    if (!pkey) {
        fprintf(stderr, "PKI Error: EVP_PKEY_new_raw_private_key failed.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // --- 步骤 2: 创建 CSR (X509_REQ) 对象 ---
    X509_REQ* req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "PKI Error: X509_REQ_new failed.\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    // 设置版本号 (通常为 0)
    X509_REQ_set_version(req, 0);

    // --- 步骤 3: 设置 CSR 的主题 (Subject) ---
    X509_NAME* subject = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)username, -1, -1, 0)) {
        fprintf(stderr, "PKI Error: X509_NAME_add_entry_by_txt failed.\n");
        goto cleanup; // 使用 goto 进行统一的错误清理
    }

    // --- 步骤 4: 设置 CSR 的公钥 ---
    if (X509_REQ_set_pubkey(req, pkey) <= 0) {
        fprintf(stderr, "PKI Error: X509_REQ_set_pubkey failed.\n");
        goto cleanup;
    }

    // --- 步骤 5: 使用私钥签署 CSR ---
    // 对于 Ed25519 (纯签名算法)，摘要算法参数应为 NULL。
    if (X509_REQ_sign(req, pkey, NULL) <= 0) {
        fprintf(stderr, "PKI Error: X509_REQ_sign failed.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // --- 步骤 6: 将 CSR 对象转换为 PEM 格式的字符串 ---
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "PKI Error: BIO_new failed.\n");
        goto cleanup;
    }
    
    if (!PEM_write_bio_X509_REQ(bio, req)) {
        fprintf(stderr, "PKI Error: PEM_write_bio_X509_REQ failed.\n");
        BIO_free(bio);
        goto cleanup;
    }

    // 从 BIO 内存缓冲区中获取数据
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        *out_csr_pem = (char*)malloc(mem->length + 1);
        if (*out_csr_pem) {
            memcpy(*out_csr_pem, mem->data, mem->length);
            (*out_csr_pem)[mem->length] = '\0';
            ret = 0; // 成功！
        }
    }
    
    BIO_free(bio);

cleanup:
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);

    return ret;
}

// 这是一个模拟函数，用于演示OCSP检查的流程点。
// 在生产环境中，这里需要实现一个真正的HTTP客户端来向OCSP服务器发送请求。
static int check_ocsp_status_mock(X509* user_cert, X509* issuer_cert) {
    // 通过将参数转换为 (void) 来显式地告诉编译器
    // 我们知道这些参数在此模拟函数中未使用，以消除警告。
    (void)user_cert;
    (void)issuer_cert;

    printf("      iv. [检查吊销状态 (OCSP)]: ");
    
    // 为本演示的目的，我们假定检查总是成功的。
    printf("模拟 OCSP 响应 'Good'。证书未被吊销。\n");
    return 0; // 0 表示成功 (未吊销)
}


int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username) {
    assert(user_cert_pem != NULL && trusted_ca_cert_pem != NULL && expected_username != NULL);

    int ret_code = -1; // 默认一般性错误

    // --- 准备工作: 将 PEM 字符串加载到 OpenSSL 的 X509 对象中 ---
    BIO* user_bio = BIO_new_mem_buf(user_cert_pem, -1);
    BIO* ca_bio = BIO_new_mem_buf(trusted_ca_cert_pem, -1);
    X509* user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    X509* ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;

    if (!user_cert || !ca_cert) {
        fprintf(stderr, "Verify Error: Failed to parse PEM certificates.\n");
        goto cleanup;
    }

    // --- 步骤 i: 验证签名链 & ii: 检查有效期 ---
    printf("    验证步骤 i & ii (签名链 和 有效期):\n");
    store = X509_STORE_new();
    if (!store) goto cleanup;
    
    // 将根 CA 添加到我们的信任库中
    if (X509_STORE_add_cert(store, ca_cert) != 1) {
        fprintf(stderr, "Verify Error: Failed to add CA cert to store.\n");
        goto cleanup;
    }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) goto cleanup;

    // 初始化验证上下文：我们要用 'store' 中的信任锚来验证 'user_cert'
    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) {
        fprintf(stderr, "Verify Error: Failed to initialize verification context.\n");
        goto cleanup;
    }
    
    // 执行验证！
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "      > 失败: %s\n", X509_verify_cert_error_string(err));
        ret_code = -2; // 签名链或有效期验证失败
        goto cleanup;
    }
    printf("      > 成功: 证书由受信任的 CA 签署且在有效期内。\n");

    // --- 步骤 iii: 核对主体 ---
    printf("    验证步骤 iii (核对主体):\n");
    X509_NAME* subject_name = X509_get_subject_name(user_cert);
    char cn[256]; // 缓冲区用于存放 Common Name
    
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
    if (cn_len < 0) {
        fprintf(stderr, "      > 失败: 无法从证书中提取 Common Name。\n");
        ret_code = -3;
        goto cleanup;
    }

    if (strcmp(expected_username, cn) != 0) {
        fprintf(stderr, "      > 失败: 证书主体不匹配！预期 '%s', 实际 '%s'。\n", expected_username, cn);
        ret_code = -3; // 主体不匹配
        goto cleanup;
    }
    printf("      > 成功: 证书主体与预期用户 '%s' 匹配。\n", expected_username);

    // --- 步骤 iv: 检查吊销状态 (实时) ---
    if (check_ocsp_status_mock(user_cert, ca_cert) != 0) {
        fprintf(stderr, "      > 失败: 证书已被吊销！\n");
        ret_code = -4; // 证书被吊销
        goto cleanup;
    }

    // 所有检查都通过了！
    ret_code = 0;

cleanup:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    if (user_cert) X509_free(user_cert);
    if (ca_cert) X509_free(ca_cert);
    if (user_bio) BIO_free(user_bio);
    if (ca_bio) BIO_free(ca_bio);
    
    return ret_code;
}

int extract_public_key_from_cert(const char* user_cert_pem,
                                 unsigned char* public_key_out) {
    assert(user_cert_pem != NULL && public_key_out != NULL);

    int ret = -1;
    BIO* cert_bio = BIO_new_mem_buf(user_cert_pem, -1);
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    if (!cert_bio) goto cleanup;

    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Extract PK Error: Failed to parse certificate PEM.\n");
        goto cleanup;
    }

    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Extract PK Error: Failed to get public key from certificate.\n");
        goto cleanup;
    }
    
    // 检查密钥类型是否是我们期望的 Ed25519
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        fprintf(stderr, "Extract PK Error: Public key is not of type Ed25519.\n");
        goto cleanup;
    }

    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 ||
        pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
        fprintf(stderr, "Extract PK Error: Failed to get raw public key bytes.\n");
        goto cleanup;
    }
    
    ret = 0; // 成功

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);
    return ret;
}