/**
 * @file pki_handler.c
 * @brief PKI 相关操作的实现。
 *
 * @details
 * 本文件使用 OpenSSL 库处理 X.509 证书操作，并使用 libcurl 库执行
 * OCSP (在线证书状态协议) 网络请求，以实现实时的证书吊销检查。
 * 代码中包含了详细的错误处理和资源管理，以确保安全性和健壮性。
 */

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ocsp.h>
#include <curl/curl.h>

#include "pki_handler.h"
#include "../common/secure_memory.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ======================= 错误报告宏 =======================
// 在调试模式下，打印详细的 OpenSSL 错误信息，便于调试。
// 在发布模式下，打印通用的安全错误信息，避免向最终用户泄露过多内部细节。
#ifdef DEBUG_MODE
#define LOG_PKI_ERROR(msg) do { \
    fprintf(stderr, "PKI Error (Debug): %s (in %s:%d)\n", msg, __FILE__, __LINE__); \
    ERR_print_errors_fp(stderr); \
} while(0)
#define LOG_PKI_ERROR_FMT(fmt, ...) do { \
    fprintf(stderr, "PKI Error (Debug): " fmt " (in %s:%d)\n", __VA_ARGS__, __FILE__, __LINE__); \
    ERR_print_errors_fp(stderr); \
} while(0)
#else
#define LOG_PKI_ERROR(msg) \
    fprintf(stderr, "Error: A critical security operation related to PKI could not be completed.\n")
#define LOG_PKI_ERROR_FMT(fmt, ...) \
    fprintf(stderr, "Error: A critical security operation related to PKI could not be completed.\n")
#endif


// ======================= 初始化与清理 =======================

int pki_init() {
    // 初始化 libcurl 用于网络操作 (OCSP)
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_PKI_ERROR("Failed to initialize libcurl.");
        return -1;
    }
    // 初始化 OpenSSL 库，加载错误字符串等
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        LOG_PKI_ERROR("Failed to initialize OpenSSL crypto library.");
        return -1;
    }
    // 为 OpenSSL 3.0+ 加载默认的算法提供者 (provider)
    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        LOG_PKI_ERROR("Failed to load OpenSSL default provider.");
        // 注意：这里不需要手动卸载 provider，应用退出时会自动处理。
        return -1;
    }
    return 0;
}

void free_csr_pem(char* csr_pem) {
    // 由于这个内存是通过 OpenSSL 的 BIO -> BUF_MEM 获取并手动 malloc 的，
    // 所以直接使用 free 释放是正确的。
    if (csr_pem != NULL) {
        free(csr_pem);
    }
}

// ======================= CSR 生成 =======================

int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL || mkp->sk == NULL || username == NULL || out_csr_pem == NULL) {
        return -1;
    }
    *out_csr_pem = NULL;

    int ret = -1;
    EVP_PKEY* pkey = NULL;
    X509_REQ* req = NULL;
    BIO* bio = NULL;
    X509_NAME* subject = NULL;
    
    // 安全关键点: libsodium 的 Ed25519 私钥 (64字节) 包含了种子 (前32字节) 和公钥 (后32字节)。
    // OpenSSL 的 EVP_PKEY_new_raw_private_key 需要的是原始的 32 字节种子。
    unsigned char private_seed[crypto_sign_SEEDBYTES];
    crypto_sign_ed25519_sk_to_seed(private_seed, mkp->sk);

    // 使用种子在 OpenSSL 中重建 EVP_PKEY 对象。
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_seed, sizeof(private_seed));

    // **[安全强化]** 无论 pkey 创建是否成功，都必须立即擦除栈上的私钥种子副本，
    // 以最大限度地减少其在内存中的暴露时间。
    secure_zero_memory(private_seed, sizeof(private_seed));

    if (!pkey) { LOG_PKI_ERROR("EVP_PKEY_new_raw_private_key failed."); goto cleanup; }
    
    req = X509_REQ_new();
    if (!req) { LOG_PKI_ERROR("X509_REQ_new failed."); goto cleanup; }
    
    X509_REQ_set_version(req, 0L); // CSR 版本为 v1 (值为 0)

    subject = X509_REQ_get_subject_name(req);
    if (!subject) { LOG_PKI_ERROR("X509_REQ_get_subject_name failed."); goto cleanup; }

    // 将用户名设置为 CSR 的 Common Name (CN)
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)username, -1, -1, 0)) {
        LOG_PKI_ERROR("X509_NAME_add_entry_by_txt failed."); goto cleanup;
    }

    // 设置公钥并用私钥签名 CSR
    if (X509_REQ_set_pubkey(req, pkey) <= 0) { LOG_PKI_ERROR("X509_REQ_set_pubkey failed."); goto cleanup; }
    if (X509_REQ_sign(req, pkey, NULL) <= 0) { LOG_PKI_ERROR("X509_REQ_sign failed."); goto cleanup; } // 使用默认摘要算法

    // 将 CSR 写入内存 BIO
    bio = BIO_new(BIO_s_mem());
    if (!bio) { LOG_PKI_ERROR("BIO_new failed."); goto cleanup; }
    
    if (!PEM_write_bio_X509_REQ(bio, req)) { LOG_PKI_ERROR("PEM_write_bio_X509_REQ failed."); goto cleanup; }

    // 从 BIO 中提取 PEM 字符串
    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        *out_csr_pem = (char*)malloc(mem->length + 1);
        if (*out_csr_pem) {
            memcpy(*out_csr_pem, mem->data, mem->length);
            (*out_csr_pem)[mem->length] = '\0';
            ret = 0; // 成功
        } else {
             LOG_PKI_ERROR("malloc failed for CSR PEM string.");
        }
    }
    
cleanup:
    // 统一释放所有已分配的 OpenSSL 资源
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return ret;
}

// ======================= OCSP 吊销检查 =======================

// 用于 libcurl 写入回调的内存结构体
struct memory_chunk {
    char* memory;
    size_t size;
    size_t capacity;
};

// libcurl 的回调函数，用于将下载的数据写入内存
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*)userp;

    // 动态扩展缓冲区
    if (mem->size + realsize + 1 > mem->capacity) {
        size_t new_capacity = (mem->capacity > 0) ? mem->capacity * 2 : 1024;
        if (new_capacity < mem->size + realsize + 1) new_capacity = mem->size + realsize + 1;

        char* ptr = realloc(mem->memory, new_capacity);
        if (ptr == NULL) {
            fprintf(stderr, "OCSP Error: not enough memory (realloc returned NULL)\n");
            return 0; // 返回 0 会使 libcurl 停止并报告错误
        }
        mem->memory = ptr;
        mem->capacity = new_capacity;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0; // 保持 null 结尾

    return realsize;
}

// 使用 libcurl 执行 HTTP POST 请求
static struct memory_chunk perform_http_post(const char* url, const unsigned char* data, size_t data_len) {
    CURL* curl;
    struct memory_chunk chunk = { .memory = NULL, .size = 0, .capacity = 0 };

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");

        // 设置网络超时以增强健壮性
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L); // 5秒连接超时
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);      // 10秒总操作超时

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L); // 强制验证对端证书

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "OCSP Error: HTTP request to %s failed: %s\n", url, curl_easy_strerror(res));
            // **[BUG FIX]** 修复内存泄漏：当网络请求失败时，释放已经分配的内存。
            free(chunk.memory);
            chunk.memory = NULL;
            chunk.size = 0;
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    return chunk;
}

// 核心的 OCSP 状态检查函数
static int check_ocsp_status(X509* user_cert, X509* issuer_cert, X509_STORE* store) {
    int ret = -1; // 默认失败
    OCSP_REQUEST* ocsp_req = NULL;
    OCSP_CERTID* cid = NULL;
    OCSP_RESPONSE* ocsp_resp = NULL;
    OCSP_BASICRESP* bresp = NULL;
    BIO* req_bio = NULL;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = NULL;

    printf("      iv. [Checking Revocation Status (OCSP)]:\n");

    // 1. 从用户证书的 AIA (Authority Information Access) 扩展中提取 OCSP 服务器 URI
    ocsp_uris = X509_get1_ocsp(user_cert);
    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        fprintf(stderr, "         > FAILED: No OCSP URI found in certificate. Cannot verify revocation status.\n");
        ret = -4;
        goto cleanup;
    }
    // 只使用第一个找到的 URI
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    printf("         > OCSP Server: %s\n", ocsp_uri);

    // 2. 构建 OCSP 请求
    ocsp_req = OCSP_REQUEST_new();
    if (!ocsp_req) { LOG_PKI_ERROR("OCSP_REQUEST_new failed"); goto cleanup; }
    
    // 创建要查询的证书ID (基于颁发者名称和密钥的哈希以及证书序列号)
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) { LOG_PKI_ERROR("OCSP_cert_to_id failed"); goto cleanup; }
    
    // 将证书ID添加到请求中
    if (!OCSP_request_add0_id(ocsp_req, cid)) {
        // **[BUG FIX]** 如果添加失败，cid 的所有权没有转移，必须手动释放
        OCSP_CERTID_free(cid);
        cid = NULL; 
        LOG_PKI_ERROR("OCSP_request_add0_id failed"); 
        goto cleanup; 
    }
    cid = NULL; // 成功后，cid 的所有权已转移给 ocsp_req，将本地指针置空

    // 3. 发送 OCSP 请求
    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, ocsp_req)) { LOG_PKI_ERROR("i2d_OCSP_REQUEST_bio failed"); goto cleanup; }
    
    unsigned char* req_data = NULL;
    long req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);
    
    // "故障关闭"策略：任何网络失败或空响应都视为验证失败
    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        fprintf(stderr, "         > FAILED: Could not retrieve a valid response from the OCSP server.\n");
        if(response_chunk.memory) free(response_chunk.memory);
        ret = -4;
        goto cleanup;
    }
    
    // 4. 解析 OCSP 响应
    const unsigned char* p = (const unsigned char*)response_chunk.memory;
    ocsp_resp = d2i_OCSP_RESPONSE(NULL, &p, response_chunk.size);
    free(response_chunk.memory);
    if (!ocsp_resp) { LOG_PKI_ERROR("Failed to parse OCSP response."); ret = -4; goto cleanup; }

    if (OCSP_response_status(ocsp_resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOG_PKI_ERROR_FMT("OCSP response status was not successful: %s", OCSP_response_status_str(OCSP_response_status(ocsp_resp)));
        ret = -4; goto cleanup;
    }

    // 5. 验证 OCSP 响应
    bresp = OCSP_response_get1_basic(ocsp_resp);
    if (!bresp) { LOG_PKI_ERROR("Could not get Basic OCSP Response."); ret = -4; goto cleanup; }

    // 验证 OCSP 响应的签名是否有效 (通常由 OCSP Responder 证书签名，该证书应由 CA 签发)
    if (OCSP_basic_verify(bresp, NULL, store, 0) <= 0) {
        LOG_PKI_ERROR("OCSP response signature verification failed.");
        ret = -4; goto cleanup;
    }

    // 6. 检查证书状态
    int status, reason;
    ASN1_GENERALIZEDTIME* rev_time = NULL, *this_update = NULL, *next_update = NULL;
    
    // 重新创建证书ID以在响应中查找
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) { LOG_PKI_ERROR("OCSP_cert_to_id failed for response lookup"); goto cleanup; }

    // 在响应中查找我们证书的状态
    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
        fprintf(stderr, "         > FAILED: Status for this certificate not found in the OCSP response.\n");
        ret = -4; goto cleanup;
    }

    // 检查 OCSP 响应本身是否在有效期内（防止重放攻击）
    if (OCSP_check_validity(this_update, next_update, 300L, -1L) <= 0) {
        LOG_PKI_ERROR("OCSP response is not within its validity period (stale response).");
        ret = -4; goto cleanup;
    }

    // 最终判断证书状态
    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            printf("         > SUCCESS: OCSP status is 'Good'. Certificate has not been revoked.\n");
            ret = 0; // 只有这里才是唯一的成功路径
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            fprintf(stderr, "         > FAILED: OCSP status is 'Revoked'. Certificate has been revoked!\n");
            ret = -4;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            fprintf(stderr, "         > FAILED: OCSP status is 'Unknown'. Cannot confirm certificate validity.\n");
            ret = -4;
            break;
        default:
             LOG_PKI_ERROR("Unknown OCSP certificate status code encountered.");
             ret = -1;
             break;
    }

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_REQUEST_free(ocsp_req);
    OCSP_RESPONSE_free(ocsp_resp);
    OCSP_BASICRESP_free(bresp);
    BIO_free(req_bio);
    if (ocsp_uris) X509_get1_ocsp_free(ocsp_uris); // 使用对应的释放函数
    return ret;
}

// ======================= 核心验证函数 =======================

int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username) {
    if (user_cert_pem == NULL || trusted_ca_cert_pem == NULL || expected_username == NULL) {
        return -1;
    }

    int ret_code = -1; // 默认一般错误

    BIO* user_bio = NULL;
    BIO* ca_bio = NULL;
    X509* user_cert = NULL;
    X509* ca_cert = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;

    // 1. 将 PEM 字符串加载到 OpenSSL 的 X509 对象中
    user_bio = BIO_new_mem_buf(user_cert_pem, -1);
    ca_bio = BIO_new_mem_buf(trusted_ca_cert_pem, -1);
    if (!user_bio || !ca_bio) { LOG_PKI_ERROR("Failed to create BIO for certificates."); goto cleanup; }
    
    user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    if (!user_cert || !ca_cert) { LOG_PKI_ERROR("Failed to parse PEM certificates."); goto cleanup; }

    // 2. 验证签名链和有效期
    printf("    Step i & ii (Chain & Validity Period):\n");
    store = X509_STORE_new();
    if (!store) { LOG_PKI_ERROR("X509_STORE_new failed."); goto cleanup; }
    
    // 将受信任的 CA 证书添加到证书存储区
    if (X509_STORE_add_cert(store, ca_cert) != 1) { LOG_PKI_ERROR("Failed to add CA cert to store."); goto cleanup; }
    
    // 创建验证上下文
    ctx = X509_STORE_CTX_new();
    if (!ctx) { LOG_PKI_ERROR("X509_STORE_CTX_new failed."); goto cleanup; }

    // 初始化上下文：我们要用 `store` 中的 CA 来验证 `user_cert`
    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) { LOG_PKI_ERROR("Failed to initialize verification context."); goto cleanup; }
    
    // 执行验证
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "      > FAILED: %s\n", X509_verify_cert_error_string(err));
        ret_code = -2; // 签名链或有效期错误
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate is signed by a trusted CA and is within its validity period.\n");

    // 3. 验证主体身份
    printf("    Step iii (Subject Verification):\n");
    X509_NAME* subject_name = X509_get_subject_name(user_cert);
    if (!subject_name) { LOG_PKI_ERROR("Could not get subject name."); ret_code = -3; goto cleanup; }

    char cn[256] = {0}; // 缓冲区足够大以容纳 Common Name
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn));
    if (cn_len < 0) {
        LOG_PKI_ERROR("Could not extract Common Name from certificate.");
        ret_code = -3;
        goto cleanup;
    }

    if (strcmp(expected_username, cn) != 0) {
        fprintf(stderr, "      > FAILED: Certificate subject mismatch! Expected '%s', but got '%s'.\n", expected_username, cn);
        ret_code = -3; // 主体不匹配
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate subject matches the expected user '%s'.\n", expected_username);

    // 4. 验证吊销状态
    int ocsp_res = check_ocsp_status(user_cert, ca_cert, store);
    if (ocsp_res != 0) {
        ret_code = ocsp_res; // 使用 ocsp_check 返回的特定错误码 (-4 或 -1)
        goto cleanup;
    }

    // 所有检查通过
    ret_code = 0;

cleanup:
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(user_cert);
    X509_free(ca_cert);
    BIO_free(user_bio);
    BIO_free(ca_bio);
    
    return ret_code;
}

// ======================= 公钥提取 =======================

int extract_public_key_from_cert(const char* user_cert_pem,
                                 unsigned char* public_key_out) {
    if (user_cert_pem == NULL || public_key_out == NULL) {
        return -1;
    }
    int ret = -1;
    BIO* cert_bio = BIO_new_mem_buf(user_cert_pem, -1);
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    if (!cert_bio) goto cleanup;
    
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) { LOG_PKI_ERROR("Failed to parse certificate PEM for public key extraction."); goto cleanup; }

    pkey = X509_get_pubkey(cert);
    if (!pkey) { LOG_PKI_ERROR("Failed to get public key from certificate."); goto cleanup; }
    
    // 验证公钥类型是否为我们期望的 Ed25519
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        LOG_PKI_ERROR("Public key in certificate is not of the expected type (Ed25519).");
        goto cleanup;
    }
    
    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    // 提取原始的公钥字节
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 || pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
        LOG_PKI_ERROR("Failed to get raw public key bytes from certificate.");
        goto cleanup;
    }
    
    ret = 0; // 成功

cleanup:
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(cert_bio);
    return ret;
}