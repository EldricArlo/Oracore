#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <curl/curl.h>

#include "pki_handler.h"
#include "../common/secure_memory.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ======================= 错误报告宏 =======================
// 使用此宏来控制错误报告的详细程度。
// 在编译时通过 -DDEBUG_MODE 标志启用详细错误（包括OpenSSL错误栈）。
// 在生产构建中，它只会打印通用的错误消息，以避免泄露内部实现细节。
#ifdef DEBUG_MODE
#define LOG_PKI_ERROR(msg) do { \
    fprintf(stderr, "PKI Error (Debug): %s\n", msg); \
    ERR_print_errors_fp(stderr); \
} while(0)
#define LOG_PKI_ERROR_FMT(fmt, ...) do { \
    fprintf(stderr, "PKI Error (Debug): " fmt "\n", __VA_ARGS__); \
    ERR_print_errors_fp(stderr); \
} while(0)
#else
#define LOG_PKI_ERROR(msg) \
    fprintf(stderr, "Error: A critical security operation could not be completed.\n")
#define LOG_PKI_ERROR_FMT(fmt, ...) \
    fprintf(stderr, "Error: A critical security operation could not be completed.\n")
#endif


// --- 初始化函数 ---
int pki_init() {
    // 为多线程安全初始化 libcurl。此函数是全局的，可以安全地多次调用。
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_PKI_ERROR("Failed to initialize libcurl.");
        return -1;
    }

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        LOG_PKI_ERROR("Failed to initialize OpenSSL crypto library.");
        return -1;
    }

    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        LOG_PKI_ERROR("Failed to load OpenSSL default provider.");
        return -1;
    }
    return 0;
}


void free_csr_pem(char* csr_pem) {
    if (csr_pem != NULL) {
        free(csr_pem);
    }
}

int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL || mkp->sk == NULL || username == NULL || out_csr_pem == NULL) {
        return -1;
    }
    *out_csr_pem = NULL;

    int ret = -1;
    EVP_PKEY* pkey = NULL;
    X509_REQ* req = NULL;
    BIO* bio = NULL;
    
    // 步骤 1: 显式地从 libsodium 的 64 字节私钥中提取出 32 字节的种子。
    // 这是安全的、符合 API 规范的做法，避免了依赖 libsodium 内部的密钥格式。
    unsigned char private_seed[crypto_sign_SEEDBYTES];
    crypto_sign_ed25519_sk_to_seed(private_seed, mkp->sk);

    // 步骤 2: 使用提取出的种子来创建 OpenSSL 的 EVP_PKEY 对象。
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_seed, sizeof(private_seed));
    
    // 步骤 3: 立即安全地擦除栈上的种子副本，使其在内存中的生命周期尽可能短。
    secure_zero_memory(private_seed, sizeof(private_seed));

    if (!pkey) {
        LOG_PKI_ERROR("EVP_PKEY_new_raw_private_key failed.");
        goto cleanup;
    }
    
    req = X509_REQ_new();
    if (!req) {
        LOG_PKI_ERROR("X509_REQ_new failed.");
        goto cleanup;
    }
    
    X509_REQ_set_version(req, 0);

    X509_NAME* subject = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)username, -1, -1, 0)) {
        LOG_PKI_ERROR("X509_NAME_add_entry_by_txt failed.");
        goto cleanup;
    }

    if (X509_REQ_set_pubkey(req, pkey) <= 0) {
        LOG_PKI_ERROR("X509_REQ_set_pubkey failed.");
        goto cleanup;
    }

    if (X509_REQ_sign(req, pkey, NULL) <= 0) {
        LOG_PKI_ERROR("X509_REQ_sign failed.");
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        LOG_PKI_ERROR("BIO_new failed.");
        goto cleanup;
    }
    
    if (!PEM_write_bio_X509_REQ(bio, req)) {
        LOG_PKI_ERROR("PEM_write_bio_X509_REQ failed.");
        goto cleanup;
    }

    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        *out_csr_pem = (char*)malloc(mem->length + 1);
        if (*out_csr_pem) {
            memcpy(*out_csr_pem, mem->data, mem->length);
            (*out_csr_pem)[mem->length] = '\0';
            ret = 0;
        } else {
             LOG_PKI_ERROR("malloc failed for CSR PEM string.");
        }
    }
    
cleanup:
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return ret;
}

struct memory_chunk {
    char* memory;
    size_t size;
    size_t capacity;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*)userp;

    if (mem->size + realsize + 1 > mem->capacity) {
        size_t new_capacity = (mem->capacity > 0) ? mem->capacity * 2 : 1024;
        if (new_capacity < mem->size + realsize + 1) {
            new_capacity = mem->size + realsize + 1;
        }

        char* ptr = realloc(mem->memory, new_capacity);
        if (ptr == NULL) {
            // 在此场景下，打印具体错误是安全的，因为它不泄露加密细节
            fprintf(stderr, "OCSP Error: not enough memory (realloc returned NULL)\n");
            return 0;
        }
        mem->memory = ptr;
        mem->capacity = new_capacity;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// 使用 libcurl 执行 HTTP POST 请求的辅助函数
static struct memory_chunk perform_http_post(const char* url, const unsigned char* data, size_t data_len) {
    CURL* curl;
    CURLcode res;
    struct memory_chunk chunk = { .memory = NULL, .size = 0, .capacity = 0 };

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            // 对于网络错误，向用户显示具体错误是有用的
            fprintf(stderr, "OCSP Error: HTTP request failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
            chunk.size = 0;
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    return chunk;
}

// 真实的OCSP检查函数
static int check_ocsp_status(X509* user_cert, X509* issuer_cert, X509_STORE* store) {
    int ret = -1;
    OCSP_REQUEST* req = NULL;
    OCSP_CERTID* cid = NULL;
    OCSP_RESPONSE* resp = NULL;
    OCSP_BASICRESP* bresp = NULL;
    BIO* req_bio = NULL;
    unsigned char* req_data = NULL;
    long req_len;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = NULL;

    printf("      iv. [检查吊销状态 (OCSP)]:\n");

    ocsp_uris = X509_get1_ocsp(user_cert);
    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        fprintf(stderr, "         > 失败: 证书中未找到 OCSP URI。无法验证吊销状态。\n");
        ret = -4;
        goto cleanup;
    }
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    printf("         > OCSP 服务器: %s\n", ocsp_uri);

    req = OCSP_REQUEST_new();
    if (!req) goto cleanup;
    
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) goto cleanup;
    if (!OCSP_request_add0_id(req, cid)) {
        OCSP_CERTID_free(cid);
        goto cleanup;
    }
    cid = NULL;

    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, req)) goto cleanup;
    
    req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);
    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        fprintf(stderr, "         > 失败: 未能从 OCSP 服务器获取响应。\n");
        if(response_chunk.memory) free(response_chunk.memory);
        ret = -4;
        goto cleanup;
    }
    
    const unsigned char* p = (const unsigned char*)response_chunk.memory;
    resp = d2i_OCSP_RESPONSE(NULL, &p, response_chunk.size);
    free(response_chunk.memory);
    if (!resp) {
        LOG_PKI_ERROR("Failed to parse OCSP response.");
        goto cleanup;
    }

    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOG_PKI_ERROR_FMT("OCSP response status was not successful: %s", OCSP_response_status_str(OCSP_response_status(resp)));
        goto cleanup;
    }

    bresp = OCSP_response_get1_basic(resp);
    if (!bresp) {
        LOG_PKI_ERROR("Could not get Basic OCSP Response from response.");
        goto cleanup;
    }

    if (OCSP_basic_verify(bresp, NULL, store, 0) <= 0) {
        LOG_PKI_ERROR("OCSP response signature verification failed.");
        goto cleanup;
    }

    int status, reason;
    ASN1_GENERALIZEDTIME* rev_time = NULL, *this_update = NULL, *next_update = NULL;
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) goto cleanup;

    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
        // 这是策略失败，而不是系统错误，因此显示具体消息
        fprintf(stderr, "         > 失败: 在OCSP响应中找不到此证书的状态。\n");
        goto cleanup;
    }

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            printf("         > 成功: OCSP 响应 'Good'。证书未被吊销。\n");
            ret = 0;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            fprintf(stderr, "         > 失败: OCSP 响应 'Revoked'。证书已被吊销！\n");
            ret = -4;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            fprintf(stderr, "         > 失败: OCSP 响应 'Unknown'。证书状态未知。\n");
            ret = -4;
            break;
        default:
             LOG_PKI_ERROR("Unknown OCSP certificate status code encountered.");
             ret = -1;
             break;
    }

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bresp);
    BIO_free(req_bio);
    if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
    return ret;
}

int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username) {
    if (user_cert_pem == NULL || trusted_ca_cert_pem == NULL || expected_username == NULL) {
        return -1;
    }

    int ret_code = -1;

    BIO* user_bio = BIO_new_mem_buf(user_cert_pem, -1);
    BIO* ca_bio = BIO_new_mem_buf(trusted_ca_cert_pem, -1);
    X509* user_cert = NULL;
    X509* ca_cert = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;

    if (!user_bio || !ca_bio) {
        LOG_PKI_ERROR("Failed to create BIO for certificates.");
        goto cleanup;
    }
    user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    if (!user_cert || !ca_cert) {
        LOG_PKI_ERROR("Failed to parse PEM certificates.");
        goto cleanup;
    }

    printf("    验证步骤 i & ii (签名链 和 有效期):\n");
    store = X509_STORE_new();
    if (!store) goto cleanup;
    
    if (X509_STORE_add_cert(store, ca_cert) != 1) {
        LOG_PKI_ERROR("Failed to add CA cert to store.");
        goto cleanup;
    }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) goto cleanup;

    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) {
        LOG_PKI_ERROR("Failed to initialize verification context.");
        goto cleanup;
    }
    
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        // 向用户显示具体的验证失败原因非常重要
        fprintf(stderr, "      > 失败: %s\n", X509_verify_cert_error_string(err));
        ret_code = -2;
        goto cleanup;
    }
    printf("      > 成功: 证书由受信任的 CA 签署且在有效期内。\n");

    printf("    验证步骤 iii (核对主体):\n");
    X509_NAME* subject_name = X509_get_subject_name(user_cert);
    char cn[256] = {0};
    
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn) - 1);
    if (cn_len < 0) {
        LOG_PKI_ERROR("Could not extract Common Name from certificate.");
        ret_code = -3;
        goto cleanup;
    }

    if (strcmp(expected_username, cn) != 0) {
        fprintf(stderr, "      > 失败: 证书主体不匹配！预期 '%s', 实际 '%s'。\n", expected_username, cn);
        ret_code = -3;
        goto cleanup;
    }
    printf("      > 成功: 证书主体与预期用户 '%s' 匹配。\n", expected_username);

    int ocsp_res = check_ocsp_status(user_cert, ca_cert, store);
    if (ocsp_res != 0) {
        ret_code = ocsp_res;
        goto cleanup;
    }

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
    if (user_cert_pem == NULL || public_key_out == NULL) {
        return -1;
    }

    int ret = -1;
    BIO* cert_bio = BIO_new_mem_buf(user_cert_pem, -1);
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    if (!cert_bio) goto cleanup;

    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) {
        LOG_PKI_ERROR("Failed to parse certificate PEM for public key extraction.");
        goto cleanup;
    }

    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        LOG_PKI_ERROR("Failed to get public key from certificate.");
        goto cleanup;
    }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        LOG_PKI_ERROR("Public key in certificate is not of the expected type (Ed25519).");
        goto cleanup;
    }

    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 ||
        pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
        LOG_PKI_ERROR("Failed to get raw public key bytes from certificate.");
        goto cleanup;
    }
    
    ret = 0;

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);
    return ret;
}