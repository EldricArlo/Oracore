// --- pki_handler.c (REVISED BY COMMITTEE) ---
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
#include "../../include/hsc_kernel.h" // 引入公共头文件以使用常量和错误码

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h> // For SIZE_MAX

// [新增] 内部使用的常量
#define OCSP_HTTP_CONNECT_TIMEOUT_SECONDS 5L
#define OCSP_HTTP_TOTAL_TIMEOUT_SECONDS 10L
#define OCSP_RESPONSE_VALIDITY_SLACK_SECONDS 300L // 5分钟的宽限期
#define INITIAL_HTTP_CHUNK_CAPACITY 1024


// ======================= 错误报告宏 =======================
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
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        LOG_PKI_ERROR("Failed to initialize libcurl.");
        return HSC_ERROR_PKI_OPERATION;
    }
    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        LOG_PKI_ERROR("Failed to initialize OpenSSL crypto library.");
        return HSC_ERROR_PKI_OPERATION;
    }
    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        LOG_PKI_ERROR("Failed to load OpenSSL default provider.");
        return HSC_ERROR_PKI_OPERATION;
    }
    return HSC_OK;
}


void free_csr_pem(char* csr_pem) {
    if (csr_pem != NULL) {
        free(csr_pem);
    }
}

int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem) {
    if (mkp == NULL || mkp->sk == NULL || username == NULL || out_csr_pem == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    *out_csr_pem = NULL;

    int ret = HSC_ERROR_PKI_OPERATION; // [修改] 默认返回 PKI 操作失败
    EVP_PKEY* pkey = NULL;
    X509_REQ* req = NULL;
    BIO* bio = NULL;
    X509_NAME* subject = NULL;
    unsigned char* private_seed = NULL;
    
    // 使用安全内存分配私钥种子，防止其被交换到磁盘或在内存中残留
    private_seed = secure_alloc(crypto_sign_SEEDBYTES);
    if (!private_seed) { 
        LOG_PKI_ERROR("secure_alloc failed for private seed."); 
        ret = HSC_ERROR_ALLOCATION_FAILED;
        goto cleanup; 
    }
    
    crypto_sign_ed25519_sk_to_seed(private_seed, mkp->sk);

    // --- [委员会修复开始] ---
    //
    // **风险通告与缓解措施:**
    // 下方的 `EVP_PKEY_new_raw_private_key` 函数会接收 `private_seed` 指针，
    // 并在其内部（由OpenSSL管理，位于标准堆）创建一份该种子的副本以构造 EVP_PKEY 对象。
    // 这意味着私钥材料的副本会短暂地存在于非安全内存中。这是一个与不感知安全内存的
    // 第三方库（如OpenSSL）交互时固有的、必须接受的风险。
    //
    // 我们的缓解策略是：
    // 1. 将原始种子存放在安全内存中 (`secure_alloc`)。
    // 2. 将此风险窗口限制在当前函数的生命周期内。
    // 3. 在调用OpenSSL函数后，立即使用 `OPENSSL_cleanse` 擦除我们栈上的种子副本，
    //    作为 `secure_free` (其内部使用 sodium_memzero) 之外的额外深度防御层。
    // 4. 立即调用 `secure_free` 销毁原始的安全内存缓冲区。
    //
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_seed, crypto_sign_SEEDBYTES);
    
    // 无论 `pkey` 创建是否成功，都必须立即、安全地销毁我们本地的种子副本。
    OPENSSL_cleanse(private_seed, crypto_sign_SEEDBYTES);
    secure_free(private_seed);
    private_seed = NULL; // 避免悬垂指针 (dangling pointer)

    // --- [委员会修复结束] ---

    if (!pkey) { LOG_PKI_ERROR("EVP_PKEY_new_raw_private_key failed."); goto cleanup; }
    
    req = X509_REQ_new();
    if (!req) { LOG_PKI_ERROR("X509_REQ_new failed."); goto cleanup; }
    
    if (X509_REQ_set_version(req, 0L) <= 0) { LOG_PKI_ERROR("X509_REQ_set_version failed."); goto cleanup; }

    subject = X509_REQ_get_subject_name(req);
    if (!subject) { LOG_PKI_ERROR("X509_REQ_get_subject_name failed."); goto cleanup; }

    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)username, -1, -1, 0)) {
        LOG_PKI_ERROR("X509_NAME_add_entry_by_txt failed."); goto cleanup;
    }

    if (X509_REQ_set_pubkey(req, pkey) <= 0) { LOG_PKI_ERROR("X509_REQ_set_pubkey failed."); goto cleanup; }
    if (X509_REQ_sign(req, pkey, NULL) <= 0) { LOG_PKI_ERROR("X509_REQ_sign failed."); goto cleanup; }

    bio = BIO_new(BIO_s_mem());
    if (!bio) { LOG_PKI_ERROR("BIO_new failed."); goto cleanup; }
    
    if (!PEM_write_bio_X509_REQ(bio, req)) { LOG_PKI_ERROR("PEM_write_bio_X509_REQ failed."); goto cleanup; }

    BUF_MEM* mem = NULL;
    BIO_get_mem_ptr(bio, &mem);
    if (mem && mem->data && mem->length > 0) {
        *out_csr_pem = (char*)malloc(mem->length + 1);
        if (*out_csr_pem) {
            memcpy(*out_csr_pem, mem->data, mem->length);
            (*out_csr_pem)[mem->length] = '\0';
            ret = HSC_OK; // [修改] 成功
        } else {
             LOG_PKI_ERROR("malloc failed for CSR PEM string.");
             ret = HSC_ERROR_ALLOCATION_FAILED;
        }
    }
    
cleanup:
    // 确保即使在早期的错误路径中，private_seed 也已被设为 NULL 且不会被二次释放
    if (private_seed) {
        // 此处的调用仅作为额外的安全措施，正常流程中它应为 NULL
        secure_free(private_seed);
    }
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return ret;
}


// ======================= OCSP 检查的静态辅助函数 (REFACTORED) =======================

struct memory_chunk {
    char* memory;
    size_t size;
    size_t capacity;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    // [安全修复 P0] 防止整数溢出
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        fprintf(stderr, "OCSP Error: Potential integer overflow detected in HTTP callback. Aborting.\n");
        return 0; // 返回 0 会使 libcurl 中止传输，这是一个安全的失败模式。
    }
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*)userp;

    if (mem->size + realsize + 1 > mem->capacity) {
        size_t new_capacity = (mem->capacity > 0) ? mem->capacity * 2 : INITIAL_HTTP_CHUNK_CAPACITY;
        if (new_capacity < mem->size + realsize + 1) new_capacity = mem->size + realsize + 1;

        char* ptr = realloc(mem->memory, new_capacity);
        if (ptr == NULL) {
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

static struct memory_chunk perform_http_post(const char* url, const unsigned char* data, size_t data_len) {
    CURL* curl;
    CURLcode res;
    struct memory_chunk chunk = { .memory = NULL, .size = 0, .capacity = 0 };

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");

        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, OCSP_HTTP_CONNECT_TIMEOUT_SECONDS);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, OCSP_HTTP_TOTAL_TIMEOUT_SECONDS);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

        // --- [安全修复 HIGH] ---
        // 强制验证对端服务器证书的有效性
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        // 强制验证证书中的主机名是否与我们连接的主机名匹配
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        // [安全修复 HIGH] 移除了硬编码的 CA 路径。
        // 现在 libcurl 将使用其内置的、平台感知的默认 CA 证书搜索路径，
        // 极大地提高了跨平台兼容性。
        // curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
        // --- [修复结束] ---

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
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

/**
 * @brief [重构] 辅助函数1: 创建 OCSP 请求对象
 */
static OCSP_REQUEST* _create_ocsp_request(X509* user_cert, X509* issuer_cert) {
    OCSP_REQUEST* ocsp_req = OCSP_REQUEST_new();
    if (!ocsp_req) {
        LOG_PKI_ERROR("Failed to create OCSP_REQUEST object.");
        return NULL;
    }

    OCSP_CERTID* cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) {
        LOG_PKI_ERROR("Failed to create OCSP_CERTID.");
        OCSP_REQUEST_free(ocsp_req);
        return NULL;
    }

    // OCSP_request_add0_id 会取得 cid 的所有权，所以我们不需要再手动释放它
    if (!OCSP_request_add0_id(ocsp_req, cid)) {
        LOG_PKI_ERROR("Failed to add certificate ID to OCSP request.");
        OCSP_CERTID_free(cid); // 在失败的情况下，需要我们自己释放
        OCSP_REQUEST_free(ocsp_req);
        return NULL;
    }

    return ocsp_req;
}

/**
 * @brief [重构] 辅助函数2: 发送 OCSP 请求并解析响应
 */
static OCSP_RESPONSE* _send_and_parse_ocsp_request(X509* user_cert, OCSP_REQUEST* ocsp_req) {
    OCSP_RESPONSE* ocsp_resp = NULL;
    BIO* req_bio = NULL;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = X509_get1_ocsp(user_cert);

    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        fprintf(stderr, "         > FAILED: No OCSP URI found in certificate. Cannot verify revocation status.\n");
        goto cleanup;
    }
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    printf("         > OCSP Server: %s\n", ocsp_uri);

    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, ocsp_req)) {
        LOG_PKI_ERROR("Failed to serialize OCSP request.");
        goto cleanup;
    }

    unsigned char* req_data = NULL;
    long req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);

    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        fprintf(stderr, "         > FAILED: Could not retrieve a response from the OCSP server.\n");
        if(response_chunk.memory) free(response_chunk.memory);
        goto cleanup;
    }

    const unsigned char* p = (const unsigned char*)response_chunk.memory;
    ocsp_resp = d2i_OCSP_RESPONSE(NULL, &p, response_chunk.size);
    free(response_chunk.memory);
    if (!ocsp_resp) {
        LOG_PKI_ERROR("Failed to parse OCSP response.");
    }
    
cleanup:
    BIO_free(req_bio);
    if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
    return ocsp_resp;
}

/**
 * @brief [重构] 辅助函数3: 验证响应签名并检查证书状态
 */
static int _verify_and_check_status(OCSP_RESPONSE* ocsp_resp, X509_STORE* store, X509* user_cert, X509* issuer_cert) {
    int final_status = -1; // Default to a generic error
    OCSP_BASICRESP* bresp = NULL;
    OCSP_CERTID* cid = NULL;
    
    if (OCSP_response_status(ocsp_resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        LOG_PKI_ERROR_FMT("OCSP response status was not successful: %s", OCSP_response_status_str(OCSP_response_status(ocsp_resp)));
        goto cleanup;
    }

    bresp = OCSP_response_get1_basic(ocsp_resp);
    if (!bresp) { LOG_PKI_ERROR("Could not get Basic OCSP Response from response."); goto cleanup; }

    if (OCSP_basic_verify(bresp, NULL, store, 0) <= 0) {
        LOG_PKI_ERROR("OCSP response signature verification failed.");
        goto cleanup;
    }
    
    int status, reason;
    ASN1_GENERALIZEDTIME* rev_time = NULL, *this_update = NULL, *next_update = NULL;
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) { LOG_PKI_ERROR("Failed to create OCSP_CERTID for status check."); goto cleanup; }

    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
        fprintf(stderr, "         > FAILED: Status for this certificate not found in the OCSP response.\n");
        goto cleanup;
    }

    if (OCSP_check_validity(this_update, next_update, OCSP_RESPONSE_VALIDITY_SLACK_SECONDS, -1L) <= 0) {
        LOG_PKI_ERROR("OCSP response is not within its validity period (stale response).");
        goto cleanup;
    }

    final_status = status; // V_OCSP_CERTSTATUS_GOOD, V_OCSP_CERTSTATUS_REVOKED, etc.

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_BASICRESP_free(bresp);
    return final_status;
}


static int check_ocsp_status(X509* user_cert, X509* issuer_cert, X509_STORE* store) {
    printf("      iv. [Checking Revocation Status (OCSP)]:\n");
    int ret = HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED; // [修改] Default to failure, per "Fail-Closed"

    OCSP_REQUEST* ocsp_req = _create_ocsp_request(user_cert, issuer_cert);
    if (!ocsp_req) {
        return ret;
    }

    OCSP_RESPONSE* ocsp_resp = _send_and_parse_ocsp_request(user_cert, ocsp_req);
    OCSP_REQUEST_free(ocsp_req); // Request is no longer needed
    if (!ocsp_resp) {
        return ret;
    }

    int status = _verify_and_check_status(ocsp_resp, store, user_cert, issuer_cert);
    OCSP_RESPONSE_free(ocsp_resp); // Response is no longer needed

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            printf("         > SUCCESS: OCSP status is 'Good'. Certificate has not been revoked.\n");
            ret = HSC_OK; // [修改] 成功
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            fprintf(stderr, "         > FAILED: OCSP status is 'Revoked'. Certificate has been revoked!\n");
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            fprintf(stderr, "         > FAILED: OCSP status is 'Unknown'. The certificate's status is unknown.\n");
            break;
        default:
             LOG_PKI_ERROR("Unknown or failed OCSP certificate status check.");
             break;
    }

    return ret;
}

// ======================= 主验证函数 =======================

int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username) {
    if (user_cert_pem == NULL || trusted_ca_cert_pem == NULL || expected_username == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }

    int ret_code = HSC_ERROR_GENERAL;
    BIO* user_bio = NULL;
    BIO* ca_bio = NULL;
    X509* user_cert = NULL;
    X509* ca_cert = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;

    user_bio = BIO_new_mem_buf(user_cert_pem, -1);
    ca_bio = BIO_new_mem_buf(trusted_ca_cert_pem, -1);
    if (!user_bio || !ca_bio) { 
        LOG_PKI_ERROR("Failed to create BIO for certificates."); 
        ret_code = HSC_ERROR_PKI_OPERATION;
        goto cleanup; 
    }
    
    user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    if (!user_cert || !ca_cert) { 
        LOG_PKI_ERROR("Failed to parse PEM certificates."); 
        ret_code = HSC_ERROR_INVALID_FORMAT;
        goto cleanup; 
    }

    // 步骤 i & ii: 信任链与有效期
    printf("    Step i & ii (Chain & Validity Period):\n");
    store = X509_STORE_new();
    if (!store) { LOG_PKI_ERROR("Failed to create X509_STORE."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    if (X509_STORE_add_cert(store, ca_cert) != 1) { LOG_PKI_ERROR("Failed to add CA cert to store."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) { LOG_PKI_ERROR("Failed to create X509_STORE_CTX."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) { LOG_PKI_ERROR("Failed to initialize verification context."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "      > FAILED: %s\n", X509_verify_cert_error_string(err));
        ret_code = HSC_ERROR_CERT_CHAIN_OR_VALIDITY;
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate is signed by a trusted CA and is within its validity period.\n");

    // 步骤 iii: 主体匹配
    printf("    Step iii (Subject Verification):\n");
    X509_NAME* subject_name = X509_get_subject_name(user_cert);
    if (!subject_name) { LOG_PKI_ERROR("Could not get subject name from certificate."); ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH; goto cleanup; }
    char cn[CERT_COMMON_NAME_MAX_LEN] = {0};
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn) - 1);
    if (cn_len < 0) {
        LOG_PKI_ERROR("Could not extract Common Name from certificate.");
        ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH;
        goto cleanup;
    }
    if (strcmp(expected_username, cn) != 0) {
        fprintf(stderr, "      > FAILED: Certificate subject mismatch! Expected '%s', but got '%s'.\n", expected_username, cn);
        ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH;
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate subject matches the expected user '%s'.\n", expected_username);

    // 步骤 iv: 强制OCSP吊销检查
    int ocsp_res = check_ocsp_status(user_cert, ca_cert, store);
    if (ocsp_res != HSC_OK) { // [修改] 检查是否成功
        ret_code = ocsp_res; // ocsp_res already holds the correct error code
        goto cleanup;
    }

    ret_code = HSC_OK; // [修改] 所有检查通过

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
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    int ret = HSC_ERROR_PKI_OPERATION; // [修改] 默认返回 PKI 操作失败
    BIO* cert_bio = BIO_new_mem_buf(user_cert_pem, -1);
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    if (!cert_bio) { goto cleanup; }
    cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
    if (!cert) { 
        LOG_PKI_ERROR("Failed to parse certificate PEM for public key extraction."); 
        ret = HSC_ERROR_INVALID_FORMAT;
        goto cleanup; 
    }

    pkey = X509_get_pubkey(cert);
    if (!pkey) { LOG_PKI_ERROR("Failed to get public key from certificate."); goto cleanup; }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        LOG_PKI_ERROR("Public key in certificate is not of the expected type (Ed25519).");
        ret = HSC_ERROR_INVALID_FORMAT;
        goto cleanup;
    }
    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 || pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
        LOG_PKI_ERROR("Failed to get raw public key bytes from certificate.");
        goto cleanup;
    }
    ret = HSC_OK; // [修改] 成功
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);
    return ret;
}