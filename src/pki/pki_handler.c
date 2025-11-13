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
#include "../../include/hsc_kernel.h" // 引入公共头文件以使用常量

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
    X509_NAME* subject = NULL;
    
    // 从 Ed25519 私钥中提取出 32 字节的核心种子
    unsigned char private_seed[crypto_sign_SEEDBYTES];
    crypto_sign_ed25519_sk_to_seed(private_seed, mkp->sk);

    // 使用种子创建 OpenSSL 的 EVP_PKEY 对象
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_seed, sizeof(private_seed));

    // 无论 pkey 创建是否成功，都必须立即擦除栈上的私钥种子副本，
    // 以最大限度地减少其在内存中的暴露时间。
    secure_zero_memory(private_seed, sizeof(private_seed));

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
    // [安全修复 P0] 防止整数溢出
    // 如果 nmemb > 0 且 size 大于 SIZE_MAX / nmemb,
    // 那么 size * nmemb 的结果将会溢出，导致后续 realloc 分配过小的内存，
    // 进而引发 memcpy 时的堆缓冲区溢出。
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

        // [修改] 使用定义的常量设置网络超时
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, OCSP_HTTP_CONNECT_TIMEOUT_SECONDS);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, OCSP_HTTP_TOTAL_TIMEOUT_SECONDS);

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
            fprintf(stderr, "OCSP Error: HTTP request failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
            chunk.size = 0;
            chunk.capacity = 0;
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    return chunk;
}

static int check_ocsp_status(X509* user_cert, X509* issuer_cert, X509_STORE* store) {
    int ret = -1;
    OCSP_REQUEST* ocsp_req = NULL;
    OCSP_CERTID* cid = NULL;
    OCSP_RESPONSE* ocsp_resp = NULL;
    OCSP_BASICRESP* bresp = NULL;
    BIO* req_bio = NULL;
    unsigned char* req_data = NULL;
    long req_len;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = NULL;

    printf("      iv. [Checking Revocation Status (OCSP)]:\n");

    ocsp_uris = X509_get1_ocsp(user_cert);
    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        fprintf(stderr, "         > FAILED: No OCSP URI found in certificate. Cannot verify revocation status.\n");
        // [修改] 使用公共定义的错误码
        ret = HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED;
        goto cleanup;
    }
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    printf("         > OCSP Server: %s\n", ocsp_uri);

    ocsp_req = OCSP_REQUEST_new();
    if (!ocsp_req) goto cleanup;
    
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) goto cleanup;
    if (!OCSP_request_add0_id(ocsp_req, cid)) { OCSP_CERTID_free(cid); cid = NULL; goto cleanup; }
    cid = NULL;

    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, ocsp_req)) goto cleanup;
    
    req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);
    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        fprintf(stderr, "         > FAILED: Could not retrieve a response from the OCSP server.\n");
        if(response_chunk.memory) free(response_chunk.memory);
        // [修改] 使用公共定义的错误码
        ret = HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED;
        goto cleanup;
    }
    
    const unsigned char* p = (const unsigned char*)response_chunk.memory;
    ocsp_resp = d2i_OCSP_RESPONSE(NULL, &p, response_chunk.size);
    free(response_chunk.memory);
    if (!ocsp_resp) { LOG_PKI_ERROR("Failed to parse OCSP response."); goto cleanup; }

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
    if (!cid) goto cleanup;

    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
        fprintf(stderr, "         > FAILED: Status for this certificate not found in the OCSP response.\n");
        goto cleanup;
    }

    // [修改] 使用定义的常量
    if (OCSP_check_validity(this_update, next_update, OCSP_RESPONSE_VALIDITY_SLACK_SECONDS, -1L) <= 0) {
        LOG_PKI_ERROR("OCSP response is not within its validity period (stale response).");
        goto cleanup;
    }

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            printf("         > SUCCESS: OCSP status is 'Good'. Certificate has not been revoked.\n");
            ret = 0;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            fprintf(stderr, "         > FAILED: OCSP status is 'Revoked'. Certificate has been revoked!\n");
            // [修改] 使用公共定义的错误码
            ret = HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            fprintf(stderr, "         > FAILED: OCSP status is 'Unknown'. The certificate's status is unknown.\n");
            // [修改] 使用公共定义的错误码
            ret = HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED;
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
    if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
    return ret;
}

int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username) {
    if (user_cert_pem == NULL || trusted_ca_cert_pem == NULL || expected_username == NULL) {
        return -1;
    }

    // [修改] 使用公共定义的错误码
    int ret_code = HSC_VERIFY_ERROR_GENERAL;

    BIO* user_bio = BIO_new_mem_buf(user_cert_pem, -1);
    BIO* ca_bio = BIO_new_mem_buf(trusted_ca_cert_pem, -1);
    X509* user_cert = NULL;
    X509* ca_cert = NULL;
    X509_STORE* store = NULL;
    X509_STORE_CTX* ctx = NULL;
    X509_NAME* subject_name = NULL;

    if (!user_bio || !ca_bio) { LOG_PKI_ERROR("Failed to create BIO for certificates."); goto cleanup; }
    user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    if (!user_cert || !ca_cert) { LOG_PKI_ERROR("Failed to parse PEM certificates."); goto cleanup; }

    printf("    Step i & ii (Chain & Validity Period):\n");
    store = X509_STORE_new();
    if (!store) goto cleanup;
    
    if (X509_STORE_add_cert(store, ca_cert) != 1) { LOG_PKI_ERROR("Failed to add CA cert to store."); goto cleanup; }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) goto cleanup;

    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) { LOG_PKI_ERROR("Failed to initialize verification context."); goto cleanup; }
    
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "      > FAILED: %s\n", X509_verify_cert_error_string(err));
        // [修改] 使用公共定义的错误码
        ret_code = HSC_VERIFY_ERROR_CHAIN_OR_VALIDITY;
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate is signed by a trusted CA and is within its validity period.\n");

    printf("    Step iii (Subject Verification):\n");
    subject_name = X509_get_subject_name(user_cert);
    // [修改] 使用公共定义的错误码
    if (!subject_name) { LOG_PKI_ERROR("Could not get subject name from certificate."); ret_code = HSC_VERIFY_ERROR_SUBJECT_MISMATCH; goto cleanup; }

    // [修改] 使用定义的常量
    char cn[CERT_COMMON_NAME_MAX_LEN] = {0};
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn) - 1);
    if (cn_len < 0) {
        LOG_PKI_ERROR("Could not extract Common Name from certificate.");
        // [修改] 使用公共定义的错误码
        ret_code = HSC_VERIFY_ERROR_SUBJECT_MISMATCH;
        goto cleanup;
    }

    if (strcmp(expected_username, cn) != 0) {
        fprintf(stderr, "      > FAILED: Certificate subject mismatch! Expected '%s', but got '%s'.\n", expected_username, cn);
        // [修改] 使用公共定义的错误码
        ret_code = HSC_VERIFY_ERROR_SUBJECT_MISMATCH;
        goto cleanup;
    }
    printf("      > SUCCESS: Certificate subject matches the expected user '%s'.\n", expected_username);

    int ocsp_res = check_ocsp_status(user_cert, ca_cert, store);
    if (ocsp_res != 0) {
        ret_code = ocsp_res;
        goto cleanup;
    }

    // [修改] 使用公共定义的成功码
    ret_code = HSC_VERIFY_SUCCESS;

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
    if (!cert) { LOG_PKI_ERROR("Failed to parse certificate PEM for public key extraction."); goto cleanup; }

    pkey = X509_get_pubkey(cert);
    if (!pkey) { LOG_PKI_ERROR("Failed to get public key from certificate."); goto cleanup; }
    
    if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
        LOG_PKI_ERROR("Public key in certificate is not of the expected type (Ed25519).");
        goto cleanup;
    }
    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 || pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
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