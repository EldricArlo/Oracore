// ========================= [CRITICAL FIX START] =========================
//
// 修复Windows环境下的头文件命名冲突问题。
//
// 问题根源: Windows的 <wincrypt.h> (通常被 <windows.h> 间接包含)
// 定义了与OpenSSL完全相同的宏，例如 X509_NAME, OCSP_REQUEST 等。
//
// 解决方案: 必须确保OpenSSL和cURL的头文件在任何可能引起冲突的
// Windows系统头文件之前被包含。我们将它们放在文件的最顶部。
//
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h> 
#include <curl/curl.h>
// ========================== [CRITICAL FIX END] ==========================

#include "pki_handler.h" // 项目内头文件紧随其后

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// --- 初始化函数 ---
int pki_init() {
    // 为多线程安全初始化 libcurl。此函数是全局的，可以安全地多次调用。
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "PKI Error: Failed to initialize libcurl.\n");
        return -1;
    }

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_LOAD_CONFIG, NULL) == 0) {
        fprintf(stderr, "PKI Error: Failed to initialize OpenSSL crypto library.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    OSSL_PROVIDER* provider = OSSL_PROVIDER_load(NULL, "default");
    if (provider == NULL) {
        fprintf(stderr, "PKI Error: Failed to load OpenSSL default provider.\n");
        ERR_print_errors_fp(stderr);
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
    
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, mkp->sk, crypto_sign_SEEDBYTES);
    if (!pkey) {
        fprintf(stderr, "PKI Error: EVP_PKEY_new_raw_private_key failed.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    
    req = X509_REQ_new();
    if (!req) {
        fprintf(stderr, "PKI Error: X509_REQ_new failed.\n");
        goto cleanup;
    }
    
    X509_REQ_set_version(req, 0);

    X509_NAME* subject = X509_REQ_get_subject_name(req);
    if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (const unsigned char*)username, -1, -1, 0)) {
        fprintf(stderr, "PKI Error: X509_NAME_add_entry_by_txt failed.\n");
        goto cleanup;
    }

    if (X509_REQ_set_pubkey(req, pkey) <= 0) {
        fprintf(stderr, "PKI Error: X509_REQ_set_pubkey failed.\n");
        goto cleanup;
    }

    if (X509_REQ_sign(req, pkey, NULL) <= 0) {
        fprintf(stderr, "PKI Error: X509_REQ_sign failed.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        fprintf(stderr, "PKI Error: BIO_new failed.\n");
        goto cleanup;
    }
    
    if (!PEM_write_bio_X509_REQ(bio, req)) {
        fprintf(stderr, "PKI Error: PEM_write_bio_X509_REQ failed.\n");
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
             fprintf(stderr, "PKI Error: malloc failed for CSR PEM string.\n");
        }
    }
    
cleanup:
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    return ret;
}


// ======================= [NEW OCSP IMPLEMENTATION START] =======================

// 用于 libcurl 接收数据的内存块结构体
struct memory_chunk {
    char* memory;
    size_t size;
};

// libcurl 写入回调函数
static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*)userp;

    char* ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "OCSP Error: not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

// 使用 libcurl 执行 HTTP POST 请求的辅助函数
static struct memory_chunk perform_http_post(const char* url, const unsigned char* data, size_t data_len) {
    CURL* curl;
    CURLcode res;
    struct memory_chunk chunk = { .memory = NULL, .size = 0 };

    chunk.memory = malloc(1);
    if (chunk.memory == NULL) {
        return chunk;
    }
    chunk.memory[0] = '\0';

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
        
        // 在生产环境中，应配置CURLOPT_CAINFO来验证OCSP服务器的TLS证书
        // curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "OCSP Error: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
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
    int ret = -1; // Default to general error
    OCSP_REQUEST* req = NULL;
    OCSP_CERTID* cid = NULL;
    OCSP_RESPONSE* resp = NULL;
    OCSP_BASICRESP* bresp = NULL;
    BIO* req_bio = NULL;
    unsigned char* req_data = NULL;
    long req_len;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = NULL;

    printf("      iv. [检查吊销状态 (OCSP)]:\n");

    // 步骤 1: 从证书的 Authority Information Access (AIA) 扩展中获取 OCSP URL
    ocsp_uris = X509_get1_ocsp(user_cert);
    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        fprintf(stderr, "         > 警告: 证书中未找到 OCSP URI。跳过吊销检查。\n");
        ret = 0; // 如果没有提供URI，我们无法检查，只能假设其有效
        goto cleanup;
    }
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    printf("         > OCSP 服务器: %s\n", ocsp_uri);

    // 步骤 2: 创建 OCSP 请求
    req = OCSP_REQUEST_new();
    if (!req) goto cleanup;
    
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) goto cleanup;
    if (!OCSP_request_add0_id(req, cid)) {
        OCSP_CERTID_free(cid); // If add fails, we must free it
        goto cleanup;
    }
    cid = NULL; // ownership transferred to req

    // 步骤 3: 发送 HTTP 请求
    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, req)) goto cleanup;
    
    req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);
    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        fprintf(stderr, "         > 失败: 未能从 OCSP 服务器获取响应。\n");
        if(response_chunk.memory) free(response_chunk.memory);
        goto cleanup;
    }
    
    // 步骤 4: 解析并验证 OCSP 响应
    const unsigned char* p = (const unsigned char*)response_chunk.memory;
    resp = d2i_OCSP_RESPONSE(NULL, &p, response_chunk.size);
    free(response_chunk.memory);
    if (!resp) {
        fprintf(stderr, "         > 失败: 解析 OCSP 响应失败。\n");
        goto cleanup;
    }

    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        fprintf(stderr, "         > 失败: OCSP 响应状态不成功 (%s)。\n", OCSP_response_status_str(OCSP_response_status(resp)));
        goto cleanup;
    }

    bresp = OCSP_response_get1_basic(resp);
    if (!bresp) {
        fprintf(stderr, "         > 失败: 无法从响应中获取 Basic OCSP Response。\n");
        goto cleanup;
    }

    if (OCSP_basic_verify(bresp, NULL, store, 0) <= 0) {
        fprintf(stderr, "         > 失败: OCSP 响应签名验证失败！\n");
        goto cleanup;
    }

    // 步骤 5: 检查特定证书的状态
    int status, reason;
    ASN1_GENERALIZEDTIME* rev_time = NULL, *this_update = NULL, *next_update = NULL;
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert); // Re-create for lookup
    if (!cid) goto cleanup;

    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
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
             fprintf(stderr, "         > 失败: 未知的证书状态代码。\n");
             ret = -1;
             break;
    }

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bresp);
    BIO_free(req_bio);
    // ======================= [FINAL FIX] =========================
    if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris); // The one and only correct free function.
    // =============================================================
    return ret;
}

// ======================= [NEW OCSP IMPLEMENTATION END] =========================


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
        fprintf(stderr, "Verify Error: Failed to create BIO for certificates.\n");
        goto cleanup;
    }
    user_cert = PEM_read_bio_X509(user_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_bio, NULL, NULL, NULL);
    if (!user_cert || !ca_cert) {
        fprintf(stderr, "Verify Error: Failed to parse PEM certificates.\n");
        goto cleanup;
    }

    printf("    验证步骤 i & ii (签名链 和 有效期):\n");
    store = X509_STORE_new();
    if (!store) goto cleanup;
    
    if (X509_STORE_add_cert(store, ca_cert) != 1) {
        fprintf(stderr, "Verify Error: Failed to add CA cert to store.\n");
        goto cleanup;
    }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) goto cleanup;

    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) {
        fprintf(stderr, "Verify Error: Failed to initialize verification context.\n");
        goto cleanup;
    }
    
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
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
        fprintf(stderr, "      > 失败: 无法从证书中提取 Common Name。\n");
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
        ret_code = ocsp_res; // Propagate specific OCSP error code (-4)
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
        fprintf(stderr, "Extract PK Error: Failed to parse certificate PEM.\n");
        goto cleanup;
    }

    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Extract PK Error: Failed to get public key from certificate.\n");
        goto cleanup;
    }
    
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
    
    ret = 0;

cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);
    return ret;
}