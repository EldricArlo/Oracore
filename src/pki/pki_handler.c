#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <curl/curl.h>

// Finding #3 - 引入网络头文件以解析 IP 地址进行 SSRF 防御
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
#endif

#include "pki_handler.h"

// 编译错误修复
// 必须包含 crypto_client.h 才能访问 master_key_pair 结构体的内部成员 (identity_sk)
// 以及获取 MASTER_PUBLIC_KEY_BYTES 常量定义。
#include "../core_crypto/crypto_client.h" 

#include "../common/secure_memory.h"
#include "../../include/hsc_kernel.h"
#include "../common/internal_logger.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

// 内部使用的常量
#define OCSP_HTTP_CONNECT_TIMEOUT_SECONDS 5L
#define OCSP_HTTP_TOTAL_TIMEOUT_SECONDS 10L
#define OCSP_RESPONSE_VALIDITY_SLACK_SECONDS 300L // 5分钟的宽限期
#define INITIAL_HTTP_CHUNK_CAPACITY 1024
#define MAX_OCSP_RESPONSE_SIZE (1 * 1024 * 1024) // 1 MB
#define MAX_CERT_PEM_SIZE (100 * 1024)           // 100 KB limit for a single certificate PEM

// 内部全局配置状态，默认为严格安全模式
static hsc_pki_config g_pki_config = {
    .allow_no_ocsp_uri = false
};

// ======================= 错误报告宏 =======================

static void _hsc_log_openssl_error_queue() {
    unsigned long err_code;
    char err_buf[256];
    while ((err_code = ERR_get_error()) != 0) {
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        _hsc_log(HSC_LOG_LEVEL_ERROR, "    OpenSSL Internal Error: %s", err_buf);
    }
}

#define LOG_PKI_ERROR(msg) do { \
    _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: %s", msg); \
    _hsc_log_openssl_error_queue(); \
} while(0)

#define LOG_PKI_ERROR_FMT(fmt, ...) do { \
    _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: " fmt, __VA_ARGS__); \
    _hsc_log_openssl_error_queue(); \
} while(0)


// --- 初始化函数 ---
int pki_init(const hsc_pki_config* config) {
    // 更新配置状态
    if (config != NULL) {
        g_pki_config = *config;
    } else {
        // 默认严格模式
        g_pki_config.allow_no_ocsp_uri = false;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to initialize libcurl.");
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
    // 现在包含了 crypto_client.h，编译器可以看到 mkp->identity_sk 的定义
    if (mkp == NULL || mkp->identity_sk == NULL || username == NULL || out_csr_pem == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }

    // [FIX] Input Validation: Username length check
    // Prevent buffer overflows or massive ASN.1 structures
    if (strlen(username) > CERT_COMMON_NAME_MAX_LEN) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: Username exceeds maximum allowed length (%d).", CERT_COMMON_NAME_MAX_LEN);
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    // Basic sanity check for empty strings
    if (strlen(username) == 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: Username cannot be empty.");
        return HSC_ERROR_INVALID_ARGUMENT;
    }

    *out_csr_pem = NULL;

    int ret = HSC_ERROR_PKI_OPERATION;
    EVP_PKEY* pkey = NULL;
    X509_REQ* req = NULL;
    BIO* bio = NULL;
    X509_NAME* subject = NULL;
    unsigned char* private_seed = NULL;
    
    private_seed = secure_alloc(crypto_sign_SEEDBYTES);
    if (!private_seed) { 
        _hsc_log(HSC_LOG_LEVEL_ERROR, "secure_alloc failed for private seed."); 
        ret = HSC_ERROR_ALLOCATION_FAILED;
        goto cleanup; 
    }
    
    crypto_sign_ed25519_sk_to_seed(private_seed, mkp->identity_sk);
    
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, private_seed, crypto_sign_SEEDBYTES);
    
    OPENSSL_cleanse(private_seed, crypto_sign_SEEDBYTES);
    secure_free(private_seed);
    private_seed = NULL;

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
            ret = HSC_OK;
        } else {
             _hsc_log(HSC_LOG_LEVEL_ERROR, "malloc failed for CSR PEM string.");
             ret = HSC_ERROR_ALLOCATION_FAILED;
        }
    }
    
cleanup:
    BIO_free(bio);
    X509_REQ_free(req);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    return ret;
}


// ======================= OCSP 检查的静态辅助函数 =======================

// Finding #3 - SSRF 防御回调函数实现
static curl_socket_t opensocket_callback(void *clientp, curlsocktype purpose, struct curl_sockaddr *addr) {
    (void)clientp; // 未使用

    // 我们只拦截 IP 连接请求
    if (purpose != CURLSOCKTYPE_IPCXN) {
        return socket(addr->family, addr->socktype, addr->protocol);
    }

    bool block_connection = false;
    char ip_str[INET6_ADDRSTRLEN];
    ip_str[0] = '\0';

    // 检查环境变量配置，看是否允许连接私有网络
    bool allow_private = (getenv("HSC_PKI_ALLOW_PRIVATE_IP") != NULL);

    if (addr->family == AF_INET) {
        // --- IPv4 Checks ---
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr->addr;
        unsigned char *ip = (unsigned char *)&addr4->sin_addr;
        
        // 用于日志
        inet_ntop(AF_INET, &addr4->sin_addr, ip_str, sizeof(ip_str));

        // 1. Block Loopback (127.0.0.0/8) - ALWAYS BLOCKED
        if (ip[0] == 127) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Loopback IP: %s", ip_str);
        }
        // Audit Finding #1 - 显式拦截 0.0.0.0 (INADDR_ANY)。
        // 在某些系统上，0.0.0.0 意味着本机，可绕过 127.0.0.0/8 的检查。
        else if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to 0.0.0.0 (Localhost alias)");
        }
        // 2. Block Link-Local (169.254.0.0/16) - ALWAYS BLOCKED (AWS/Cloud Metadata)
        else if (ip[0] == 169 && ip[1] == 254) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Link-Local IP: %s", ip_str);
        }
        // 3. Block Private LANs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) - CONDITIONALLY BLOCKED
        else if (!allow_private) {
            if (ip[0] == 10 ||
                (ip[0] == 172 && (ip[1] >= 16 && ip[1] <= 31)) ||
                (ip[0] == 192 && ip[1] == 168)) {
                block_connection = true;
                _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Private LAN IP: %s (Set HSC_PKI_ALLOW_PRIVATE_IP=1 to allow)", ip_str);
            }
        }

    } else if (addr->family == AF_INET6) {
        // --- IPv6 Checks ---
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr->addr;
        unsigned char *ip = (unsigned char *)&addr6->sin6_addr;
        
        // 用于日志
        inet_ntop(AF_INET6, &addr6->sin6_addr, ip_str, sizeof(ip_str));

        // 1. Block Loopback (::1) - ALWAYS BLOCKED
        static const unsigned char loopback_v6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (memcmp(ip, loopback_v6, 16) == 0) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Loopback IPv6: %s", ip_str);
        }
        // Audit Finding #1 - 显式拦截 :: (Unspecified Address)
        // 同样防止作为本地别名绕过。
        else if (memcmp(ip, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Unspecified IPv6 (::)");
        }
        // 2. Block Unique Local (fc00::/7) - CONDITIONALLY BLOCKED
        // fc00:: to fdff:: -> First byte & 0xFE == 0xFC
        else if (!allow_private && (ip[0] & 0xFE) == 0xFC) {
            block_connection = true;
             _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Unique Local IPv6: %s", ip_str);
        }
        // 3. Block Link-Local (fe80::/10) - ALWAYS BLOCKED
        // First byte 0xFE, second byte & 0xC0 == 0x80
        else if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) {
            block_connection = true;
            _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked connection to Link-Local IPv6: %s", ip_str);
        }
        // Finding #1 - Explicitly Block IPv4-mapped IPv6 addresses (::ffff:0:0/96)
        // Format: 80 bits of zeros + 16 bits of ones (0xFFFF) + 32 bits IPv4
        // Attack vector: Attacker uses ::ffff:127.0.0.1 to bypass IPv4 whitelist checks.
        else {
            static const unsigned char ipv4_mapped_prefix[12] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF
            };
            if (memcmp(ip, ipv4_mapped_prefix, 12) == 0) {
                block_connection = true;
                _hsc_log(HSC_LOG_LEVEL_ERROR, "SSRF Security: Blocked IPv4-mapped IPv6 address: %s (Bypassing strictly prohibited)", ip_str);
            }
        }
    }

    if (block_connection) {
        return CURL_SOCKET_BAD;
    }

    // 安全检查通过，手动创建 socket 并返回给 libcurl
    return socket(addr->family, addr->socktype, addr->protocol);
}


struct memory_chunk {
    char* memory;
    size_t size;
    size_t capacity;
};

static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: Potential integer overflow detected in HTTP callback. Aborting.");
        return 0; 
    }
    size_t realsize = size * nmemb;
    struct memory_chunk* mem = (struct memory_chunk*)userp;

    if (mem->size + realsize > MAX_OCSP_RESPONSE_SIZE) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: Response exceeds the maximum allowed size of %d MB. Aborting.", MAX_OCSP_RESPONSE_SIZE / (1024*1024));
        return 0; 
    }

    if (mem->size + realsize + 1 > mem->capacity) {
        size_t new_capacity = (mem->capacity > 0) ? mem->capacity * 2 : INITIAL_HTTP_CHUNK_CAPACITY;
        if (new_capacity < mem->size + realsize + 1) new_capacity = mem->size + realsize + 1;
        
        if (new_capacity > MAX_OCSP_RESPONSE_SIZE) {
            new_capacity = MAX_OCSP_RESPONSE_SIZE;
        }

        char* new_ptr = realloc(mem->memory, new_capacity);
        if (new_ptr == NULL) {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: not enough memory (realloc returned NULL)");
            return 0;
        }
        mem->memory = new_ptr;
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
        
        #if LIBCURL_VERSION_NUM >= 0x075500 // 7.85.0
            curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
            curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
        #else
            curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
            curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        #endif
        
        // Finding #3 - 启用 SSRF 防御回调
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, NULL);

        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)MAX_OCSP_RESPONSE_SIZE);
        
        res = curl_easy_perform(curl);

        if (res == CURLE_FILESIZE_EXCEEDED) {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: Response from server exceeded the maximum allowed size of %d MB.", MAX_OCSP_RESPONSE_SIZE / (1024*1024));
            free(chunk.memory);
            chunk.memory = NULL;
            chunk.size = 0;
        } else if (res == CURLE_COULDNT_CONNECT && chunk.memory == NULL) {
            // 如果是因为 socket 回调拒绝而连接失败
             _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: Connection blocked (SSRF Protection) or failed to connect.");
        } else if (res != CURLE_OK) {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "OCSP Error: HTTP request failed: %s", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
            chunk.size = 0;
        }
        
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }
    return chunk;
}

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

    if (!OCSP_request_add0_id(ocsp_req, cid)) {
        LOG_PKI_ERROR("Failed to add certificate ID to OCSP request.");
        OCSP_CERTID_free(cid);
        OCSP_REQUEST_free(ocsp_req);
        return NULL;
    }

    // [FIX]: High Risk #1 (Replay Attack)
    // 强制向 OCSP 请求添加 Nonce 扩展。
    // 这要求 OCSP Responder 必须支持 Nonce，否则后续验证将失败。
    // 这是防止攻击者重放旧的 "Good" 响应的关键缓解措施。
    if (!OCSP_request_add1_nonce(ocsp_req, NULL, -1)) {
        LOG_PKI_ERROR("Failed to add Nonce to OCSP request.");
        OCSP_REQUEST_free(ocsp_req);
        return NULL;
    }

    return ocsp_req;
}

static OCSP_RESPONSE* _send_and_parse_ocsp_request(X509* user_cert, OCSP_REQUEST* ocsp_req) {
    OCSP_RESPONSE* ocsp_resp = NULL;
    BIO* req_bio = NULL;
    STACK_OF(OPENSSL_STRING)* ocsp_uris = X509_get1_ocsp(user_cert);

    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        if(ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
        return NULL;
    }
    const char* ocsp_uri = sk_OPENSSL_STRING_value(ocsp_uris, 0);
    _hsc_log(HSC_LOG_LEVEL_INFO, "         > OCSP Server: %s", ocsp_uri);

    req_bio = BIO_new(BIO_s_mem());
    if (!req_bio || !i2d_OCSP_REQUEST_bio(req_bio, ocsp_req)) {
        LOG_PKI_ERROR("Failed to serialize OCSP request.");
        goto cleanup;
    }

    unsigned char* req_data = NULL;
    long req_len = BIO_get_mem_data(req_bio, &req_data);
    struct memory_chunk response_chunk = perform_http_post(ocsp_uri, req_data, req_len);

    if (response_chunk.memory == NULL || response_chunk.size == 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "         > FAILED: Could not retrieve a response from the OCSP server.");
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

// [FIX]: Updated signature to accept OCSP_REQUEST* for nonce verification
static int _verify_and_check_status(OCSP_RESPONSE* ocsp_resp, OCSP_REQUEST* ocsp_req, X509_STORE* store, X509* user_cert, X509* issuer_cert) {
    int final_status = -1;
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

    // [FIX]: High Risk #1 (Replay Attack) - Verify Nonce
    // 检查响应中的 Nonce 是否存在且与请求中的一致。
    // 返回值: 1=匹配, 0=响应中缺失, -1=不匹配
    int nonce_check = OCSP_check_nonce(ocsp_req, bresp);
    if (nonce_check <= 0) {
        if (nonce_check == 0) {
            // Nonce 缺失。根据 Fail-Closed 高安全策略，要求服务器必须支持 Nonce。
            // 攻击者可能会剥离 Nonce 并重放不带 Nonce 的旧响应。
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > SECURITY FAILURE: OCSP Response is missing the Nonce extension.");
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > This suggests the server does not support Nonce, or an attacker has stripped it to replay an old response.");
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > Policy: Fail-Closed.");
        } else {
            // Nonce 存在但不匹配
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > SECURITY CRITICAL: OCSP Nonce mismatch! Potential Replay Attack detected.");
        }
        goto cleanup;
    }
    _hsc_log(HSC_LOG_LEVEL_INFO, "         > SUCCESS: OCSP Nonce verified. Response is fresh.");
    
    int status, reason;
    ASN1_GENERALIZEDTIME* rev_time = NULL, *this_update = NULL, *next_update = NULL;
    cid = OCSP_cert_to_id(NULL, user_cert, issuer_cert);
    if (!cid) { LOG_PKI_ERROR("Failed to create OCSP_CERTID for status check."); goto cleanup; }

    if (!OCSP_resp_find_status(bresp, cid, &status, &reason, &rev_time, &this_update, &next_update)) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "         > FAILED: Status for this certificate not found in the OCSP response.");
        goto cleanup;
    }

    if (OCSP_check_validity(this_update, next_update, OCSP_RESPONSE_VALIDITY_SLACK_SECONDS, -1L) <= 0) {
        LOG_PKI_ERROR("OCSP response is not within its validity period (stale response).");
        goto cleanup;
    }

    final_status = status;

cleanup:
    OCSP_CERTID_free(cid);
    OCSP_BASICRESP_free(bresp);
    return final_status;
}


static int check_ocsp_status(X509* user_cert, X509* issuer_cert, X509_STORE* store) {
    _hsc_log(HSC_LOG_LEVEL_INFO, "      iv. [Checking Revocation Status (OCSP)]:");
    int ret = HSC_ERROR_CERT_OCSP_UNAVAILABLE;

    // Fail-Closed 策略实施
    // 1. 首先检查证书中是否存在 OCSP URI (AIA 扩展)。
    STACK_OF(OPENSSL_STRING)* ocsp_uris = X509_get1_ocsp(user_cert);
    if (!ocsp_uris || sk_OPENSSL_STRING_num(ocsp_uris) <= 0) {
        _hsc_log(HSC_LOG_LEVEL_WARN, "         > WARNING: Certificate contains no OCSP URI (AIA extension missing).");
        
        // 检查全局配置：是否允许无OCSP URI的证书通过
        if (g_pki_config.allow_no_ocsp_uri) {
            _hsc_log(HSC_LOG_LEVEL_WARN, "         > CONFIG: 'Private PKI Mode' is enabled. Skipping revocation check.");
            if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
            return HSC_OK; 
        } else {
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > SECURITY FAILURE: No OCSP URI found. Security policy requires strict revocation checking.");
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > To allow this certificate, enable 'Private PKI Mode' in configuration (RISKY).");
            if (ocsp_uris) sk_OPENSSL_STRING_free(ocsp_uris);
            return HSC_ERROR_CERT_NO_OCSP_URI; // Fail-Closed
        }
    }
    sk_OPENSSL_STRING_free(ocsp_uris);

    OCSP_REQUEST* ocsp_req = _create_ocsp_request(user_cert, issuer_cert);
    if (!ocsp_req) {
        return ret;
    }

    // 2. 如果存在 URI，则尝试连接。如果此时失败（网络错误/服务器错误），则必须 Fail-Closed。
    OCSP_RESPONSE* ocsp_resp = _send_and_parse_ocsp_request(user_cert, ocsp_req);
    
    // [NOTE] Do NOT free ocsp_req yet, we need it for nonce verification
    
    if (!ocsp_resp) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "         > FAILED: OCSP URI exists, but server is unreachable (or blocked by SSRF protection).");
        _hsc_log(HSC_LOG_LEVEL_ERROR, "         > Security Policy: Fail-Closed enforced.");
        OCSP_REQUEST_free(ocsp_req); // Free request here as we fail out
        return ret;
    }

    // [FIX]: Pass ocsp_req to verification function
    int status = _verify_and_check_status(ocsp_resp, ocsp_req, store, user_cert, issuer_cert);
    
    OCSP_RESPONSE_free(ocsp_resp);
    OCSP_REQUEST_free(ocsp_req); // Clean up request

    switch (status) {
        case V_OCSP_CERTSTATUS_GOOD:
            _hsc_log(HSC_LOG_LEVEL_INFO, "         > SUCCESS: OCSP status is 'Good'. Certificate has not been revoked.");
            ret = HSC_OK;
            break;
        case V_OCSP_CERTSTATUS_REVOKED:
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > FAILED: OCSP status is 'Revoked'. Certificate has been revoked!");
            ret = HSC_ERROR_CERT_REVOKED;
            break;
        case V_OCSP_CERTSTATUS_UNKNOWN:
            _hsc_log(HSC_LOG_LEVEL_ERROR, "         > FAILED: OCSP status is 'Unknown'. This is treated as a revocation per security policy.");
            ret = HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN;
            break;
        default:
             LOG_PKI_ERROR("Unknown or failed OCSP certificate status check (including Nonce mismatch).");
             ret = HSC_ERROR_CERT_OCSP_UNAVAILABLE;
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

    // [FIX] Input Validation: PEM and Username
    // 1. Check length of expected_username to prevent overflow in comparisons
    if (strlen(expected_username) > CERT_COMMON_NAME_MAX_LEN) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: Expected username is too long.");
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    // 2. Check length of PEM input to prevent DoS via massive allocation
    if (strlen(user_cert_pem) > MAX_CERT_PEM_SIZE) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: User certificate PEM too large (Limit: %d bytes).", MAX_CERT_PEM_SIZE);
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    // Not strictly checking CA cert size here, as it's usually trusted/internal, but good practice if exposed.
    if (strlen(trusted_ca_cert_pem) > MAX_CERT_PEM_SIZE) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: CA certificate PEM too large (Limit: %d bytes).", MAX_CERT_PEM_SIZE);
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

    _hsc_log(HSC_LOG_LEVEL_INFO, "    Step i & ii (Chain & Validity Period):");
    store = X509_STORE_new();
    if (!store) { LOG_PKI_ERROR("Failed to create X509_STORE."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    if (X509_STORE_add_cert(store, ca_cert) != 1) { LOG_PKI_ERROR("Failed to add CA cert to store."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    
    ctx = X509_STORE_CTX_new();
    if (!ctx) { LOG_PKI_ERROR("Failed to create X509_STORE_CTX."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    if (X509_STORE_CTX_init(ctx, store, user_cert, NULL) != 1) { LOG_PKI_ERROR("Failed to initialize verification context."); ret_code = HSC_ERROR_PKI_OPERATION; goto cleanup; }
    
    if (X509_verify_cert(ctx) != 1) {
        long err = X509_STORE_CTX_get_error(ctx);
        _hsc_log(HSC_LOG_LEVEL_ERROR, "      > FAILED: %s", X509_verify_cert_error_string(err));
        ret_code = HSC_ERROR_CERT_CHAIN_OR_VALIDITY;
        goto cleanup;
    }
    _hsc_log(HSC_LOG_LEVEL_INFO, "      > SUCCESS: Certificate is signed by a trusted CA and is within its validity period.");

    _hsc_log(HSC_LOG_LEVEL_INFO, "    Step iii (Subject Verification):");
    X509_NAME* subject_name = X509_get_subject_name(user_cert);
    if (!subject_name) { LOG_PKI_ERROR("Could not get subject name from certificate."); ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH; goto cleanup; }
    char cn[CERT_COMMON_NAME_MAX_LEN] = {0};
    int cn_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName, cn, sizeof(cn) - 1);
    if (cn_len < 0) {
        LOG_PKI_ERROR("Could not extract Common Name from certificate.");
        ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH;
        goto cleanup;
    }

    size_t expected_len = strlen(expected_username);
    if (expected_len != (size_t)cn_len || sodium_memcmp(expected_username, cn, expected_len) != 0) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "      > FAILED: Certificate subject mismatch! Expected '%s', but got '%s'.", expected_username, cn);
        ret_code = HSC_ERROR_CERT_SUBJECT_MISMATCH;
        goto cleanup;
    }
    _hsc_log(HSC_LOG_LEVEL_INFO, "      > SUCCESS: Certificate subject matches the expected user '%s'.", expected_username);

    // [FIX] Vulnerability #2: Broken Chain Validation
    // 必须获取已验证的证书链，以找到用户证书的直接签发者（Issuer）。
    // 之前的代码错误地使用 Root CA 作为签发者，这在有中间 CA 时会导致 OCSP 失败。
    STACK_OF(X509)* chain = X509_STORE_CTX_get1_chain(ctx);
    if (!chain) {
        LOG_PKI_ERROR("Failed to retrieve verified certificate chain for OCSP check.");
        ret_code = HSC_ERROR_PKI_OPERATION;
        goto cleanup;
    }

    X509* real_issuer = NULL;
    // 链结构通常为: [0]=UserCert, [1]=Intermediate, [2]=Root...
    // 我们需要的是 [1] 作为直接签发者。
    // 如果链长度为 1，则说明是自签名或直接由根签发（且根未在链中作为额外元素），
    // 此时直接签发者就是它自己（自签名）或我们需要 fallback 到 Root。
    // 为了安全起见，对于标准 PKI，Issuer 通常在索引 1。
    if (sk_X509_num(chain) > 1) {
        real_issuer = sk_X509_value(chain, 1);
    } else {
        // Fallback: 假设 ca_cert 是直接签发者
        real_issuer = ca_cert; 
    }

    int ocsp_res = check_ocsp_status(user_cert, real_issuer, store);
    
    // 释放链副本
    sk_X509_pop_free(chain, X509_free);

    if (ocsp_res != HSC_OK) {
        ret_code = ocsp_res;
        goto cleanup;
    }

    ret_code = HSC_OK;

cleanup:
    if (ctx) X509_STORE_CTX_free(ctx);
    if (store) X509_STORE_free(store);
    if (user_cert) X509_free(user_cert);
    if (ca_cert) X509_free(ca_cert);
    if (user_bio) BIO_free(user_bio);
    if (ca_bio) BIO_free(ca_bio);
    
    return ret_code;
}

// [FIX]: Added public_key_max_len for safety (Vulnerability #1)
int extract_public_key_from_cert(const char* user_cert_pem,
                                 unsigned char* public_key_out,
                                 size_t public_key_max_len) {
    if (user_cert_pem == NULL || public_key_out == NULL) {
        return HSC_ERROR_INVALID_ARGUMENT;
    }
    
    // [FIX] Buffer Overflow Protection
    if (public_key_max_len < MASTER_PUBLIC_KEY_BYTES) {
        _hsc_log(HSC_LOG_LEVEL_ERROR, "PKI Error: Output buffer too small for public key (Required: %d, Provided: %zu).", MASTER_PUBLIC_KEY_BYTES, public_key_max_len);
        return HSC_ERROR_OUTPUT_BUFFER_TOO_SMALL;
    }

    int ret = HSC_ERROR_PKI_OPERATION;
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
    // MASTER_PUBLIC_KEY_BYTES 现在已定义 (通过 crypto_client.h -> security_spec.h)
    size_t pub_key_len = MASTER_PUBLIC_KEY_BYTES;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key_out, &pub_key_len) != 1 || pub_key_len != MASTER_PUBLIC_KEY_BYTES) {
        LOG_PKI_ERROR("Failed to get raw public key bytes from certificate.");
        goto cleanup;
    }
    ret = HSC_OK;
cleanup:
    if (pkey) EVP_PKEY_free(pkey);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);
    return ret;
}