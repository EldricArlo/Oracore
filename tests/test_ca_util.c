#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sodium.h>

// [修复] 移除此处的宏定义，因为它已由 <openssl/x509.h> 提供
// #define X509_VERSION_3 2L 

#define SECONDS_IN_A_YEAR 31536000L

// --- 文件 I/O 辅助函数 ---
char* read_file_to_string(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (length < 0) {
        fclose(f);
        fprintf(stderr, "Error: Cannot determine size of file '%s'.\n", filename);
        return NULL;
    }
    char* buffer = malloc(length + 1);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "Error: Memory allocation failed.\n");
        return NULL;
    }
    if (fread(buffer, 1, length, f) != (size_t)length) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "Error: Failed to read file '%s'.\n", filename);
        return NULL;
    }
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}

bool write_string_to_file(const char* filename, const char* data) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Error: Cannot create file '%s': %s\n", filename, strerror(errno));
        return false;
    }
    bool success = (fwrite(data, 1, strlen(data), f) == strlen(data));
    if (!success) {
        fprintf(stderr, "Error writing to file '%s'.\n", filename);
    }
    fclose(f);
    return success;
}

// --- 核心证书操作函数 (从原 main.c 迁移并修改) ---

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

int do_generate_test_ca(const char* ca_key_path, const char* ca_cert_path) {
    int ret = -1;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *key_bio = NULL, *cert_bio = NULL;
    char *ca_key_pem = NULL, *ca_cert_pem = NULL;

    unsigned char ca_sk_seed[crypto_sign_SEEDBYTES];
    memset(ca_sk_seed, 0xCA, sizeof(ca_sk_seed));

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ca_sk_seed, sizeof(ca_sk_seed));
    if (!pkey) goto cleanup;

    cert = X509_new();
    if (!cert) goto cleanup;

    // 使用 OpenSSL 提供的 X509_VERSION_3
    X509_set_version(cert, 2L); // 2L 对应 X509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), SECONDS_IN_A_YEAR);
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
    ca_key_pem = (char*)malloc(key_mem->length + 1);
    if (!ca_key_pem) goto cleanup;
    memcpy(ca_key_pem, key_mem->data, key_mem->length);
    ca_key_pem[key_mem->length] = '\0';

    BIO_get_mem_ptr(cert_bio, &cert_mem);
    ca_cert_pem = (char*)malloc(cert_mem->length + 1);
    if (!ca_cert_pem) goto cleanup;
    memcpy(ca_cert_pem, cert_mem->data, cert_mem->length);
    ca_cert_pem[cert_mem->length] = '\0';
    
    if (write_string_to_file(ca_key_path, ca_key_pem) && write_string_to_file(ca_cert_path, ca_cert_pem)) {
        printf("✅ 成功生成CA密钥和证书:\n  CA私钥 -> %s\n  CA证书 -> %s\n", ca_key_path, ca_cert_path);
        ret = 0;
    }

cleanup:
    free(ca_key_pem);
    free(ca_cert_pem);
    EVP_PKEY_free(pkey); X509_free(cert);
    BIO_free(key_bio); BIO_free(cert_bio);
    return ret;
}

int do_sign_csr(const char* csr_path, const char* ca_key_path, const char* ca_cert_path, const char* user_cert_path) {
    int ret = -1;
    BIO *csr_bio = NULL, *ca_key_bio = NULL, *ca_cert_bio = NULL, *out_bio = NULL;
    X509_REQ *req = NULL;
    EVP_PKEY *ca_key = NULL;
    X509 *ca_cert = NULL, *user_cert = NULL;
    EVP_PKEY* req_pubkey = NULL;
    char* csr_pem = NULL, *ca_key_pem = NULL, *ca_cert_pem = NULL, *user_cert_pem = NULL;

    csr_pem = read_file_to_string(csr_path);
    ca_key_pem = read_file_to_string(ca_key_path);
    ca_cert_pem = read_file_to_string(ca_cert_path);
    if (!csr_pem || !ca_key_pem || !ca_cert_pem) goto cleanup;

    csr_bio = BIO_new_mem_buf(csr_pem, -1);
    ca_key_bio = BIO_new_mem_buf(ca_key_pem, -1);
    ca_cert_bio = BIO_new_mem_buf(ca_cert_pem, -1);
    if(!csr_bio || !ca_key_bio || !ca_cert_bio) goto cleanup;

    req = PEM_read_bio_X509_REQ(csr_bio, NULL, NULL, NULL);
    ca_key = PEM_read_bio_PrivateKey(ca_key_bio, NULL, NULL, NULL);
    ca_cert = PEM_read_bio_X509(ca_cert_bio, NULL, NULL, NULL);
    if(!req || !ca_key || !ca_cert) { fprintf(stderr, "Error: Failed to parse PEM inputs.\n"); goto cleanup; }

    user_cert = X509_new();
    if(!user_cert) goto cleanup;

    // 使用 OpenSSL 提供的 X509_VERSION_3
    X509_set_version(user_cert, 2L); // 2L 对应 X509 v3
    ASN1_INTEGER_set(X509_get_serialNumber(user_cert), 2);
    X509_set_issuer_name(user_cert, X509_get_subject_name(ca_cert));
    X509_gmtime_adj(X509_getm_notBefore(user_cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(user_cert), SECONDS_IN_A_YEAR);
    
    req_pubkey = X509_REQ_get_pubkey(req);
    if (!req_pubkey) goto cleanup;
    X509_set_subject_name(user_cert, X509_REQ_get_subject_name(req));
    X509_set_pubkey(user_cert, req_pubkey);
    
    // 为OCSP检查添加 Authority Information Access 扩展
    add_ext(user_cert, NID_info_access, "OCSP;URI:http://ocsp.digicert.com"); // 使用一个真实的OCSP服务器以供测试

    if (X509_sign(user_cert, ca_key, NULL) <= 0) goto cleanup;

    out_bio = BIO_new(BIO_s_mem());
    if(!out_bio) goto cleanup;
    if(!PEM_write_bio_X509(out_bio, user_cert)) goto cleanup;
    
    BUF_MEM *out_mem;
    BIO_get_mem_ptr(out_bio, &out_mem);
    user_cert_pem = (char*)malloc(out_mem->length + 1);
    if (!user_cert_pem) goto cleanup;
    memcpy(user_cert_pem, out_mem->data, out_mem->length);
    user_cert_pem[out_mem->length] = '\0';
    
    if (write_string_to_file(user_cert_path, user_cert_pem)) {
        printf("✅ 成功签署CSR '%s' -> %s\n", csr_path, user_cert_path);
        ret = 0;
    }

cleanup:
    free(csr_pem); free(ca_key_pem); free(ca_cert_pem); free(user_cert_pem);
    EVP_PKEY_free(req_pubkey);
    BIO_free(csr_bio); BIO_free(ca_key_bio); BIO_free(ca_cert_bio); BIO_free(out_bio);
    X509_REQ_free(req); EVP_PKEY_free(ca_key); X509_free(ca_cert); X509_free(user_cert);
    return ret;
}

void print_usage(const char* prog_name) {
    fprintf(stderr, "Oracipher Core - 测试CA工具\n\n");
    fprintf(stderr, "用法:\n");
    fprintf(stderr, "  %s gen-ca <ca-key-out.key> <ca-cert-out.pem>\n", prog_name);
    fprintf(stderr, "    -> 生成一个新的根CA密钥对和自签名证书。\n\n");
    fprintf(stderr, "  %s sign <user.csr> <ca.key> <ca.pem> <user-cert-out.pem>\n", prog_name);
    fprintf(stderr, "    -> 使用指定的CA签署一个用户的证书签名请求(CSR)。\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "Fatal: Libsodium initialization failed.\n");
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "gen-ca") == 0) {
        if (argc != 4) { print_usage(argv[0]); return 1; }
        return do_generate_test_ca(argv[2], argv[3]);
    } else if (strcmp(command, "sign") == 0) {
        if (argc != 6) { print_usage(argv[0]); return 1; }
        return do_sign_csr(argv[2], argv[3], argv[4], argv[5]);
    } else {
        fprintf(stderr, "错误: 未知命令 '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}