// src/cli.c (版本 2.1 - 最终版，包含所有简化和 verify-cert)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h> 

// 在某些非GNU系统上需要此头文件
#if defined(__linux__) || defined(__APPLE__)
#include <endian.h>
#else // 简单的 Windows 或其他平台回退
#ifndef htole64
#define htole64(x) (x)
#endif
#ifndef le64toh
#define le64toh(x) (x)
#endif
#endif


#include "common/security_spec.h"
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

// --- 辅助函数 ---

// 打印简化的帮助信息
void print_usage(const char* prog_name) {
    fprintf(stderr, "高安全性混合加密系统 v4.1 (简化版 CLI)\n\n");
    fprintf(stderr, "用法: %s <命令> [参数...]\n\n", prog_name);
    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair <basename>\n");
    fprintf(stderr, "    ↳ 生成 <basename>.pub 和 <basename>.key\n\n");
    fprintf(stderr, "  gen-csr <private-key-file> <username>\n");
    fprintf(stderr, "    ↳ 使用私钥为用户生成 CSR 文件 (输出 <private-key-file>.csr)\n\n");
    fprintf(stderr, "  verify-cert <cert-to-verify> --ca <ca-cert> --user <expected-user>\n");
    fprintf(stderr, "    ↳ 验证一个证书的有效性\n\n");
    fprintf(stderr, "  encrypt <file> --to <recipient-cert> --from <sender-priv-key>\n");
    fprintf(stderr, "    ↳ 加密文件，生成一个打包好的 <file>.hsc 文件\n\n");
    fprintf(stderr, "  decrypt <file.hsc> --from <sender-cert> --to <recipient-priv-key>\n");
    fprintf(stderr, "    ↳ 解密 .hsc 文件，恢复原始文件 (输出 <file>.decrypted)\n");
}

// 从文件读取字节
unsigned char* read_file_bytes(const char* filename, size_t* out_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) { perror("无法打开文件"); return NULL; }
    fseek(f, 0, SEEK_END); long len = ftell(f); fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); fprintf(stderr,"错误: 文件为空或无法读取: %s\n", filename); return NULL; }
    unsigned char* buffer = malloc(len + 1); // +1 for potential null terminator
    if (!buffer) { fclose(f); fprintf(stderr, "内存分配失败\n"); return NULL; }
    if (fread(buffer, 1, len, f) != (size_t)len) { fclose(f); free(buffer); fprintf(stderr, "读取文件失败: %s\n", filename); return NULL; }
    buffer[len] = '\0'; // Ensure string is null-terminated for text-based files like certs
    *out_len = len; fclose(f); return buffer;
}

// 将字节写入文件
bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { perror("无法创建文件"); return false; }
    if (fwrite(data, 1, len, f) != len) { fclose(f); fprintf(stderr, "写入文件失败: %s\n", filename); return false; }
    fclose(f); return true;
}

// --- 打包/解包逻辑 ---
// 包格式: [ 8字节: 封装密钥长度 (小端序) ] [ 封装的密钥 ] [ 加密的数据 ]
bool create_package(const char* filename, const void* key_data, size_t key_len, const void* encrypted_data, size_t data_len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { perror("无法创建包文件"); return false; }
    uint64_t key_len_le = htole64(key_len);
    if (fwrite(&key_len_le, sizeof(uint64_t), 1, f) != 1) { fprintf(stderr, "错误: 写入包头失败\n"); fclose(f); return false; }
    if (fwrite(key_data, 1, key_len, f) != key_len) { fprintf(stderr, "错误: 写入封装密钥失败\n"); fclose(f); return false; }
    if (fwrite(encrypted_data, 1, data_len, f) != data_len) { fprintf(stderr, "错误: 写入加密数据失败\n"); fclose(f); return false; }
    fclose(f); return true;
}

bool unpack_package(const char* filename, unsigned char** key_data, size_t* key_len, unsigned char** encrypted_data, size_t* data_len) {
    size_t total_len;
    unsigned char* buffer = read_file_bytes(filename, &total_len);
    if (!buffer) return false;
    if (total_len < sizeof(uint64_t)) { fprintf(stderr, "错误: 包文件过小，无法解析\n"); free(buffer); return false; }
    uint64_t key_len_le;
    memcpy(&key_len_le, buffer, sizeof(uint64_t));
    *key_len = le64toh(key_len_le);
    if (total_len < sizeof(uint64_t) + *key_len) { fprintf(stderr, "错误: 包文件损坏或长度不一致\n"); free(buffer); return false; }
    *key_data = malloc(*key_len);
    if (!*key_data) { fprintf(stderr, "内存分配失败\n"); free(buffer); return false; }
    memcpy(*key_data, buffer + sizeof(uint64_t), *key_len);
    *data_len = total_len - sizeof(uint64_t) - *key_len;
    *encrypted_data = malloc(*data_len);
     if (!*encrypted_data) { fprintf(stderr, "内存分配失败\n"); free(buffer); free(*key_data); *key_data=NULL; return false; }
    memcpy(*encrypted_data, buffer + sizeof(uint64_t) + *key_len, *data_len);
    free(buffer); return true;
}

// --- 命令处理函数 ---

int handle_gen_keypair(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s gen-keypair <文件名基础>\n", argv[0]);
        return 1;
    }
    const char* basename = argv[2];
    char pub_path[260];
    char priv_path[260];
    snprintf(pub_path, sizeof(pub_path), "%s.pub", basename);
    snprintf(priv_path, sizeof(priv_path), "%s.key", basename);

    master_key_pair mkp;
    if (generate_master_key_pair(&mkp) != 0) {
        fprintf(stderr, "错误: 生成主密钥对失败。\n"); return 1;
    }
    
    bool success = write_file_bytes(pub_path, mkp.pk, MASTER_PUBLIC_KEY_BYTES) &&
                   write_file_bytes(priv_path, mkp.sk, MASTER_SECRET_KEY_BYTES);

    free_master_key_pair(&mkp);
    if (success) {
        printf("✅ 成功生成密钥对:\n  公钥 -> %s\n  私钥 -> %s\n", pub_path, priv_path);
    }
    return success ? 0 : 1;
}

int handle_gen_csr(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "用法: %s gen-csr <私钥文件> \"<用户名>\"\n", argv[0]);
        return 1;
    }
    const char* priv_path = argv[2];
    const char* user_cn = argv[3];
    
    char csr_path[260];
    // 从私钥文件名派生出CSR文件名
    const char* dot = strrchr(priv_path, '.');
    if(dot) {
        snprintf(csr_path, dot - priv_path + 1, "%s", priv_path);
    } else {
        strncpy(csr_path, priv_path, sizeof(csr_path) - 5);
    }
    strncat(csr_path, ".csr", sizeof(csr_path) - strlen(csr_path) - 1);


    master_key_pair mkp;
    size_t sk_len;
    mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!mkp.sk) { fprintf(stderr, "安全内存分配失败\n"); return 1; }
    unsigned char* sk_from_file = read_file_bytes(priv_path, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取或验证私钥失败。\n");
        secure_free(mkp.sk); free(sk_from_file); return 1;
    }
    memcpy(mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len);
    free(sk_from_file);

    char* csr_pem = NULL;
    if (generate_csr(&mkp, user_cn, &csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 CSR 失败。\n");
        free_master_key_pair(&mkp); return 1;
    }

    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) {
        fprintf(stderr, "错误: 写入 CSR 文件失败。\n");
    } else {
        printf("✅ 成功为用户 '%s' 生成 CSR -> %s\n", user_cn, csr_path);
    }
    free_master_key_pair(&mkp);
    free_csr_pem(csr_pem);
    return 0;
}

int handle_verify_cert(int argc, char* argv[]) {
    const char* cert_path = NULL;
    const char* ca_path = NULL;
    const char* user_cn = NULL;

    if (argc < 3) { goto usage; }
    cert_path = argv[2];

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) ca_path = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) user_cn = argv[++i];
    }
    if (!cert_path || !ca_path || !user_cn) {
    usage:
        fprintf(stderr, "用法: %s verify-cert <待验证证书> --ca <CA根证书> --user <预期用户名>\n", argv[0]);
        return 1;
    }

    size_t cert_len, ca_len;
    char* user_cert_pem = (char*)read_file_bytes(cert_path, &cert_len);
    char* ca_cert_pem = (char*)read_file_bytes(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) { free(user_cert_pem); free(ca_cert_pem); return 1; }
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = verify_user_certificate(user_cert_pem, ca_cert_pem, user_cn);

    free(user_cert_pem); free(ca_cert_pem);

    switch(result) {
        case 0:  printf("\033[32m[成功]\033[0m 证书所有验证项均通过。\n"); return 0;
        case -2: fprintf(stderr, "\033[31m[失败]\033[0m 证书签名链或有效期验证失败。\n"); return 1;
        case -3: fprintf(stderr, "\033[31m[失败]\033[0m 证书主体 (用户名) 不匹配。\n"); return 1;
        case -4: fprintf(stderr, "\033[31m[失败]\033[0m 证书吊销状态检查失败 (OCSP)！\n"); return 1;
        default: fprintf(stderr, "\033[31m[失败]\033[0m 未知的验证错误 (代码: %d)。\n", result); return 1;
    }
}

int handle_hybrid_encrypt(int argc, char* argv[]) {
    const char* in_file = NULL;
    const char* recipient_cert_file = NULL;
    const char* sender_priv_file = NULL;

    if (argc < 3) { goto usage; }
    in_file = argv[2];

    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) recipient_cert_file = argv[++i];
        else if (strcmp(argv[i], "--from") == 0 && i + 1 < argc) sender_priv_file = argv[++i];
    }
    if (!in_file || !recipient_cert_file || !sender_priv_file) {
    usage:
        fprintf(stderr, "用法: %s encrypt <文件> --to <接收方证书> --from <发送方私钥>\n", argv[0]);
        return 1;
    }

    char out_file[260];
    snprintf(out_file, sizeof(out_file), "%s.hsc", in_file);

    int ret = 1;
    unsigned char* plaintext = NULL, *encrypted_data = NULL, *encapsulated_key = NULL;
    master_key_pair sender_mkp = { .sk = NULL };
    char* recipient_cert_pem = NULL;
    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    size_t plaintext_len;
    plaintext = read_file_bytes(in_file, &plaintext_len);
    if (!plaintext) goto cleanup;

    size_t enc_buf_len = plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    encrypted_data = malloc(enc_buf_len);
    if (!encrypted_data) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    unsigned long long actual_enc_len;
    if (encrypt_symmetric_aead(encrypted_data, &actual_enc_len, plaintext, plaintext_len, session_key) != 0) goto cleanup;

    size_t cert_len;
    recipient_cert_pem = (char*)read_file_bytes(recipient_cert_file, &cert_len);
    if (!recipient_cert_pem) goto cleanup;
    
    unsigned char recipient_pk[MASTER_PUBLIC_KEY_BYTES];
    if (extract_public_key_from_cert(recipient_cert_pem, recipient_pk) != 0) goto cleanup;

    size_t sk_len;
    sender_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!sender_mkp.sk) { fprintf(stderr, "安全内存分配失败\n"); goto cleanup; }
    unsigned char* sk_from_file = read_file_bytes(sender_priv_file, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) goto cleanup;
    memcpy(sender_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len); free(sk_from_file);

    size_t enc_key_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_key_buf_len);
    if (!encapsulated_key) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    size_t actual_encapsulated_len;
    if (encapsulate_session_key(encapsulated_key, &actual_encapsulated_len, session_key, sizeof(session_key), recipient_pk, sender_mkp.sk) != 0) goto cleanup;

    if (!create_package(out_file, encapsulated_key, actual_encapsulated_len, encrypted_data, actual_enc_len)) goto cleanup;

    printf("✅ 混合加密完成！\n  输出文件 -> %s\n", out_file);
    ret = 0;

cleanup:
    free(plaintext); free(encrypted_data); free(encapsulated_key); free(recipient_cert_pem);
    if(sender_mkp.sk) free_master_key_pair(&sender_mkp);
    secure_zero_memory(session_key, sizeof(session_key));
    return ret;
}

int handle_hybrid_decrypt(int argc, char* argv[]) {
    const char* in_file = NULL;
    const char* sender_cert_file = NULL;
    const char* recipient_priv_file = NULL;

    if (argc < 3) { goto usage; }
    in_file = argv[2];

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--from") == 0 && i + 1 < argc) sender_cert_file = argv[++i];
        else if (strcmp(argv[i], "--to") == 0 && i + 1 < argc) recipient_priv_file = argv[++i];
    }
    if (!in_file || !sender_cert_file || !recipient_priv_file) {
    usage:
        fprintf(stderr, "用法: %s decrypt <file.hsc> --from <发送方证书> --to <接收方私钥>\n", argv[0]);
        return 1;
    }

    char out_file[260];
    const char* dot = strrchr(in_file, '.');
    if(dot && strcmp(dot, ".hsc") == 0) {
        snprintf(out_file, dot - in_file + 1, "%s", in_file);
    } else {
        strncpy(out_file, in_file, sizeof(out_file) - 11);
    }
    strncat(out_file, ".decrypted", sizeof(out_file) - strlen(out_file) - 1);

    int ret = 1;
    unsigned char *enc_data = NULL, *enc_key = NULL, *dec_plaintext = NULL;
    size_t enc_data_len, enc_key_len;
    char* sender_cert_pem = NULL;
    master_key_pair recipient_mkp = { .sk = NULL };
    unsigned char* dec_session_key = NULL;

    if (!unpack_package(in_file, &enc_key, &enc_key_len, &enc_data, &enc_data_len)) goto cleanup;

    size_t cert_len;
    sender_cert_pem = (char*)read_file_bytes(sender_cert_file, &cert_len);
    if (!sender_cert_pem) goto cleanup;
    unsigned char sender_pk[MASTER_PUBLIC_KEY_BYTES];
    if (extract_public_key_from_cert(sender_cert_pem, sender_pk) != 0) goto cleanup;
    
    size_t sk_len;
    recipient_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!recipient_mkp.sk) { fprintf(stderr, "安全内存分配失败\n"); goto cleanup; }
    unsigned char* sk_from_file = read_file_bytes(recipient_priv_file, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) goto cleanup;
    memcpy(recipient_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len); free(sk_from_file);

    dec_session_key = secure_alloc(SESSION_KEY_BYTES);
    if (!dec_session_key) { fprintf(stderr, "安全内存分配失败\n"); goto cleanup; }
    if (decapsulate_session_key(dec_session_key, enc_key, enc_key_len, sender_pk, recipient_mkp.sk) != 0) {
        fprintf(stderr, "错误: 解封装会话密钥失败！可能是密钥或证书错误。\n"); goto cleanup;
    }

    dec_plaintext = malloc(enc_data_len);
    if (!dec_plaintext) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    unsigned long long actual_dec_len;
    if (decrypt_symmetric_aead(dec_plaintext, &actual_dec_len, enc_data, enc_data_len, dec_session_key) != 0) {
        fprintf(stderr, "错误: 解密文件内容失败！可能是数据被篡改。\n"); goto cleanup;
    }

    if (!write_file_bytes(out_file, dec_plaintext, actual_dec_len)) goto cleanup;
    
    printf("✅ 混合解密完成！\n  解密文件 -> %s\n", out_file);
    ret = 0;

cleanup:
    free(enc_data); free(enc_key); free(dec_plaintext); free(sender_cert_pem);
    if(recipient_mkp.sk) free_master_key_pair(&recipient_mkp);
    if (dec_session_key) secure_free(dec_session_key);
    return ret;
}


// --- Main 函数 ---
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (crypto_client_init() != 0 || pki_init() != 0) {
        fprintf(stderr, "严重错误: 依赖库初始化失败！\n");
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "gen-keypair") == 0) {
        return handle_gen_keypair(argc, argv);
    } else if (strcmp(command, "gen-csr") == 0) {
        return handle_gen_csr(argc, argv);
    } else if (strcmp(command, "encrypt") == 0) {
        return handle_hybrid_encrypt(argc, argv);
    } else if (strcmp(command, "decrypt") == 0) {
        return handle_hybrid_decrypt(argc, argv);
    } else if (strcmp(command, "verify-cert") == 0) {
        return handle_verify_cert(argc, argv);
    } else {
        fprintf(stderr, "错误: 未知命令 '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}