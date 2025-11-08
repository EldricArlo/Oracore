// src/cli.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "common/security_spec.h"
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

// --- 辅助函数 ---

// 打印帮助信息
void print_usage(const char* prog_name) {
    fprintf(stderr, "高安全性混合加密系统 v4.0 CLI 工具\n\n");
    fprintf(stderr, "用法: %s <命令> [选项...]\n\n", prog_name);
    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair     生成一个主密钥对 (Ed25519)。\n");
    fprintf(stderr, "  gen-csr         根据私钥生成一个证书签名请求 (CSR)。\n");
    fprintf(stderr, "  verify-cert     验证一个用户证书。\n");
    fprintf(stderr, "  hybrid-encrypt  使用混合加密来加密一个文件。\n");
    fprintf(stderr, "  hybrid-decrypt  解密一个被混合加密过的文件。\n\n");
    fprintf(stderr, "详细选项请使用 ' %s <命令> --help ' 查看。\n", prog_name);
}

// 从文件读取字节
unsigned char* read_file_bytes(const char* filename, size_t* out_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        perror("无法打开文件");
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) {
        fclose(f);
        fprintf(stderr, "错误: 文件为空或读取长度失败: %s\n", filename);
        return NULL;
    }

    unsigned char* buffer = malloc(len);
    if (!buffer) {
        fclose(f);
        fprintf(stderr, "内存分配失败\n");
        return NULL;
    }

    if (fread(buffer, 1, len, f) != (size_t)len) {
        fclose(f);
        free(buffer);
        fprintf(stderr, "读取文件失败: %s\n", filename);
        return NULL;
    }

    *out_len = len;
    fclose(f);
    return buffer;
}

// 将字节写入文件
bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        perror("无法创建文件");
        return false;
    }
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        fprintf(stderr, "写入文件失败: %s\n", filename);
        return false;
    }
    fclose(f);
    return true;
}

// --- 命令处理函数 ---

// `gen-keypair` 命令
int handle_gen_keypair(int argc, char* argv[]) {
    const char* pub_path = NULL;
    const char* priv_path = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc) {
            pub_path = argv[++i];
        } else if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc) {
            priv_path = argv[++i];
        }
    }

    if (!pub_path || !priv_path) {
        fprintf(stderr, "用法: %s gen-keypair --pub <公钥输出文件> --priv <私钥输出文件>\n", argv[0]);
        return 1;
    }

    master_key_pair mkp;
    if (generate_master_key_pair(&mkp) != 0) {
        fprintf(stderr, "错误: 生成主密钥对失败。\n");
        return 1;
    }

    bool success = true;
    if (!write_file_bytes(pub_path, mkp.pk, MASTER_PUBLIC_KEY_BYTES)) {
        fprintf(stderr, "错误: 写入公钥文件失败。\n");
        success = false;
    }
    if (!write_file_bytes(priv_path, mkp.sk, MASTER_SECRET_KEY_BYTES)) {
        fprintf(stderr, "错误: 写入私钥文件失败。\n");
        success = false;
    }

    free_master_key_pair(&mkp);

    if (success) {
        printf("成功生成密钥对:\n");
        printf("  公钥 -> %s\n", pub_path);
        printf("  私钥 -> %s\n", priv_path);
    }
    return success ? 0 : 1;
}

// `gen-csr` 命令
int handle_gen_csr(int argc, char* argv[]) {
    const char* priv_path = NULL;
    const char* user_cn = NULL;
    const char* csr_path = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--priv") == 0 && i + 1 < argc) priv_path = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) user_cn = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) csr_path = argv[++i];
    }
    
    if (!priv_path || !user_cn || !csr_path) {
        fprintf(stderr, "用法: %s gen-csr --priv <私钥文件> --user <用户名/CN> --out <CSR输出文件>\n", argv[0]);
        return 1;
    }

    master_key_pair mkp;
    size_t sk_len;
    // 私钥需要被分配在安全内存中
    mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    unsigned char* sk_from_file = read_file_bytes(priv_path, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取或验证私钥失败。\n");
        secure_free(mkp.sk);
        free(sk_from_file);
        return 1;
    }
    memcpy(mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len); // 擦除临时副本
    free(sk_from_file);

    char* csr_pem = NULL;
    if (generate_csr(&mkp, user_cn, &csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 CSR 失败。\n");
        free_master_key_pair(&mkp);
        return 1;
    }

    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) {
        fprintf(stderr, "错误: 写入 CSR 文件失败。\n");
        free_master_key_pair(&mkp);
        free_csr_pem(csr_pem);
        return 1;
    }

    printf("成功为用户 '%s' 生成 CSR -> %s\n", user_cn, csr_path);
    free_master_key_pair(&mkp);
    free_csr_pem(csr_pem);
    return 0;
}

// `verify-cert` 命令
int handle_verify_cert(int argc, char* argv[]) {
    const char* cert_path = NULL;
    const char* ca_path = NULL;
    const char* user_cn = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) cert_path = argv[++i];
        else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) ca_path = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) user_cn = argv[++i];
    }

    if (!cert_path || !ca_path || !user_cn) {
        fprintf(stderr, "用法: %s verify-cert --cert <用户证书> --ca <根CA证书> --user <预期用户名>\n", argv[0]);
        return 1;
    }

    size_t cert_len, ca_len;
    char* user_cert_pem = (char*)read_file_bytes(cert_path, &cert_len);
    char* ca_cert_pem = (char*)read_file_bytes(ca_path, &ca_len);

    if (!user_cert_pem || !ca_cert_pem) {
        free(user_cert_pem);
        free(ca_cert_pem);
        return 1;
    }
    
    // 添加 null 终止符
    user_cert_pem[cert_len] = '\0';
    ca_cert_pem[ca_len] = '\0';
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = verify_user_certificate(user_cert_pem, ca_cert_pem, user_cn);

    free(user_cert_pem);
    free(ca_cert_pem);

    switch(result) {
        case 0:
            printf("\033[32m[成功]\033[0m 证书所有验证项均通过。\n");
            return 0;
        case -1:
            fprintf(stderr, "\033[31m[失败]\033[0m 发生内部错误 (如内存分配、PEM解析)。\n");
            return 1;
        case -2:
            fprintf(stderr, "\033[31m[失败]\033[0m 证书签名链或有效期验证失败。\n");
            return 1;
        case -3:
            fprintf(stderr, "\033[31m[失败]\033[0m 证书主体 (用户名) 不匹配。\n");
            return 1;
        case -4:
            fprintf(stderr, "\033[31m[失败]\033[0m 证书吊销状态检查失败 (OCSP)！\n");
            return 1;
        default:
            fprintf(stderr, "\033[31m[失败]\033[0m 未知的验证错误。\n");
            return 1;
    }
}

// `hybrid-encrypt` 命令
int handle_hybrid_encrypt(int argc, char* argv[]) {
    const char* in_file = NULL;
    const char* out_data = NULL;
    const char* out_key = NULL;
    const char* recipient_cert_file = NULL;
    const char* sender_priv_file = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) in_file = argv[++i];
        else if (strcmp(argv[i], "--out-data") == 0 && i + 1 < argc) out_data = argv[++i];
        else if (strcmp(argv[i], "--out-key") == 0 && i + 1 < argc) out_key = argv[++i];
        else if (strcmp(argv[i], "--recipient-cert") == 0 && i + 1 < argc) recipient_cert_file = argv[++i];
        else if (strcmp(argv[i], "--sender-priv") == 0 && i + 1 < argc) sender_priv_file = argv[++i];
    }
    if (!in_file || !out_data || !out_key || !recipient_cert_file || !sender_priv_file) {
        fprintf(stderr, "用法: %s hybrid-encrypt --in <明文文件> --out-data <加密数据输出> --out-key <封装密钥输出> --recipient-cert <接收方证书> --sender-priv <发送方私钥>\n", argv[0]);
        return 1;
    }

    int ret = 1; // 默认失败
    unsigned char* plaintext = NULL;
    unsigned char* encrypted_data = NULL;
    unsigned char* encapsulated_key = NULL;
    master_key_pair sender_mkp = { .sk = NULL };
    char* recipient_cert_pem = NULL;

    // 1. 生成一次性会话密钥
    unsigned char session_key[SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));
    printf("1. 已生成临时会话密钥。\n");

    // 2. 读取明文文件
    size_t plaintext_len;
    plaintext = read_file_bytes(in_file, &plaintext_len);
    if (!plaintext) goto cleanup;
    printf("2. 已读取明文文件: %s (%zu 字节)。\n", in_file, plaintext_len);

    // 3. 对称加密文件内容
    size_t enc_buf_len = plaintext_len + crypto_aead_xchacha20poly1305_ietf_ABYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    encrypted_data = malloc(enc_buf_len);
    if (!encrypted_data) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    unsigned long long actual_enc_len;
    if (encrypt_symmetric_aead(encrypted_data, &actual_enc_len, plaintext, plaintext_len, session_key) != 0) {
        fprintf(stderr, "错误: 对称加密失败！\n");
        goto cleanup;
    }
    printf("3. 已使用AEAD对称加密文件内容。\n");

    // 4. 读取接收方证书并提取公钥
    size_t cert_len;
    recipient_cert_pem = (char*)read_file_bytes(recipient_cert_file, &cert_len);
    if (!recipient_cert_pem) goto cleanup;
    recipient_cert_pem[cert_len] = '\0';

    unsigned char recipient_pk[MASTER_PUBLIC_KEY_BYTES];
    if (extract_public_key_from_cert(recipient_cert_pem, recipient_pk) != 0) {
        fprintf(stderr, "错误: 无法从接收方证书中提取公钥！\n");
        goto cleanup;
    }
    printf("4. 已从接收方证书中提取公钥。\n");

    // 5. 读取发送方私钥
    size_t sk_len;
    sender_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    unsigned char* sk_from_file = read_file_bytes(sender_priv_file, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取或验证发送方私钥失败。\n");
        goto cleanup;
    }
    memcpy(sender_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len);
    free(sk_from_file);
    printf("5. 已加载发送方私钥。\n");

    // 6. 封装会话密钥
    size_t enc_key_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_key_buf_len);
    if (!encapsulated_key) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    size_t actual_encapsulated_len;
    if (encapsulate_session_key(encapsulated_key, &actual_encapsulated_len, session_key, sizeof(session_key), recipient_pk, sender_mkp.sk) != 0) {
        fprintf(stderr, "错误: 封装会话密钥失败！\n");
        goto cleanup;
    }
    printf("6. 已使用非对称加密封装会话密钥。\n");

    // 7. 写入输出文件
    if (!write_file_bytes(out_data, encrypted_data, actual_enc_len)) goto cleanup;
    if (!write_file_bytes(out_key, encapsulated_key, actual_encapsulated_len)) goto cleanup;

    printf("\n\033[32m[成功]\033[0m 混合加密完成！\n");
    printf("  - 加密数据 -> %s\n", out_data);
    printf("  - 封装密钥 -> %s\n", out_key);
    ret = 0;

cleanup:
    free(plaintext);
    free(encrypted_data);
    free(encapsulated_key);
    free(recipient_cert_pem);
    free_master_key_pair(&sender_mkp);
    secure_zero_memory(session_key, sizeof(session_key)); // 清理会话密钥
    return ret;
}

// `hybrid-decrypt` 命令
int handle_hybrid_decrypt(int argc, char* argv[]) {
    const char* in_data = NULL;
    const char* in_key = NULL;
    const char* out_file = NULL;
    const char* sender_cert_file = NULL;
    const char* recipient_priv_file = NULL;

     for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--in-data") == 0 && i + 1 < argc) in_data = argv[++i];
        else if (strcmp(argv[i], "--in-key") == 0 && i + 1 < argc) in_key = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) out_file = argv[++i];
        else if (strcmp(argv[i], "--sender-cert") == 0 && i + 1 < argc) sender_cert_file = argv[++i];
        else if (strcmp(argv[i], "--recipient-priv") == 0 && i + 1 < argc) recipient_priv_file = argv[++i];
    }
    if (!in_data || !in_key || !out_file || !sender_cert_file || !recipient_priv_file) {
        fprintf(stderr, "用法: %s hybrid-decrypt --in-data <加密数据> --in-key <封装密钥> --out <解密输出文件> --sender-cert <发送方证书> --recipient-priv <接收方私钥>\n", argv[0]);
        return 1;
    }

    int ret = 1; // 默认失败
    unsigned char* encrypted_data = NULL;
    unsigned char* encapsulated_key = NULL;
    unsigned char* decrypted_plaintext = NULL;
    char* sender_cert_pem = NULL;
    master_key_pair recipient_mkp = { .sk = NULL };
    unsigned char* decrypted_session_key = NULL;

    // 1. 读取发送方证书并提取公钥
    size_t cert_len;
    sender_cert_pem = (char*)read_file_bytes(sender_cert_file, &cert_len);
    if (!sender_cert_pem) goto cleanup;
    sender_cert_pem[cert_len] = '\0';
    unsigned char sender_pk[MASTER_PUBLIC_KEY_BYTES];
    if (extract_public_key_from_cert(sender_cert_pem, sender_pk) != 0) {
        fprintf(stderr, "错误: 无法从发送方证书中提取公钥！\n");
        goto cleanup;
    }
    printf("1. 已从发送方证书中提取公钥。\n");
    
    // 2. 读取接收方私钥
    size_t sk_len;
    recipient_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    unsigned char* sk_from_file = read_file_bytes(recipient_priv_file, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取或验证接收方私钥失败。\n");
        goto cleanup;
    }
    memcpy(recipient_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);
    secure_zero_memory(sk_from_file, sk_len);
    free(sk_from_file);
    printf("2. 已加载接收方私钥。\n");

    // 3. 读取封装的会话密钥并解封装
    size_t encapsulated_key_len;
    encapsulated_key = read_file_bytes(in_key, &encapsulated_key_len);
    if (!encapsulated_key) goto cleanup;

    decrypted_session_key = secure_alloc(SESSION_KEY_BYTES);
    if (!decrypted_session_key) { fprintf(stderr, "安全内存分配失败\n"); goto cleanup; }

    if (decapsulate_session_key(decrypted_session_key, encapsulated_key, encapsulated_key_len, sender_pk, recipient_mkp.sk) != 0) {
        fprintf(stderr, "错误: 解封装会话密钥失败！可能是密钥错误或数据被篡改。\n");
        goto cleanup;
    }
    printf("3. 已成功解封装会话密钥。\n");

    // 4. 读取加密数据并解密
    size_t encrypted_data_len;
    encrypted_data = read_file_bytes(in_data, &encrypted_data_len);
    if (!encrypted_data) goto cleanup;

    // 解密后的明文长度不会超过密文长度
    decrypted_plaintext = malloc(encrypted_data_len);
    if (!decrypted_plaintext) { fprintf(stderr, "内存分配失败\n"); goto cleanup; }
    
    unsigned long long actual_dec_len;
    if (decrypt_symmetric_aead(decrypted_plaintext, &actual_dec_len, encrypted_data, encrypted_data_len, decrypted_session_key) != 0) {
        fprintf(stderr, "错误: 解密文件内容失败！可能是密钥错误或数据被篡改。\n");
        goto cleanup;
    }
    printf("4. 已使用恢复的会话密钥解密文件内容。\n");

    // 5. 写入解密后的文件
    if (!write_file_bytes(out_file, decrypted_plaintext, actual_dec_len)) {
        goto cleanup;
    }
    
    printf("\n\033[32m[成功]\033[0m 混合解密完成！\n");
    printf("  - 解密后的文件 -> %s\n", out_file);
    ret = 0;

cleanup:
    free(encrypted_data);
    free(encapsulated_key);
    free(decrypted_plaintext);
    free(sender_cert_pem);
    free_master_key_pair(&recipient_mkp);
    if (decrypted_session_key) {
        secure_free(decrypted_session_key);
    }
    return ret;
}


// --- Main 函数: 参数解析与分发 ---
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // 初始化依赖库
    if (crypto_client_init() != 0) {
        fprintf(stderr, "严重错误: Libsodium 密码学库初始化失败！\n");
        return 1;
    }
    if (pki_init() != 0) {
        fprintf(stderr, "严重错误: OpenSSL PKI 库初始化失败！\n");
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "gen-keypair") == 0) {
        return handle_gen_keypair(argc, argv);
    } else if (strcmp(command, "gen-csr") == 0) {
        return handle_gen_csr(argc, argv);
    } else if (strcmp(command, "verify-cert") == 0) {
        return handle_verify_cert(argc, argv);
    } else if (strcmp(command, "hybrid-encrypt") == 0) {
        return handle_hybrid_encrypt(argc, argv);
    } else if (strcmp(command, "hybrid-decrypt") == 0) {
        return handle_hybrid_decrypt(argc, argv);
    } else if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    else {
        fprintf(stderr, "错误: 未知命令 '%s'\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}