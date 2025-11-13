// --- cli.c (REFACTORED) ---
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

// 引入 getopt_long 以增强参数解析
#include <getopt.h>
// 在某些环境中（如 MinGW），optind 需要手动声明
#if defined(__MINGW32__) || defined(__MINGW64__)
extern int optind;
#endif

// 重新包含 sodium.h 以解决 'sodium_memzero' 隐式声明错误
#include <sodium.h> 

#include "hsc_kernel.h"

// --- [移除] 字节序处理辅助函数 store64_le / load64_le 已移至 hsc_kernel.c ---

// --- 辅助函数 ---
void print_usage(const char* prog_name) {
    fprintf(stderr, "高安全性混合加密系统 v4.2 (流式处理版 CLI)\n\n");
    fprintf(stderr, "用法: %s <命令> [参数...]\n\n", prog_name);
    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair <basename>\n");
    fprintf(stderr, "  gen-csr <private-key-file> <username>\n");
    fprintf(stderr, "  verify-cert <cert-to-verify> --ca <ca-cert> --user <expected-user>\n");
    fprintf(stderr, "  encrypt <file> --to <recipient-cert.pem> --from <sender.key>\n");
    fprintf(stderr, "      (原始密钥模式) --recipient-pk-file <recipient.pub> --from <sender.key>\n");
    fprintf(stderr, "  decrypt <file.hsc> --to <recipient.key> --from <sender-cert.pem>\n");
    fprintf(stderr, "      (原始密钥模式) --to <recipient.key> --sender-pk-file <sender.pub>\n");
}

// [修改] read_variable_size_file 仅用于读取密钥和证书等小文件
unsigned char* read_small_file(const char* filename, size_t* out_len) {
    FILE* f;
    bool is_stdin = (strcmp(filename, "-") == 0);

    if (is_stdin) {
        f = stdin;
    } else {
        f = fopen(filename, "rb");
        if (!f) {
            perror("无法打开文件");
            return NULL;
        }
    }
    
    // 对于小文件，我们先获取大小
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0 || file_size > 1024 * 1024) { // 设置1MB的上限
        fprintf(stderr, "错误: 文件过大或无法读取大小: %s\n", filename);
        if(!is_stdin) fclose(f);
        return NULL;
    }

    unsigned char* buffer = malloc(file_size + 1);
    if (!buffer) {
        fprintf(stderr, "错误: 内存分配失败\n");
        if(!is_stdin) fclose(f);
        return NULL;
    }

    size_t bytes_read = fread(buffer, 1, file_size, f);
    if (bytes_read != (size_t)file_size) {
        fprintf(stderr, "错误: 读取文件失败: %s\n", filename);
        free(buffer);
        if(!is_stdin) fclose(f);
        return NULL;
    }
    
    if (!is_stdin) {
        fclose(f);
    }

    buffer[bytes_read] = '\0';
    *out_len = bytes_read;
    return buffer;
}

bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { 
        fprintf(stderr, "错误: 无法打开文件 '%s' 进行写入: %s\n", filename, strerror(errno));
        return false; 
    }
    bool ok = (fwrite(data, 1, len, f) == len);
    if (!ok) {
        fprintf(stderr, "错误: 写入文件 '%s' 时失败。可能磁盘已满或权限不足。\n", filename);
    }
    fclose(f); 
    return ok;
}

bool create_output_path(char* out_buf, size_t out_buf_size, const char* in_path, const char* new_ext) {
    const char* dot = strrchr(in_path, '.');
    const char* slash = strrchr(in_path, '/');
    #ifdef _WIN32
    const char* backslash = strrchr(in_path, '\\');
    if (backslash > slash) slash = backslash;
    #endif
    size_t base_len = (dot && (!slash || dot > slash)) ? (size_t)(dot - in_path) : strlen(in_path);
    int written = snprintf(out_buf, out_buf_size, "%.*s%s", (int)base_len, in_path, new_ext);
    
    return !(written < 0 || (size_t)written >= out_buf_size);
}

// --- 命令处理函数 ---

int handle_gen_keypair(int argc, char* argv[]) {
    if (argc != 3) { print_usage(argv[0]); return 1; }
    const char* basename = argv[2];
    char pub_path[FILENAME_MAX], priv_path[FILENAME_MAX];
    
    snprintf(pub_path, sizeof(pub_path), "%s.pub", basename);
    snprintf(priv_path, sizeof(priv_path), "%s.key", basename);
    
    int ret = 1;
    hsc_master_key_pair* kp = hsc_generate_master_key_pair();
    if (kp) {
        if (hsc_save_master_key_pair(kp, pub_path, priv_path) == HSC_OK) { // [修改]
            printf("✅ 成功生成密钥对:\n  公钥 -> %s\n  私钥 -> %s\n", pub_path, priv_path);
            ret = 0;
        } else {
            fprintf(stderr, "错误: 保存密钥对到文件失败。请检查目录权限和磁盘空间。\n");
        }
    } else {
        fprintf(stderr, "错误: 生成密钥对时发生内部错误。\n");
    }
    hsc_free_master_key_pair(&kp);
    return ret;
}

int handle_gen_csr(int argc, char* argv[]) {
    if (argc != 4) { print_usage(argv[0]); return 1; }
    const char* priv_path = argv[2]; const char* user_cn = argv[3];
    char csr_path[FILENAME_MAX];
    
    if (!create_output_path(csr_path, sizeof(csr_path), priv_path, ".csr")) {
        fprintf(stderr, "错误: 生成的 CSR 文件名过长。\n");
        return 1;
    }
    
    int ret = 1;
    hsc_master_key_pair* kp = NULL; char* csr_pem = NULL;
    kp = hsc_load_master_key_pair_from_private_key(priv_path);
    if (!kp) {
        fprintf(stderr, "错误: 无法从 '%s' 加载私钥。\n", priv_path);
        goto cleanup;
    }
    if (hsc_generate_csr(kp, user_cn, &csr_pem) != HSC_OK) { // [修改]
        fprintf(stderr, "错误: 生成 CSR 失败。\n");
        goto cleanup;
    }
    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) {
        goto cleanup;
    }
    printf("✅ 成功为用户 '%s' 生成 CSR -> %s\n", user_cn, csr_path);
    ret = 0;
cleanup:
    hsc_free_master_key_pair(&kp); hsc_free_pem_string(csr_pem);
    return ret;
}

int handle_verify_cert(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }

    const char* cert_path = argv[2];
    const char* ca_path = NULL;
    const char* user_cn = NULL;

    static struct option long_options[] = {
        {"ca",   required_argument, 0, 'c'},
        {"user", required_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 3;
    while ((opt = getopt_long(argc, argv, "c:u:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': ca_path = optarg; break;
            case 'u': user_cn = optarg; break;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!cert_path || !ca_path || !user_cn) { print_usage(argv[0]); return 1; }

    int ret = 1;
    unsigned char* user_cert_pem = NULL, *ca_cert_pem = NULL; size_t cert_len, ca_len;
    user_cert_pem = read_small_file(cert_path, &cert_len);
    ca_cert_pem = read_small_file(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) { goto cleanup; }
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = hsc_verify_user_certificate((const char*)user_cert_pem, (const char*)ca_cert_pem, user_cn);
    
    // [修改] 实现精细化的错误报告
    switch(result) {
        case HSC_OK:  
            printf("\033[32m[成功]\033[0m 证书所有验证项均通过。\n"); 
            ret = 0; 
            break;
        case HSC_ERROR_CERT_CHAIN_OR_VALIDITY: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书签名链或有效期验证失败。\n"); 
            break;
        case HSC_ERROR_CERT_SUBJECT_MISMATCH: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书主体(CN)与预期用户不匹配。\n"); 
            break;
        case HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书吊销状态检查失败 (OCSP)！\n"); 
            break;
        case HSC_ERROR_INVALID_FORMAT:
            fprintf(stderr, "\033[31m[失败]\033[0m 无法解析证书文件，请检查是否为有效的PEM格式。\n"); 
            break;
        default: 
            fprintf(stderr, "\033[31m[失败]\033[0m 发生未知验证错误 (代码: %d)。\n", result); 
            break;
    }
cleanup:
    free(user_cert_pem); free(ca_cert_pem); return ret;
}


// --- [移除] 加解密流式处理辅助函数已移至 hsc_kernel.c ---


// --- [重构] 加密与解密主函数 ---

int handle_hybrid_encrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }

    const char* in_file = argv[2];
    const char* recipient_cert_file = NULL;
    const char* recipient_pk_file = NULL;
    const char* sender_priv_file = NULL;

    static struct option long_options[] = {
        {"to",                required_argument, 0, 't'},
        {"from",              required_argument, 0, 'f'},
        {"recipient-pk-file", required_argument, 0, 'r'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 3;
    while ((opt = getopt_long(argc, argv, "t:f:r:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': recipient_cert_file = optarg; break;
            case 'f': sender_priv_file = optarg; break;
            case 'r': recipient_pk_file = optarg; break;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (!in_file || !sender_priv_file || (!recipient_cert_file && !recipient_pk_file)) {
        print_usage(argv[0]); return 1;
    }
    if (recipient_cert_file && recipient_pk_file) {
        fprintf(stderr, "错误: --to 和 --recipient-pk-file 选项是互斥的。\n");
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".hsc")) {
        fprintf(stderr, "错误: 生成的输出文件名过长。\n"); return 1;
    }
    
    int ret = 1;
    hsc_master_key_pair* sender_kp = NULL;
    unsigned char* recipient_cert_pem = NULL;
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    
    // 步骤 1: 确定接收者的公钥 (无论是从证书还是原始文件)
    if (recipient_pk_file) {
        // --- 原始密钥模式 ---
        fprintf(stdout, "\n\033[33m[警告] 您正在使用原始公钥模式进行加密。\n       系统不会验证接收者身份，请确保您信任此公钥的来源。\033[0m\n\n");
        size_t pk_len;
        unsigned char* pk_buf = read_small_file(recipient_pk_file, &pk_len);
        if (!pk_buf || pk_len != HSC_MASTER_PUBLIC_KEY_BYTES) {
            fprintf(stderr, "错误: 读取或验证接收者公钥文件 '%s' 失败。\n", recipient_pk_file);
            free(pk_buf);
            goto cleanup;
        }
        memcpy(recipient_pk, pk_buf, HSC_MASTER_PUBLIC_KEY_BYTES);
        free(pk_buf);
    } else {
        // --- 证书模式 ---
        size_t cert_len;
        recipient_cert_pem = read_small_file(recipient_cert_file, &cert_len);
        if (!recipient_cert_pem) { goto cleanup; }
        
        // 注意：在实际应用中，这里应该调用 hsc_verify_user_certificate
        // 但为了工具的灵活性，我们仅提取公钥。验证步骤由用户通过 verify-cert 命令独立完成。
        if (hsc_extract_public_key_from_cert((const char*)recipient_cert_pem, recipient_pk) != HSC_OK) {
            fprintf(stderr, "错误: 无法从接收者证书 '%s' 中提取公钥。\n", recipient_cert_file);
            goto cleanup;
        }
    }
    
    // 步骤 2: 加载发送者私钥
    sender_kp = hsc_load_master_key_pair_from_private_key(sender_priv_file);
    if (!sender_kp) {
        fprintf(stderr, "错误: 无法从 '%s' 加载发送者私钥。\n", sender_priv_file);
        goto cleanup;
    }
    
    // 步骤 3: 调用高级内核API执行完整的混合加密流程
    printf("正在加密 %s -> %s ...\n", in_file, out_file);
    int result = hsc_hybrid_encrypt_stream_raw(out_file, in_file, recipient_pk, sender_kp);

    if (result == HSC_OK) {
        printf("✅ 混合加密完成！\n");
        ret = 0;
    } else {
        fprintf(stderr, "错误: 加密过程中发生错误 (代码: %d)。\n", result);
    }

cleanup:
    free(recipient_cert_pem);
    hsc_free_master_key_pair(&sender_kp);
    return ret;
}


int handle_hybrid_decrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }
    
    const char* in_file = argv[2];
    const char* sender_cert_file = NULL;
    const char* sender_pk_file = NULL;
    const char* recipient_priv_file = NULL;

    static struct option long_options[] = {
        {"to",             required_argument, 0, 't'},
        {"from",           required_argument, 0, 'f'},
        {"sender-pk-file", required_argument, 0, 's'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 3;
    while ((opt = getopt_long(argc, argv, "t:f:s:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': recipient_priv_file = optarg; break;
            case 'f': sender_cert_file = optarg; break;
            case 's': sender_pk_file = optarg; break;
            default: print_usage(argv[0]); return 1;
        }
    }
    
    if (!in_file || !recipient_priv_file || (!sender_cert_file && !sender_pk_file)) {
        print_usage(argv[0]); return 1;
    }
    if (sender_cert_file && sender_pk_file) {
        fprintf(stderr, "错误: --from 和 --sender-pk-file 选项是互斥的。\n");
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".decrypted")) {
        fprintf(stderr, "错误: 生成的输出文件名过长。\n"); return 1;
    }

    int ret = 1;
    unsigned char* sender_cert_pem = NULL;
    hsc_master_key_pair* recipient_kp = NULL;
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];

    // 步骤 1: 确定发送者的公钥
    if (sender_pk_file) {
        // --- 原始密钥模式 ---
        fprintf(stdout, "\n\033[33m[警告] 您正在使用原始公钥模式进行解密。\n       系统不会验证发送者身份，请确保您信任此公钥的来源。\033[0m\n\n");
        size_t pk_len;
        unsigned char* pk_buf = read_small_file(sender_pk_file, &pk_len);
        if (!pk_buf || pk_len != HSC_MASTER_PUBLIC_KEY_BYTES) {
            fprintf(stderr, "错误: 读取或验证发送者公钥文件 '%s' 失败。\n", sender_pk_file);
            free(pk_buf);
            goto cleanup;
        }
        memcpy(sender_pk, pk_buf, HSC_MASTER_PUBLIC_KEY_BYTES);
        free(pk_buf);
    } else {
        // --- 证书模式 ---
        size_t cert_len;
        sender_cert_pem = read_small_file(sender_cert_file, &cert_len);
        if (!sender_cert_pem) goto cleanup;

        if (hsc_extract_public_key_from_cert((const char*)sender_cert_pem, sender_pk) != HSC_OK) {
            fprintf(stderr, "错误: 无法从发送者证书 '%s' 中提取公钥。\n", sender_cert_file);
            goto cleanup;
        }
    }

    // 步骤 2: 加载接收者私钥
    recipient_kp = hsc_load_master_key_pair_from_private_key(recipient_priv_file);
    if (!recipient_kp) {
        fprintf(stderr, "错误: 无法从 '%s' 加载接收者私钥。\n", recipient_priv_file);
        goto cleanup;
    }
    
    // 步骤 3: 调用高级内核API执行完整的混合解密流程
    printf("正在解密 %s -> %s ...\n", in_file, out_file);
    int result = hsc_hybrid_decrypt_stream_raw(out_file, in_file, sender_pk, recipient_kp);

    if (result == HSC_OK) {
        printf("✅ 混合解密完成！\n");
        ret = 0;
    } else if (result == HSC_ERROR_CRYPTO_OPERATION) {
        fprintf(stderr, "错误: 解密失败！数据可能被篡改，或密钥不匹配。\n");
    } else if (result == HSC_ERROR_INVALID_FORMAT) {
         fprintf(stderr, "错误: 解密失败！文件格式无效或已损坏。\n");
    } else {
        fprintf(stderr, "错误: 解密过程中发生未知错误 (代码: %d)。\n", result);
    }

cleanup:
    free(sender_cert_pem);
    hsc_free_master_key_pair(&recipient_kp);
    if (ret != 0) remove(out_file);
    return ret;
}

// --- Main 函数 ---
int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (hsc_init() != HSC_OK) { // [修改]
        fprintf(stderr, "严重错误: 高安全内核库初始化失败！\n"); return 1;
    }
    const char* command = argv[1];
    int ret = 1;
    if (strcmp(command, "gen-keypair") == 0) {
        ret = handle_gen_keypair(argc, argv);
    } else if (strcmp(command, "gen-csr") == 0) {
        ret = handle_gen_csr(argc, argv);
    } else if (strcmp(command, "encrypt") == 0) {
        ret = handle_hybrid_encrypt(argc, argv);
    } else if (strcmp(command, "decrypt") == 0) {
        ret = handle_hybrid_decrypt(argc, argv);
    } else if (strcmp(command, "verify-cert") == 0) {
        ret = handle_verify_cert(argc, argv);
    } else {
        fprintf(stderr, "错误: 未知命令 '%s'\n", command);
        print_usage(argv[0]);
    }
    hsc_cleanup();
    return ret;
}