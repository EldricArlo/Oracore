#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <sodium.h>
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
    fprintf(stderr, "高安全性混合加密系统 v4.2 (流式处理版 CLI)\n\n");
    fprintf(stderr, "用法: %s <命令> [参数...]\n\n", prog_name);
    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair <basename>\n");
    fprintf(stderr, "    ↳ 生成 <basename>.pub 和 <basename>.key\n\n");
    fprintf(stderr, "  gen-csr <private-key-file> <username>\n");
    fprintf(stderr, "    ↳ 使用私钥为用户生成 CSR 文件 (输出 <private-key-file>.csr)\n\n");
    fprintf(stderr, "  verify-cert <cert-to-verify> --ca <ca-cert> --user <expected-user>\n");
    fprintf(stderr, "    ↳ 验证一个证书的有效性\n\n");
    fprintf(stderr, "  encrypt <file> --to <recipient-cert> --from <sender-priv-key>\n");
    fprintf(stderr, "    ↳ 加密文件，生成一个支持大文件的 <file>.hsc 文件\n\n");
    fprintf(stderr, "  decrypt <file.hsc> --from <sender-cert> --to <recipient-priv-key>\n");
    fprintf(stderr, "    ↳ 解密 .hsc 文件，恢复原始文件 (输出 <file>.decrypted)\n");
}

// [委员会修改] 为读取密钥、证书等小文件设置一个合理的大小上限（例如1MB），防止DoS攻击。
#define MAX_METADATA_FILE_SIZE (1024 * 1024)

// 从文件读取字节 (用于密钥、证书等小文件)
unsigned char* read_file_bytes(const char* filename, size_t* out_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) { perror("无法打开文件"); return NULL; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) { // 检查 ftell 的错误
        perror("ftell 失败");
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    // [委员会修改] 在分配内存前，强制检查文件大小。
    if (len > MAX_METADATA_FILE_SIZE) {
        fprintf(stderr, "错误: 文件 '%s' 过大 (超过 %dMB)，已拒绝加载。\n", filename, MAX_METADATA_FILE_SIZE / (1024 * 1024));
        fclose(f);
        return NULL;
    }

    if (len == 0) { fclose(f); fprintf(stderr,"错误: 文件为空: %s\n", filename); return NULL; }
    unsigned char* buffer = malloc(len + 1);
    if (!buffer) { fclose(f); fprintf(stderr, "内存分配失败\n"); return NULL; }
    if (fread(buffer, 1, len, f) != (size_t)len) {
        fclose(f); free(buffer); fprintf(stderr, "读取文件失败: %s\n", filename); return NULL;
    }
    buffer[len] = '\0'; // 确保基于文本的文件(如证书)是null结尾的
    *out_len = len;
    fclose(f);
    return buffer;
}

// 将字节写入文件 (用于密钥、证书等小文件)
bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { perror("无法创建文件"); return false; }
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        fprintf(stderr, "写入文件失败: %s\n", filename);
        return false;
    }
    fclose(f);
    return true;
}

/**
 * @brief 安全地从输入路径生成带有新扩展名的输出路径。
 * @param out_buf       (输出) 存放结果的缓冲区。
 * @param out_buf_size  输出缓冲区的大小。
 * @param in_path       输入的原始文件路径。
 * @param new_ext       要附加或替换的新扩展名 (例如, ".csr")。
 * @return 成功返回 true，如果路径过长则返回 false。
 */
bool create_output_path(char* out_buf, size_t out_buf_size, const char* in_path, const char* new_ext) {
    // 步骤 1: 复制基础路径，为扩展名留出空间
    size_t new_ext_len = strlen(new_ext);
    if (new_ext_len >= out_buf_size) return false; // 扩展名本身就太长了

    strncpy(out_buf, in_path, out_buf_size - 1);
    out_buf[out_buf_size - 1] = '\0';

    // 步骤 2: 查找并移除旧的扩展名（如果存在）
    char* dot = strrchr(out_buf, '.');
    // 处理边缘情况，如 ".bashrc" 或 "path/to/.config"
    char* slash = strrchr(out_buf, '/');
    #ifdef _WIN32
    char* backslash = strrchr(out_buf, '\\');
    if (backslash > slash) slash = backslash;
    #endif

    if (dot && (!slash || dot > slash)) {
        *dot = '\0'; // 截断字符串以移除扩展名
    }

    // 步骤 3: 安全地追加新的扩展名
    size_t base_len = strlen(out_buf);
    if (base_len + new_ext_len + 1 > out_buf_size) {
        fprintf(stderr, "错误: 生成的输出文件名过长。\n");
        return false;
    }
    strcat(out_buf, new_ext); // strcat 在这里是安全的，因为我们已经检查了空间

    return true;
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
    
    // snprintf 是安全的，但我们仍然检查截断
    int written_pub = snprintf(pub_path, sizeof(pub_path), "%s.pub", basename);
    int written_priv = snprintf(priv_path, sizeof(priv_path), "%s.key", basename);
    if (written_pub < 0 || (size_t)written_pub >= sizeof(pub_path) ||
        written_priv < 0 || (size_t)written_priv >= sizeof(priv_path)) {
        fprintf(stderr, "错误: 文件名过长，无法生成输出路径。\n");
        return 1;
    }

    master_key_pair mkp;
    mkp.sk = NULL; // 初始化以用于清理
    int ret = 1;

    if (generate_master_key_pair(&mkp) != 0) {
        fprintf(stderr, "错误: 生成主密钥对失败。\n");
        goto cleanup;
    }
    
    if (!write_file_bytes(pub_path, mkp.pk, MASTER_PUBLIC_KEY_BYTES) ||
        !write_file_bytes(priv_path, mkp.sk, MASTER_SECRET_KEY_BYTES)) {
        // [委员会修改] 此处错误已由 write_file_bytes 自身报告，无需重复
        goto cleanup;
    }

    printf("✅ 成功生成密钥对:\n  公钥 -> %s\n  私钥 -> %s\n", pub_path, priv_path);
    ret = 0;

cleanup:
    if (mkp.sk) {
        free_master_key_pair(&mkp);
    }
    return ret;
}

int handle_gen_csr(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "用法: %s gen-csr <私钥文件> \"<用户名>\"\n", argv[0]);
        return 1;
    }
    const char* priv_path = argv[2];
    const char* user_cn = argv[3];
    
    char csr_path[260];
    if (!create_output_path(csr_path, sizeof(csr_path), priv_path, ".csr")) {
        return 1;
    }

    int ret = 1;
    master_key_pair mkp = { .sk = NULL };
    unsigned char* sk_from_file = NULL;
    char* csr_pem = NULL;

    mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!mkp.sk) { fprintf(stderr, "错误: 安全内存分配失败。\n"); goto cleanup; }

    size_t sk_len;
    sk_from_file = read_file_bytes(priv_path, &sk_len);
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        // [委员会修改] 增强错误报告
        fprintf(stderr, "错误: 读取私钥文件 '%s' 失败或密钥长度不正确。\n", priv_path);
        goto cleanup;
    }
    memcpy(mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);

    if (generate_csr(&mkp, user_cn, &csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 CSR 失败。\n");
        goto cleanup;
    }

    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) {
        // [委员会修改] 增强错误报告
        fprintf(stderr, "错误: 写入 CSR 文件到 '%s' 失败。\n", csr_path);
        goto cleanup;
    }

    printf("✅ 成功为用户 '%s' 生成 CSR -> %s\n", user_cn, csr_path);
    ret = 0;

cleanup:
    if (mkp.sk) free_master_key_pair(&mkp);
    if (sk_from_file) {
        secure_zero_memory(sk_from_file, sk_len);
        free(sk_from_file);
    }
    if (csr_pem) free_csr_pem(csr_pem);
    return ret;
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
    
    int ret = 1;
    char* user_cert_pem = NULL;
    char* ca_cert_pem = NULL;

    size_t cert_len, ca_len;
    user_cert_pem = (char*)read_file_bytes(cert_path, &cert_len);
    ca_cert_pem = (char*)read_file_bytes(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) {
        // [委员会修改] 增强错误报告 (read_file_bytes已提供部分信息)
        fprintf(stderr, "错误: 无法加载证书文件进行验证。\n");
        goto cleanup;
    }
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = verify_user_certificate(user_cert_pem, ca_cert_pem, user_cn);

    switch(result) {
        case 0:  
            printf("\033[32m[成功]\033[0m 证书所有验证项均通过。\n"); 
            ret = 0; 
            break;
        case -2: fprintf(stderr, "\033[31m[失败]\033[0m 证书签名链或有效期验证失败。\n"); break;
        case -3: fprintf(stderr, "\033[31m[失败]\033[0m 证书主体 (用户名) 不匹配。\n"); break;
        case -4: fprintf(stderr, "\033[31m[失败]\033[0m 证书吊销状态检查失败 (OCSP)！\n"); break;
        default: fprintf(stderr, "\033[31m[失败]\033[0m 未知的验证错误 (代码: %d)。\n", result); break;
    }

cleanup:
    free(user_cert_pem);
    free(ca_cert_pem);
    return ret;
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
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".hsc")) {
        return 1;
    }
    
    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    master_key_pair sender_mkp = { .sk = NULL };
    char* recipient_cert_pem = NULL;
    unsigned char* encapsulated_key = NULL;
    unsigned char* sk_from_file = NULL;
    size_t sk_len = 0;
    unsigned char session_key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

    randombytes_buf(session_key, sizeof(session_key));

    size_t cert_len;
    recipient_cert_pem = (char*)read_file_bytes(recipient_cert_file, &cert_len);
    // [委员会修改] 增强错误报告
    if (!recipient_cert_pem) {
        fprintf(stderr, "错误: 无法读取接收方证书 '%s'。\n", recipient_cert_file);
        goto cleanup;
    }
    
    unsigned char recipient_pk[MASTER_PUBLIC_KEY_BYTES];
    // [委员会修改] 增强错误报告
    if (extract_public_key_from_cert(recipient_cert_pem, recipient_pk) != 0) {
        fprintf(stderr, "错误: 从接收方证书 '%s' 提取公钥失败。\n", recipient_cert_file);
        goto cleanup;
    }

    sender_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!sender_mkp.sk) { fprintf(stderr, "错误: 安全内存分配失败。\n"); goto cleanup; }
    sk_from_file = read_file_bytes(sender_priv_file, &sk_len);
    // [委员会修改] 增强错误报告
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取发送方私钥 '%s' 失败或密钥长度不正确。\n", sender_priv_file);
        goto cleanup;
    }
    memcpy(sender_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);

    size_t enc_key_buf_len = crypto_box_NONCEBYTES + sizeof(session_key) + crypto_box_MACBYTES;
    encapsulated_key = malloc(enc_key_buf_len);
    if (!encapsulated_key) { fprintf(stderr, "错误: 内存分配失败 (用于封装密钥)。\n"); goto cleanup; }
    size_t actual_encapsulated_len;
    // [委员会修改] 增强错误报告
    if (encapsulate_session_key(encapsulated_key, &actual_encapsulated_len, session_key, sizeof(session_key), recipient_pk, sender_mkp.sk) != 0) {
        fprintf(stderr, "错误: 封装会话密钥失败。请检查密钥和证书是否匹配。\n");
        goto cleanup;
    }

    f_in = fopen(in_file, "rb");
    if (!f_in) { perror("无法打开输入文件"); goto cleanup; }
    f_out = fopen(out_file, "wb");
    if (!f_out) { perror("无法创建输出文件"); goto cleanup; }

    uint64_t key_len_le = htole64(actual_encapsulated_len);
    if (fwrite(&key_len_le, sizeof(uint64_t), 1, f_out) != 1) { fprintf(stderr, "错误: 写入包头失败。\n"); goto cleanup; }
    if (fwrite(encapsulated_key, 1, actual_encapsulated_len, f_out) != actual_encapsulated_len) { fprintf(stderr, "错误: 写入封装密钥失败。\n"); goto cleanup; }
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_push(&st, stream_header, session_key);
    
    if (fwrite(stream_header, 1, sizeof(stream_header), f_out) != sizeof(stream_header)) { fprintf(stderr, "错误: 写入流加密头部失败。\n"); goto cleanup; }

    #define CHUNK_SIZE 4096
    unsigned char buf_in[CHUNK_SIZE];
    unsigned char buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    size_t bytes_read;
    unsigned long long out_len;
    unsigned char tag;

    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) { fprintf(stderr, "读取输入文件时出错。\n"); goto cleanup; }
        tag = feof(f_in) ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        
        if (crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, bytes_read, NULL, 0, tag) != 0) {
            fprintf(stderr, "错误: 加密文件块失败。\n"); goto cleanup;
        }
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
            fprintf(stderr, "错误: 写入加密文件块失败。\n"); goto cleanup;
        }
    } while (!feof(f_in));

    printf("✅ 混合加密完成！\n  输出文件 -> %s\n", out_file);
    ret = 0;

cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    free(encapsulated_key);
    free(recipient_cert_pem);
    if (sender_mkp.sk) free_master_key_pair(&sender_mkp);
    if (sk_from_file) {
        secure_zero_memory(sk_from_file, sk_len);
        free(sk_from_file);
    }
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
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".decrypted")) {
        return 1;
    }
    
    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    char* sender_cert_pem = NULL;
    master_key_pair recipient_mkp = { .sk = NULL };
    unsigned char* sk_from_file = NULL;
    size_t sk_len = 0;
    unsigned char* enc_key = NULL;
    unsigned char* dec_session_key = NULL;

    f_in = fopen(in_file, "rb");
    if (!f_in) { perror("无法打开加密文件"); goto cleanup; }

    uint64_t key_len_le;
    if (fread(&key_len_le, sizeof(uint64_t), 1, f_in) != 1) { fprintf(stderr, "错误: 读取包头失败。文件可能已损坏或格式不正确。\n"); goto cleanup; }
    size_t enc_key_len = le64toh(key_len_le);
    
    if (enc_key_len == 0 || enc_key_len > 1024 * 1024) { // 合理性检查
        fprintf(stderr, "错误: 无效的封装密钥长度。文件可能已损坏。\n"); goto cleanup;
    }

    enc_key = malloc(enc_key_len);
    if (!enc_key) { fprintf(stderr, "错误: 内存分配失败 (用于封装密钥)。\n"); goto cleanup; }
    if (fread(enc_key, 1, enc_key_len, f_in) != enc_key_len) { fprintf(stderr, "错误: 读取封装密钥失败。文件不完整。\n"); goto cleanup; }
    
    size_t cert_len;
    sender_cert_pem = (char*)read_file_bytes(sender_cert_file, &cert_len);
    // [委员会修改] 增强错误报告
    if (!sender_cert_pem) {
        fprintf(stderr, "错误: 无法读取发送方证书 '%s'。\n", sender_cert_file);
        goto cleanup;
    }
    unsigned char sender_pk[MASTER_PUBLIC_KEY_BYTES];
    // [委员会修改] 增强错误报告
    if (extract_public_key_from_cert(sender_cert_pem, sender_pk) != 0) {
        fprintf(stderr, "错误: 从发送方证书 '%s' 提取公钥失败。\n", sender_cert_file);
        goto cleanup;
    }
    
    recipient_mkp.sk = secure_alloc(MASTER_SECRET_KEY_BYTES);
    if (!recipient_mkp.sk) { fprintf(stderr, "错误: 安全内存分配失败。\n"); goto cleanup; }
    sk_from_file = read_file_bytes(recipient_priv_file, &sk_len);
    // [委员会修改] 增强错误报告
    if (!sk_from_file || sk_len != MASTER_SECRET_KEY_BYTES) {
        fprintf(stderr, "错误: 读取接收方私钥 '%s' 失败或密钥长度不正确。\n", recipient_priv_file);
        goto cleanup;
    }
    memcpy(recipient_mkp.sk, sk_from_file, MASTER_SECRET_KEY_BYTES);

    dec_session_key = secure_alloc(crypto_secretstream_xchacha20poly1305_KEYBYTES);
    if (!dec_session_key) { fprintf(stderr, "错误: 安全内存分配失败 (用于会话密钥)。\n"); goto cleanup; }
    if (decapsulate_session_key(dec_session_key, enc_key, enc_key_len, sender_pk, recipient_mkp.sk) != 0) {
        fprintf(stderr, "错误: 解封装会话密钥失败！这通常意味着您提供了错误的私钥、错误的发送方证书，或者文件已被篡改。\n"); goto cleanup;
    }

    f_out = fopen(out_file, "wb");
    if (!f_out) { perror("无法创建解密文件"); goto cleanup; }
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (fread(stream_header, 1, sizeof(stream_header), f_in) != sizeof(stream_header)) {
        fprintf(stderr, "错误: 读取流加密头部失败。文件不完整或已损坏。\n"); goto cleanup;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, dec_session_key) != 0) {
        fprintf(stderr, "错误: 无效的流加密头部。文件可能已被篡改。\n"); goto cleanup;
    }
    
    #define DECRYPT_CHUNK_SIZE (4096 + crypto_secretstream_xchacha20poly1305_ABYTES)
    unsigned char buf_in[DECRYPT_CHUNK_SIZE];
    unsigned char buf_out[4096];
    size_t bytes_read;
    unsigned long long out_len;
    unsigned char tag;
    bool stream_finished = false;

    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) { fprintf(stderr, "读取加密文件时出错。\n"); goto cleanup; }

        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, bytes_read, NULL, 0) != 0) {
            fprintf(stderr, "错误: 解密文件块失败！数据可能被篡改。\n"); goto cleanup;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            stream_finished = true;
        }
        
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
             fprintf(stderr, "错误: 写入解密文件块失败。\n"); goto cleanup;
        }
    } while (!feof(f_in));

    if (!stream_finished) {
        fprintf(stderr, "警告: 加密流未正常结束，解密后的文件可能不完整。\n");
    }

    printf("✅ 混合解密完成！\n  解密文件 -> %s\n", out_file);
    ret = 0;

cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    free(enc_key);
    free(sender_cert_pem);
    if (recipient_mkp.sk) free_master_key_pair(&recipient_mkp);
    if (sk_from_file) {
        secure_zero_memory(sk_from_file, sk_len);
        free(sk_from_file);
    }
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