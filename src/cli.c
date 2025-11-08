// [COMMITTEE REFACTOR] 移除所有内部头文件，仅包含公共 API 和标准/第三方库头文件。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

// 包含 libsodium 头文件以访问通用辅助函数 (如 sodium_memzero) 和常量。
// 这是一个合理的依赖，因为加密库的核心功能依赖它。
#include <sodium.h> 

// [COMMITTEE REFACTOR] 核心变更：只包含项目的公共 API 头文件。
#include "hsc_kernel.h"

// --- [COMMITTEE REFACTOR] 可移植的字节序处理辅助函数 ---
// 替换平台相关的 htole64/le64toh，确保文件格式在所有架构上兼容。

/**
 * @brief 将一个64位无符号整数以小端序（Little-Endian）写入缓冲区。
 * @param dst 指向8字节目标缓冲区的指针。
 * @param w   要写入的64位整数。
 */
static void store64_le(unsigned char* dst, uint64_t w) {
    dst[0] = (unsigned char)w; w >>= 8;
    dst[1] = (unsigned char)w; w >>= 8;
    dst[2] = (unsigned char)w; w >>= 8;
    dst[3] = (unsigned char)w; w >>= 8;
    dst[4] = (unsigned char)w; w >>= 8;
    dst[5] = (unsigned char)w; w >>= 8;
    dst[6] = (unsigned char)w; w >>= 8;
    dst[7] = (unsigned char)w;
}

/**
 * @brief 从一个使用小端序编码的缓冲区中读取一个64位无符号整数。
 * @param src 指向8字节源缓冲区的指针。
 * @return    读取并重构的64位整数。
 */
static uint64_t load64_le(const unsigned char* src) {
    uint64_t w = src[7];
    w = (w << 8) | src[6];
    w = (w << 8) | src[5];
    w = (w << 8) | src[4];
    w = (w << 8) | src[3];
    w = (w << 8) | src[2];
    w = (w << 8) | src[1];
    w = (w << 8) | src[0];
    return w;
}


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

#define MAX_METADATA_FILE_SIZE (1024 * 1024)

// 安全地读取文件内容，返回一个由 malloc 分配的缓冲区。
// 注意：此函数用于读取非敏感数据，如证书。
unsigned char* read_variable_size_file(const char* filename, size_t* out_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) { perror("无法打开文件"); return NULL; }
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len < 0) {
        perror("ftell 失败");
        fclose(f);
        return NULL;
    }
    fseek(f, 0, SEEK_SET);

    if (len > MAX_METADATA_FILE_SIZE) {
        fprintf(stderr, "错误: 文件 '%s' 过大 (超过 %dMB)，已拒绝加载。\n", filename, MAX_METADATA_FILE_SIZE / (1024 * 1024));
        fclose(f);
        return NULL;
    }

    if (len == 0) { fclose(f); fprintf(stderr,"错误: 文件为空: %s\n", filename); return NULL; }
    
    unsigned char* buffer = malloc(len + 1);
    if (!buffer) { fclose(f); fprintf(stderr, "内存分配失败\n"); return NULL; }
    
    if (fread(buffer, 1, len, f) != (size_t)len) {
        if (ferror(f)) {
            perror("读取文件时出错");
        } else {
            fprintf(stderr, "读取文件失败 (未达到预期长度): %s\n", filename);
        }
        fclose(f); 
        free(buffer); 
        return NULL;
    }
    
    buffer[len] = '\0';
    *out_len = len;
    fclose(f);
    return buffer;
}


// 将字节写入文件
bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { perror("无法创建文件"); return false; }
    
    if (fwrite(data, 1, len, f) != len) {
        if (ferror(f)) {
            perror("写入文件时出错");
        } else {
            fprintf(stderr, "写入文件失败: %s\n", filename);
        }
        fclose(f);
        return false;
    }
    
    fclose(f);
    return true;
}


// [COMMITTEE REFACTOR] 保留经过审查的、更安全的路径构建函数。
bool create_output_path(char* out_buf, size_t out_buf_size, const char* in_path, const char* new_ext) {
    const char* dot = strrchr(in_path, '.');
    const char* slash = strrchr(in_path, '/');
    #ifdef _WIN32
    const char* backslash = strrchr(in_path, '\\');
    if (backslash > slash) slash = backslash;
    #endif

    size_t base_len;
    if (dot && (!slash || dot > slash)) {
        base_len = (size_t)(dot - in_path);
    } else {
        base_len = strlen(in_path);
    }

    int written = snprintf(out_buf, out_buf_size, "%.*s%s", (int)base_len, in_path, new_ext);

    if (written < 0 || (size_t)written >= out_buf_size) {
        fprintf(stderr, "错误: 生成的输出文件名过长或发生编码错误。\n");
        if (out_buf_size > 0) {
            out_buf[0] = '\0';
        }
        return false;
    }

    return true;
}


// --- 命令处理函数 ---

int handle_gen_keypair(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "用法: %s gen-keypair <文件名基础>\n", argv[0]);
        return 1;
    }
    const char* basename = argv[2];
    char pub_path[FILENAME_MAX];
    char priv_path[FILENAME_MAX];
    
    int written_pub = snprintf(pub_path, sizeof(pub_path), "%s.pub", basename);
    int written_priv = snprintf(priv_path, sizeof(priv_path), "%s.key", basename);

    if (written_pub < 0 || (size_t)written_pub >= sizeof(pub_path) ||
        written_priv < 0 || (size_t)written_priv >= sizeof(priv_path)) {
        fprintf(stderr, "错误: 文件名过长，无法生成输出路径。\n");
        return 1;
    }

    // [COMMITTEE REFACTOR] 使用公共 API 管理密钥对生命周期。
    hsc_master_key_pair* kp = NULL;
    int ret = 1;

    kp = hsc_generate_master_key_pair();
    if (kp == NULL) {
        fprintf(stderr, "错误: 生成主密钥对失败。\n");
        goto cleanup;
    }
    
    if (hsc_save_master_key_pair(kp, pub_path, priv_path) != 0) {
        fprintf(stderr, "错误: 保存密钥对到文件失败。\n");
        goto cleanup;
    }

    printf("✅ 成功生成密钥对:\n  公钥 -> %s\n  私钥 -> %s\n", pub_path, priv_path);
    ret = 0;

cleanup:
    hsc_free_master_key_pair(&kp);
    return ret;
}

int handle_gen_csr(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "用法: %s gen-csr <私钥文件> \"<用户名>\"\n", argv[0]);
        return 1;
    }
    const char* priv_path = argv[2];
    const char* user_cn = argv[3];
    
    char csr_path[FILENAME_MAX];
    if (!create_output_path(csr_path, sizeof(csr_path), priv_path, ".csr")) {
        return 1;
    }

    int ret = 1;
    // [COMMITTEE REFACTOR] 使用公共 API 加载密钥并生成 CSR。
    hsc_master_key_pair* kp = NULL;
    char* csr_pem = NULL;

    kp = hsc_load_master_key_pair_from_private_key(priv_path);
    if (kp == NULL) {
        fprintf(stderr, "错误: 从文件 '%s' 加载私钥失败。\n", priv_path);
        goto cleanup;
    }
    
    if (hsc_generate_csr(kp, user_cn, &csr_pem) != 0) {
        fprintf(stderr, "错误: 生成 CSR 失败。\n");
        goto cleanup;
    }

    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) {
        goto cleanup;
    }

    printf("✅ 成功为用户 '%s' 生成 CSR -> %s\n", user_cn, csr_path);
    ret = 0;

cleanup:
    hsc_free_master_key_pair(&kp);
    hsc_free_pem_string(csr_pem); // 使用公共 API 释放
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
    unsigned char* user_cert_pem = NULL; // [COMMITTEE REFACTOR] PEM 内容使用 unsigned char 更通用
    unsigned char* ca_cert_pem = NULL;
    size_t cert_len, ca_len;

    user_cert_pem = read_variable_size_file(cert_path, &cert_len);
    ca_cert_pem = read_variable_size_file(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) {
        fprintf(stderr, "错误: 无法加载一个或多个证书文件进行验证。\n");
        goto cleanup;
    }
    
    printf("开始验证证书 %s ...\n", cert_path);
    // [COMMITTEE REFACTOR] 调用公共 API
    int result = hsc_verify_user_certificate((const char*)user_cert_pem, (const char*)ca_cert_pem, user_cn);

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

// [COMMITTEE REFACTOR] 为封装密钥的输出缓冲区大小定义一个常量。
// 理想情况下，这个值应由 hsc_kernel.h 提供。
// 计算来源: crypto_box_NONCEBYTES(24) + HSC_SESSION_KEY_BYTES(32) + crypto_box_MACBYTES(16) = 72
#define ENCAPSULATED_KEY_BUFFER_SIZE 72

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

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".hsc")) {
        return 1;
    }
    
    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    hsc_master_key_pair* sender_kp = NULL; // [COMMITTEE REFACTOR]
    unsigned char* recipient_cert_pem = NULL;
    unsigned char session_key[HSC_SESSION_KEY_BYTES]; // [COMMITTEE REFACTOR] 使用公共 API 常量

    randombytes_buf(session_key, sizeof(session_key));

    size_t cert_len;
    recipient_cert_pem = read_variable_size_file(recipient_cert_file, &cert_len);
    if (!recipient_cert_pem) {
        fprintf(stderr, "错误: 无法读取接收方证书 '%s'。\n", recipient_cert_file);
        goto cleanup;
    }
    
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES]; // [COMMITTEE REFACTOR]
    if (hsc_extract_public_key_from_cert((const char*)recipient_cert_pem, recipient_pk) != 0) {
        fprintf(stderr, "错误: 从接收方证书 '%s' 提取公钥失败。\n", recipient_cert_file);
        goto cleanup;
    }

    sender_kp = hsc_load_master_key_pair_from_private_key(sender_priv_file); // [COMMITTEE REFACTOR]
    if (!sender_kp) { 
        fprintf(stderr, "错误: 从文件 '%s' 加载发送方私钥失败。\n", sender_priv_file);
        goto cleanup;
    }

    unsigned char encapsulated_key[ENCAPSULATED_KEY_BUFFER_SIZE]; // [COMMITTEE REFACTOR]
    size_t actual_encapsulated_len;
    if (hsc_encapsulate_session_key(encapsulated_key, &actual_encapsulated_len, session_key, sizeof(session_key), recipient_pk, sender_kp) != 0) {
        fprintf(stderr, "错误: 封装会话密钥失败。请检查密钥和证书是否匹配。\n");
        goto cleanup;
    }

    f_in = fopen(in_file, "rb");
    if (!f_in) { perror("无法打开输入文件"); goto cleanup; }
    f_out = fopen(out_file, "wb");
    if (!f_out) { perror("无法创建输出文件"); goto cleanup; }

    // [COMMITTEE REFACTOR] 使用可移植的字节序函数
    unsigned char key_len_buf[8];
    store64_le(key_len_buf, actual_encapsulated_len);
    if (fwrite(key_len_buf, 1, sizeof(key_len_buf), f_out) != sizeof(key_len_buf)) {
        fprintf(stderr, "错误: 写入包头失败。\n");
        goto cleanup;
    }
    if (fwrite(encapsulated_key, 1, actual_encapsulated_len, f_out) != actual_encapsulated_len) {
        fprintf(stderr, "错误: 写入封装密钥失败。\n");
        goto cleanup;
    }
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    crypto_secretstream_xchacha20poly1305_init_push(&st, stream_header, session_key);
    
    if (fwrite(stream_header, 1, sizeof(stream_header), f_out) != sizeof(stream_header)) {
        fprintf(stderr, "错误: 写入流加密头部失败。\n");
        goto cleanup;
    }

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
    free(recipient_cert_pem);
    hsc_free_master_key_pair(&sender_kp); // [COMMITTEE REFACTOR]
    sodium_memzero(session_key, sizeof(session_key)); // 擦除栈上的会话密钥
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

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".decrypted")) {
        return 1;
    }
    
    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    unsigned char* sender_cert_pem = NULL;
    hsc_master_key_pair* recipient_kp = NULL; // [COMMITTEE REFACTOR]
    unsigned char* enc_key = NULL;
    // [COMMITTEE REFACTOR] 会话密钥是敏感数据，但公共 API 未提供安全内存分配器。
    // 作为 CLI 的短期操作，将其分配在栈上并在使用后立即擦除，是一个可接受的折衷。
    unsigned char dec_session_key[HSC_SESSION_KEY_BYTES];

    f_in = fopen(in_file, "rb");
    if (!f_in) { perror("无法打开加密文件"); goto cleanup; }

    // [COMMITTEE REFACTOR] 使用可移植的字节序函数
    unsigned char key_len_buf[8];
    if (fread(key_len_buf, 1, sizeof(key_len_buf), f_in) != sizeof(key_len_buf)) {
        fprintf(stderr, "错误: 读取包头失败。文件可能已损坏或格式不正确。\n");
        goto cleanup;
    }
    size_t enc_key_len = load64_le(key_len_buf);
    
    if (enc_key_len == 0 || enc_key_len > 1024) { // 合理性检查
        fprintf(stderr, "错误: 无效的封装密钥长度 (%zu)。文件可能已损坏。\n", enc_key_len);
        goto cleanup;
    }

    enc_key = malloc(enc_key_len);
    if (!enc_key) { fprintf(stderr, "错误: 内存分配失败 (用于封装密钥)。\n"); goto cleanup; }
    if (fread(enc_key, 1, enc_key_len, f_in) != enc_key_len) {
        fprintf(stderr, "错误: 读取封装密钥失败。文件不完整。\n");
        goto cleanup;
    }
    
    size_t cert_len;
    sender_cert_pem = read_variable_size_file(sender_cert_file, &cert_len);
    if (!sender_cert_pem) {
        goto cleanup;
    }
    
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES]; // [COMMITTEE REFACTOR]
    if (hsc_extract_public_key_from_cert((const char*)sender_cert_pem, sender_pk) != 0) {
        fprintf(stderr, "错误: 从发送方证书 '%s' 提取公钥失败。\n", sender_cert_file);
        goto cleanup;
    }
    
    recipient_kp = hsc_load_master_key_pair_from_private_key(recipient_priv_file); // [COMMITTEE REFACTOR]
    if (!recipient_kp) {
        fprintf(stderr, "错误: 从文件 '%s' 加载接收方私钥失败。\n", recipient_priv_file);
        goto cleanup;
    }
    
    if (hsc_decapsulate_session_key(dec_session_key, enc_key, enc_key_len, sender_pk, recipient_kp) != 0) {
        fprintf(stderr, "错误: 解封装会话密钥失败！这通常意味着您提供了错误的私钥、错误的发送方证书，或者文件已被篡改。\n");
        goto cleanup;
    }

    f_out = fopen(out_file, "wb");
    if (!f_out) { perror("无法创建解密文件"); goto cleanup; }
    
    unsigned char stream_header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    if (fread(stream_header, 1, sizeof(stream_header), f_in) != sizeof(stream_header)) {
        fprintf(stderr, "错误: 读取流加密头部失败。文件不完整或已损坏。\n");
        goto cleanup;
    }

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, stream_header, dec_session_key) != 0) {
        fprintf(stderr, "错误: 无效的流加密头部。文件可能已被篡改。\n");
        goto cleanup;
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
        if (bytes_read == 0 && feof(f_in)) break;

        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, bytes_read, NULL, 0) != 0) {
            fprintf(stderr, "错误: 解密文件块失败！数据可能被篡改。\n");
            goto cleanup;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            stream_finished = true;
        }
        
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
             fprintf(stderr, "错误: 写入解密文件块失败。\n");
             goto cleanup;
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
    hsc_free_master_key_pair(&recipient_kp); // [COMMITTEE REFACTOR]
    sodium_memzero(dec_session_key, sizeof(dec_session_key)); // [COMMITTEE REFACTOR] 擦除栈上的会话密钥
    return ret;
}

// --- Main 函数 ---
int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // [COMMITTEE REFACTOR] 调用统一的公共初始化函数。
    if (hsc_init() != 0) {
        fprintf(stderr, "严重错误: 高安全内核库初始化失败！\n");
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
    
    // [COMMITTEE REFACTOR] 调用统一的公共清理函数。
    hsc_cleanup();
    return 0;
}