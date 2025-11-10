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

// --- 可移植的字节序处理辅助函数 ---
static void store64_le(unsigned char* dst, uint64_t w) {
    dst[0] = (unsigned char)w; w >>= 8; dst[1] = (unsigned char)w; w >>= 8;
    dst[2] = (unsigned char)w; w >>= 8; dst[3] = (unsigned char)w; w >>= 8;
    dst[4] = (unsigned char)w; w >>= 8; dst[5] = (unsigned char)w; w >>= 8;
    dst[6] = (unsigned char)w; w >>= 8; dst[7] = (unsigned char)w;
}
static uint64_t load64_le(const unsigned char* src) {
    uint64_t w = src[7];
    w = (w << 8) | src[6]; w = (w << 8) | src[5]; w = (w << 8) | src[4];
    w = (w << 8) | src[3]; w = (w << 8) | src[2]; w = (w << 8) | src[1];
    w = (w << 8) | src[0]; return w;
}

// --- 辅助函数 ---
void print_usage(const char* prog_name) {
    fprintf(stderr, "高安全性混合加密系统 v4.2 (流式处理版 CLI)\n\n");
    fprintf(stderr, "用法: %s <命令> [参数...]\n\n", prog_name);
    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair <basename>\n");
    fprintf(stderr, "  gen-csr <private-key-file> <username>\n");
    fprintf(stderr, "  verify-cert <cert-to-verify> --ca <ca-cert> --user <expected-user>\n");
    fprintf(stderr, "  encrypt <file> --to <recipient-cert> --from <sender-priv-key>\n");
    fprintf(stderr, "  decrypt <file.hsc> --from <sender-cert> --to <recipient-priv-key>\n");
}

// Refactored to support streams (e.g., pipes) and handle empty files correctly.
// This new implementation reads in chunks, is not vulnerable to issues with ftell on non-regular files,
// and treats a filename of "-" as stdin.
// [修改] 已移除本地宏定义，将使用 hsc_kernel.h 中的 HSC_FILE_IO_CHUNK_SIZE
unsigned char* read_variable_size_file(const char* filename, size_t* out_len) {
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

    unsigned char* buffer = NULL;
    size_t total_read = 0;
    size_t capacity = 0;
    
    while (true) {
        if (capacity < total_read + HSC_FILE_IO_CHUNK_SIZE) {
            // Use geometric growth for efficiency
            size_t new_capacity = (capacity == 0) ? HSC_FILE_IO_CHUNK_SIZE : capacity * 2;
            unsigned char* new_buffer = realloc(buffer, new_capacity);
            if (!new_buffer) {
                fprintf(stderr, "错误: 读取文件时内存分配失败。\n");
                free(buffer);
                if (!is_stdin) fclose(f);
                return NULL;
            }
            buffer = new_buffer;
            capacity = new_capacity;
        }

        size_t bytes_to_read = capacity - total_read;
        size_t bytes_read = fread(buffer + total_read, 1, bytes_to_read, f);
        total_read += bytes_read;

        if (bytes_read < bytes_to_read) {
            if (ferror(f)) {
                perror("读取文件时发生错误");
                free(buffer);
                if (!is_stdin) fclose(f);
                return NULL;
            }
            // End of file reached, break the loop
            break;
        }
    }
    
    if (!is_stdin) {
        fclose(f);
    }

    // Add null terminator
    unsigned char* final_buffer = realloc(buffer, total_read + 1);
    if (!final_buffer && total_read > 0) {
        // Fallback: realloc should not fail on shrink, but if it does, the original buffer is still valid.
        buffer[total_read] = '\0';
        *out_len = total_read;
        return buffer;
    }
    
    // Handle edge case of empty file where realloc(NULL, 1) or malloc(1) is needed
    if (!final_buffer) {
        final_buffer = malloc(1);
        if (!final_buffer) {
            fprintf(stderr, "错误: 为空内容分配缓冲区失败。\n");
            return NULL;
        }
    }
    
    final_buffer[total_read] = '\0';
    *out_len = total_read;
    return final_buffer;
}

bool write_file_bytes(const char* filename, const void* data, size_t len) {
    FILE* f = fopen(filename, "wb");
    if (!f) { return false; }
    bool ok = (fwrite(data, 1, len, f) == len);
    fclose(f); return ok;
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
    if (kp && hsc_save_master_key_pair(kp, pub_path, priv_path) == 0) {
        printf("✅ 成功生成密钥对:\n  公钥 -> %s\n  私钥 -> %s\n", pub_path, priv_path);
        ret = 0;
    }
    hsc_free_master_key_pair(&kp);
    return ret;
}

int handle_gen_csr(int argc, char* argv[]) {
    if (argc != 4) { print_usage(argv[0]); return 1; }
    const char* priv_path = argv[2]; const char* user_cn = argv[3];
    char csr_path[FILENAME_MAX];
    if (!create_output_path(csr_path, sizeof(csr_path), priv_path, ".csr")) return 1;
    
    int ret = 1;
    hsc_master_key_pair* kp = NULL; char* csr_pem = NULL;
    kp = hsc_load_master_key_pair_from_private_key(priv_path);
    if (!kp) { goto cleanup; }
    if (hsc_generate_csr(kp, user_cn, &csr_pem) != 0) { goto cleanup; }
    if (!write_file_bytes(csr_path, csr_pem, strlen(csr_pem))) goto cleanup;
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

    // 使用 getopt_long 解析参数
    static struct option long_options[] = {
        {"ca",   required_argument, 0, 'c'},
        {"user", required_argument, 0, 'u'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 3; // 从 argv[3] 开始解析
    while ((opt = getopt_long(argc, argv, "c:u:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                ca_path = optarg;
                break;
            case 'u':
                user_cn = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!cert_path || !ca_path || !user_cn) {
        print_usage(argv[0]);
        return 1;
    }

    int ret = 1;
    unsigned char* user_cert_pem = NULL, *ca_cert_pem = NULL; size_t cert_len, ca_len;
    user_cert_pem = read_variable_size_file(cert_path, &cert_len);
    ca_cert_pem = read_variable_size_file(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) { goto cleanup; }
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = hsc_verify_user_certificate((const char*)user_cert_pem, (const char*)ca_cert_pem, user_cn);
    // [修改] 使用定义的常量进行 switch
    switch(result) {
        case HSC_VERIFY_SUCCESS:  
            printf("\033[32m[成功]\033[0m 证书所有验证项均通过。\n"); 
            ret = 0; 
            break;
        case HSC_VERIFY_ERROR_CHAIN_OR_VALIDITY: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书签名链或有效期验证失败。\n"); 
            break;
        case HSC_VERIFY_ERROR_SUBJECT_MISMATCH: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书主体不匹配。\n"); 
            break;
        case HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书吊销状态检查失败 (OCSP)！\n"); 
            break;
        default: 
            fprintf(stderr, "\033[31m[失败]\033[0m 未知验证错误 (代码: %d)。\n", result); 
            break;
    }
cleanup:
    free(user_cert_pem); free(ca_cert_pem); return ret;
}

int handle_hybrid_encrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }

    const char* in_file = argv[2];
    const char* recipient_cert_file = NULL;
    const char* sender_priv_file = NULL;

    // 使用 getopt_long 解析参数
    static struct option long_options[] = {
        {"to",   required_argument, 0, 't'},
        {"from", required_argument, 0, 'f'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 3; // 从 argv[3] 开始解析
    while ((opt = getopt_long(argc, argv, "t:f:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                recipient_cert_file = optarg;
                break;
            case 'f':
                sender_priv_file = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!in_file || !recipient_cert_file || !sender_priv_file) {
        print_usage(argv[0]);
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".hsc")) return 1;
    
    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    hsc_master_key_pair* sender_kp = NULL;
    unsigned char* recipient_cert_pem = NULL;
    hsc_crypto_stream_state* st = NULL;
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    size_t cert_len;
    recipient_cert_pem = read_variable_size_file(recipient_cert_file, &cert_len);
    if (!recipient_cert_pem) { goto cleanup; }
    
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert((const char*)recipient_cert_pem, recipient_pk) != 0) goto cleanup;
    sender_kp = hsc_load_master_key_pair_from_private_key(sender_priv_file);
    if (!sender_kp) goto cleanup;
    
    unsigned char encapsulated_key[HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES];
    size_t actual_encapsulated_len;
    if (hsc_encapsulate_session_key(encapsulated_key, &actual_encapsulated_len, session_key, sizeof(session_key), recipient_pk, sender_kp) != 0) goto cleanup;

    f_in = fopen(in_file, "rb"); if (!f_in) { perror("无法打开输入文件"); goto cleanup; }
    f_out = fopen(out_file, "wb"); if (!f_out) { perror("无法创建输出文件"); goto cleanup; }
    
    unsigned char key_len_buf[8]; store64_le(key_len_buf, actual_encapsulated_len);
    
    if (fwrite(key_len_buf, 1, sizeof(key_len_buf), f_out) != sizeof(key_len_buf)) {
        fprintf(stderr, "错误: 写入文件头失败。可能磁盘已满。\n");
        goto cleanup;
    }
    if (fwrite(encapsulated_key, 1, actual_encapsulated_len, f_out) != actual_encapsulated_len) {
        fprintf(stderr, "错误: 写入封装的密钥失败。可能磁盘已满。\n");
        goto cleanup;
    }
    
    unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
    st = hsc_crypto_stream_state_new_push(stream_header, session_key);
    if (st == NULL) goto cleanup;
    
    if (fwrite(stream_header, 1, sizeof(stream_header), f_out) != sizeof(stream_header)) {
        fprintf(stderr, "错误: 写入流加密头失败。可能磁盘已满。\n");
        goto cleanup;
    }
    
    // [修改] 使用定义的常量
    unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE];
    unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
    size_t bytes_read;
    unsigned long long out_len;
    uint8_t tag;
    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) { perror("读取输入文件时发生错误"); goto cleanup; }
        tag = feof(f_in) ? HSC_STREAM_TAG_FINAL : 0;
        if (hsc_crypto_stream_push(st, buf_out, &out_len, buf_in, bytes_read, tag) != 0) {
            fprintf(stderr, "错误: 加密文件块失败。\n");
            goto cleanup;
        }
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
            fprintf(stderr, "错误: 写入加密数据块失败。可能磁盘已满。\n");
            goto cleanup;
        }
    } while (!feof(f_in));
    
    printf("✅ 混合加密完成！\n  输出文件 -> %s\n", out_file);
    ret = 0;
cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    if (ret != 0) {
        remove(out_file);
    }
    free(recipient_cert_pem);
    hsc_free_master_key_pair(&sender_kp);
    hsc_crypto_stream_state_free(&st);
    sodium_memzero(session_key, sizeof(session_key)); 
    return ret;
}

int handle_hybrid_decrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }
    
    const char* in_file = argv[2];
    const char* sender_cert_file = NULL;
    const char* recipient_priv_file = NULL;

    // 使用 getopt_long 解析参数
    static struct option long_options[] = {
        {"to",   required_argument, 0, 't'},
        {"from", required_argument, 0, 'f'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 3; // 从 argv[3] 开始解析
    while ((opt = getopt_long(argc, argv, "t:f:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                recipient_priv_file = optarg;
                break;
            case 'f':
                sender_cert_file = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!in_file || !sender_cert_file || !recipient_priv_file) {
        print_usage(argv[0]);
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".decrypted")) return 1;

    int ret = 1;
    FILE *f_in = NULL, *f_out = NULL;
    unsigned char* sender_cert_pem = NULL;
    hsc_master_key_pair* recipient_kp = NULL;
    unsigned char* enc_key = NULL;
    hsc_crypto_stream_state* st = NULL;
    unsigned char dec_session_key[HSC_SESSION_KEY_BYTES];
    f_in = fopen(in_file, "rb"); if (!f_in) { perror("无法打开输入文件"); goto cleanup; }
    
    unsigned char key_len_buf[8];
    if (fread(key_len_buf, 1, sizeof(key_len_buf), f_in) != sizeof(key_len_buf)) {
        fprintf(stderr, "错误: 读取文件失败，文件可能已损坏或不是有效的 .hsc 文件。\n");
        goto cleanup;
    }
    size_t enc_key_len = load64_le(key_len_buf);
    
    if (enc_key_len == 0 || enc_key_len > HSC_MAX_ENCAPSULATED_KEY_SIZE) {
        fprintf(stderr, "错误: 文件格式无效，加密的会话密钥长度（%zu字节）异常。\n", enc_key_len);
        goto cleanup;
    }
    enc_key = malloc(enc_key_len);
    if (!enc_key) { perror("内存分配失败"); goto cleanup; }
    if (fread(enc_key, 1, enc_key_len, f_in) != enc_key_len) {
        fprintf(stderr, "错误: 读取封装的密钥失败，文件可能已损坏。\n");
        goto cleanup;
    }
    
    size_t cert_len;
    sender_cert_pem = read_variable_size_file(sender_cert_file, &cert_len);
    if (!sender_cert_pem) goto cleanup;
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert((const char*)sender_cert_pem, sender_pk) != 0) goto cleanup;
    recipient_kp = hsc_load_master_key_pair_from_private_key(recipient_priv_file);
    if (!recipient_kp) goto cleanup;
    if (hsc_decapsulate_session_key(dec_session_key, enc_key, enc_key_len, sender_pk, recipient_kp) != 0) {
        fprintf(stderr, "错误: 解封装会话密钥失败！可能是密钥错误或数据被篡改。\n"); goto cleanup;
    }
    
    f_out = fopen(out_file, "wb"); if (!f_out) { perror("无法创建输出文件"); goto cleanup; }
    
    unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
    if (fread(stream_header, 1, sizeof(stream_header), f_in) != sizeof(stream_header)) {
        fprintf(stderr, "错误: 读取流加密头失败，文件可能已损坏。\n");
        goto cleanup;
    }
    st = hsc_crypto_stream_state_new_pull(stream_header, dec_session_key);
    if (st == NULL) { fprintf(stderr, "错误: 无效的流加密头部。可能是会话密钥错误。\n"); goto cleanup; }
    
    // [修改] 使用定义的常量
    unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
    unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE];
    size_t bytes_read;
    unsigned long long out_len;
    unsigned char tag;
    bool stream_finished = false;
    do {
        bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in);
        if (ferror(f_in)) { perror("读取输入文件时发生错误"); goto cleanup; }
        if (bytes_read == 0 && feof(f_in)) break;
        if (hsc_crypto_stream_pull(st, buf_out, &out_len, &tag, buf_in, bytes_read) != 0) {
            fprintf(stderr, "错误: 解密文件块失败！数据可能被篡改。\n"); goto cleanup;
        }
        if (tag == HSC_STREAM_TAG_FINAL) {
            stream_finished = true;
        }
        if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
            fprintf(stderr, "错误: 写入解密数据块失败。可能磁盘已满。\n");
            goto cleanup;
        }
    } while (!feof(f_in));
    
    if (!stream_finished) {
        fprintf(stderr, "错误: 解密失败！加密流被意外截断，文件不完整或已损坏。\n");
        goto cleanup;
    }

    printf("✅ 混合解密完成！\n  解密文件 -> %s\n", out_file);
    ret = 0;
cleanup:
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    if (ret != 0) {
        remove(out_file);
    }
    free(enc_key);
    free(sender_cert_pem);
    hsc_free_master_key_pair(&recipient_kp);
    hsc_crypto_stream_state_free(&st);
    sodium_memzero(dec_session_key, sizeof(dec_session_key));
    return ret;
}

// --- Main 函数 ---
int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (hsc_init() != 0) {
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
