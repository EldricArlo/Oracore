/* --- START OF FILE src/cli.c --- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

// 引入环境检测头文件
#if defined(_WIN32) || defined(__WIN32__)
    #include <io.h>
    #define isatty _isatty
    #define fileno _fileno
#else
    #include <unistd.h>
#endif

// 引入 getopt_long 以增强参数解析
#include <getopt.h>
// 在某些环境中（如 MinGW），optind 需要手动声明
#if defined(__MINGW32__) || defined(__MINGW64__)
extern int optind;
#endif

// 重新包含 sodium.h 以解决 'sodium_memzero' 隐式声明错误
#include <sodium.h> 

#include "hsc_kernel.h"

// --- 全局配置 ---
// [FIX]: Finding #4 - 新增全局标志，用于控制是否强制允许非交互模式
static bool g_force_non_interactive = false;


// --- 日志回调实现 ---

/**
 * @brief 命令行工具的日志处理函数。
 *        此函数将作为回调被注册到 hsc_kernel 库中。
 *        它负责根据日志级别格式化并打印所有来自库内部的日志消息。
 * @param level 日志级别 (0: INFO, 1: WARN, 2: ERROR)。
 * @param message 库传递过来的日志消息。
 */
static void cli_logger(int level, const char* message) {
    switch (level) {
        case 0: // INFO
            fprintf(stdout, "%s\n", message);
            break;
        case 1: // WARNING
            fprintf(stderr, "\033[33m[警告]\033[0m %s\n", message);
            break;
        case 2: // ERROR
            fprintf(stderr, "\033[31m[错误]\033[0m %s\n", message);
            break;
        default:
            fprintf(stderr, "[未知级别] %s\n", message);
            break;
    }
}

// --- 辅助函数 ---
void print_usage(const char* prog_name) {
    fprintf(stderr, "高安全性混合加密系统 v4.5 (CI/CD 增强版 CLI)\n\n");
    fprintf(stderr, "用法: %s <命令> [参数...]\n\n", prog_name);
    
    // [FIX]: 文档更新
    fprintf(stderr, "全局选项:\n");
    fprintf(stderr, "  --force-non-interactive  允许在非 TTY 环境(如脚本)中使用高风险模式 (慎用!)\n\n");

    fprintf(stderr, "命令列表:\n");
    fprintf(stderr, "  gen-keypair <basename>\n");
    fprintf(stderr, "  gen-csr <private-key-file> <username>\n");
    fprintf(stderr, "  verify-cert <cert-to-verify> --ca <ca-cert> --user <expected-user>\n");
    
    fprintf(stderr, "  encrypt <file> --to <recipient-cert.pem> --from <sender.key> --ca <ca.pem> --user <user-cn>\n");
    fprintf(stderr, "               [--no-verify] (危险: 跳过对接收者证书的验证)\n");
    
    fprintf(stderr, "  (原始密钥模式) encrypt <file> --recipient-pk-file <recipient.pub> --from <sender.key>\n");
    
    fprintf(stderr, "  decrypt <file.hsc> --to <recipient.key> --from <sender-cert.pem> --ca <ca.pem> --user <sender-cn>\n");
    fprintf(stderr, "               [--no-verify] (危险: 跳过对发送者证书的验证)\n");
    
    fprintf(stderr, "  (原始密钥模式) decrypt <file.hsc> --to <recipient.key> --sender-pk-file <sender.pub>\n");
}

// [修复] 为文件读取定义一个统一、合理的上限，防止资源耗尽攻击。
#define MAX_READ_FILE_SIZE (10 * 1024 * 1024)

// [FIX]: 内存安全修复 - read_small_file 现在返回安全内存 (sodium_malloc)
// 调用者必须使用 hsc_secure_free 释放返回的指针。
unsigned char* read_small_file(const char* filename, size_t* out_len) {
    FILE* f;
    bool is_stdin = (strcmp(filename, "-") == 0);

    if (is_stdin) {
        f = stdin;
        size_t capacity = 4096;
        size_t size = 0;
        // [FIX]: 使用安全内存分配初始缓冲区
        unsigned char* buffer = hsc_secure_alloc(capacity);
        if (!buffer) {
            fprintf(stderr, "错误: 安全内存分配失败\n");
            return NULL;
        }

        size_t bytes_read;
        while ((bytes_read = fread(buffer + size, 1, capacity - size, f)) > 0) {
            size += bytes_read;
            if (size >= MAX_READ_FILE_SIZE) {
                fprintf(stderr, "错误: 从标准输入读取的数据超过了 %d MB 的上限\n", MAX_READ_FILE_SIZE / (1024 * 1024));
                hsc_secure_free(buffer);
                return NULL;
            }

            if (size == capacity) {
                // [FIX]: Finding #3 - 优化整数溢出防御逻辑 (保留上次修复)
                size_t next_capacity;
                if (capacity > SIZE_MAX / 2) {
                    next_capacity = SIZE_MAX;
                } else {
                    next_capacity = capacity * 2;
                }

                if (next_capacity > MAX_READ_FILE_SIZE) {
                    next_capacity = MAX_READ_FILE_SIZE;
                }

                if (next_capacity <= size) {
                    fprintf(stderr, "错误: 输入数据流过大，无法安全地扩展缓冲区 (超过 %d MB)。\n", MAX_READ_FILE_SIZE / (1024 * 1024));
                    hsc_secure_free(buffer);
                    return NULL;
                }

                capacity = next_capacity;
                
                // [FIX]: 手动实现安全 realloc
                // sodium_malloc 不支持 realloc，必须 alloc new -> memcpy -> free old
                unsigned char* new_buffer = hsc_secure_alloc(capacity);
                if (!new_buffer) {
                    fprintf(stderr, "错误: 安全内存重分配失败\n");
                    hsc_secure_free(buffer);
                    return NULL;
                }
                // 复制旧数据
                memcpy(new_buffer, buffer, size);
                // 安全释放旧数据（自动擦除）
                hsc_secure_free(buffer);
                buffer = new_buffer;
            }
        }
        // 确保 null 终止符有空间（虽然对于二进制数据不总是需要，但为了字符串兼容性）
        // 注意：如果 size == capacity，这里写入可能会越界，但在 secure_alloc 中我们通常不需要强制 +1，
        // 除非是作为字符串处理。为了安全起见，如果不确定是字符串，不要依赖 null 终止符。
        // 如果确实需要，应该在上面分配时多留一个字节。
        // 鉴于 read_small_file 主要用于读取 PEM 或 keys，我们做一次调整：
        if (size < capacity) {
             buffer[size] = '\0';
        } else {
             // 如果满了，需要扩展 1 字节来放 \0，或者如果在意性能且确认为二进制则忽略。
             // 这里为了通用性，扩展一下。
             unsigned char* final_buf = hsc_secure_alloc(size + 1);
             if(final_buf) {
                 memcpy(final_buf, buffer, size);
                 final_buf[size] = '\0';
                 hsc_secure_free(buffer);
                 buffer = final_buf;
             }
        }
        
        *out_len = size;
        return buffer;

    } else {
        f = fopen(filename, "rb");
        if (!f) {
            perror("无法打开文件");
            return NULL;
        }
        
        fseek(f, 0, SEEK_END);
        long file_size_long = ftell(f);
        fseek(f, 0, SEEK_SET);

        if (file_size_long < 0) {
            fprintf(stderr, "错误: 无法确定文件大小或文件超过2GB: %s\n", filename);
            fclose(f);
            return NULL;
        }

        size_t file_size = (size_t)file_size_long;
        if (file_size >= MAX_READ_FILE_SIZE) { 
            fprintf(stderr, "错误: 文件大小 (%zu bytes) 超过了允许的上限 (%d MB): %s\n", file_size, MAX_READ_FILE_SIZE / (1024 * 1024), filename);
            fclose(f);
            return NULL;
        }

        // [FIX]: 使用安全内存分配
        unsigned char* buffer = hsc_secure_alloc(file_size + 1);
        if (!buffer) {
            fprintf(stderr, "错误: 安全内存分配失败\n");
            fclose(f);
            return NULL;
        }

        size_t bytes_read = fread(buffer, 1, file_size, f);
        if (bytes_read != file_size) {
            fprintf(stderr, "错误: 读取文件失败: %s\n", filename);
            hsc_secure_free(buffer);
            fclose(f);
            return NULL;
        }
        
        fclose(f);
        buffer[bytes_read] = '\0';
        *out_len = bytes_read;
        return buffer;
    }
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
    // Skip checking argc rigidly here because global flags might shift indices
    // We trust getopt/manual parsing logic in main or specific handlers
    // For simplicity in this legacy handler, we just check the last 2 args
    if (argc < 3) { print_usage(argv[0]); return 1; }
    
    const char* basename = argv[optind]; // Use optind from main
    char pub_path[FILENAME_MAX], priv_path[FILENAME_MAX];
    
    snprintf(pub_path, sizeof(pub_path), "%s.pub", basename);
    snprintf(priv_path, sizeof(priv_path), "%s.key", basename);
    
    int ret = 1;
    hsc_master_key_pair* kp = hsc_generate_master_key_pair();
    if (kp) {
        if (hsc_save_master_key_pair(kp, pub_path, priv_path) == HSC_OK) {
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
    if (argc < 4) { print_usage(argv[0]); return 1; }
    const char* priv_path = argv[optind]; 
    const char* user_cn = argv[optind + 1];
    
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
    if (hsc_generate_csr(kp, user_cn, &csr_pem) != HSC_OK) {
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
    // optind is set by main's getopt_long
    if (argc - optind < 1) { print_usage(argv[0]); return 1; }

    const char* cert_path = argv[optind];
    const char* ca_path = NULL;
    const char* user_cn = NULL;

    static struct option long_options[] = {
        {"ca",   required_argument, 0, 'c'},
        {"user", required_argument, 0, 'u'},
        {"force-non-interactive", no_argument, 0, 'F'}, // Allow explicit ignore
        {0, 0, 0, 0}
    };

    int opt;
    // Reset optind for this function's parsing, but we need to handle the fact
    // that main already parsed global options.
    // In this simple CLI structure, we'll re-parse or just parse remaining.
    // Actually, handle_* functions are receiving the full argv.
    // Let's use a local loop that skips the first command argument.
    
    optind = 2; // Skip prog_name and command
    while ((opt = getopt_long(argc, argv, "c:u:F", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c': ca_path = optarg; break;
            case 'u': user_cn = optarg; break;
            case 'F': g_force_non_interactive = true; break;
            default: break; // Ignore unknown or handled by main
        }
    }
    // Update cert_path to be the first non-option argument
    if (optind < argc) {
        cert_path = argv[optind];
    } else {
        print_usage(argv[0]); return 1;
    }

    if (!cert_path || !ca_path || !user_cn) { print_usage(argv[0]); return 1; }

    int ret = 1;
    unsigned char* user_cert_pem = NULL, *ca_cert_pem = NULL; size_t cert_len, ca_len;
    user_cert_pem = read_small_file(cert_path, &cert_len);
    ca_cert_pem = read_small_file(ca_path, &ca_len);
    if (!user_cert_pem || !ca_cert_pem) { goto cleanup; }
    
    printf("开始验证证书 %s ...\n", cert_path);
    int result = hsc_verify_user_certificate((const char*)user_cert_pem, (const char*)ca_cert_pem, user_cn);
    
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
        case HSC_ERROR_CERT_REVOKED: 
            fprintf(stderr, "\033[31m[失败]\033[0m 证书已被其颁发机构明确吊销！\n"); 
            break;
        case HSC_ERROR_CERT_OCSP_UNAVAILABLE:
            fprintf(stderr, "\033[31m[失败]\033[0m 无法完成证书吊销状态检查 (OCSP)。可能存在网络问题或OCSP服务器无响应。\n");
            break;
        case HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN:
            fprintf(stderr, "\033[31m[失败]\033[0m OCSP服务器报告此证书状态未知！根据安全策略，这被视为证书无效。\n");
            break;
        case HSC_ERROR_CERT_NO_OCSP_URI:
            fprintf(stderr, "\033[31m[失败]\033[0m 证书缺少 OCSP URI (AIA扩展)，无法检查吊销状态。\n");
            fprintf(stderr, "           当前安全策略 (Fail-Closed) 禁止信任此类证书。\n");
            break;
        case HSC_ERROR_INVALID_FORMAT:
            fprintf(stderr, "\033[31m[失败]\033[0m 无法解析证书文件，请检查是否为有效的PEM格式。\n"); 
            break;
        default: 
            fprintf(stderr, "\033[31m[失败]\033[0m 发生未知验证错误 (代码: %d)。\n", result); 
            break;
    }
cleanup:
    // [FIX]: 使用安全释放
    if(user_cert_pem) hsc_secure_free(user_cert_pem);
    if(ca_cert_pem) hsc_secure_free(ca_cert_pem); 
    return ret;
}

// ====================================================================================
// --- REFACTORED: handle_hybrid_encrypt and its new helper functions ---
// ====================================================================================

typedef struct {
    const char* in_file;
    const char* recipient_cert_file;
    const char* recipient_pk_file;
    const char* sender_priv_file;
    const char* ca_path;
    const char* user_cn;
    bool no_verify_flag;
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
} encrypt_args;

static bool _parse_encrypt_args(int argc, char* argv[], encrypt_args* args) {
    memset(args, 0, sizeof(encrypt_args));
    
    // We need to find the input file, which is a positional argument
    // Let's use getopt to parse flags first.
    static struct option long_options[] = {
        {"to",                required_argument, 0, 't'},
        {"from",              required_argument, 0, 'f'},
        {"recipient-pk-file", required_argument, 0, 'r'},
        {"ca",                required_argument, 0, 'c'},
        {"user",              required_argument, 0, 'u'},
        {"no-verify",         no_argument,       0, 'n'},
        {"force-non-interactive", no_argument, 0, 'F'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 2; // Start after 'encrypt'
    while ((opt = getopt_long(argc, argv, "t:f:r:c:u:nF", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': args->recipient_cert_file = optarg; break;
            case 'f': args->sender_priv_file = optarg; break;
            case 'r': args->recipient_pk_file = optarg; break;
            case 'c': args->ca_path = optarg; break;
            case 'u': args->user_cn = optarg; break;
            case 'n': args->no_verify_flag = true; break;
            case 'F': g_force_non_interactive = true; break;
            default: return false;
        }
    }

    if (optind < argc) {
        args->in_file = argv[optind];
    } else {
        return false;
    }

    if (!args->in_file || !args->sender_priv_file || (!args->recipient_cert_file && !args->recipient_pk_file)) {
        fprintf(stderr, "错误: 缺少必要的加密参数。\n");
        return false;
    }
    if (args->recipient_cert_file && args->recipient_pk_file) {
        fprintf(stderr, "错误: --to 和 --recipient-pk-file 选项是互斥的。\n");
        return false;
    }
    if (args->recipient_cert_file && !args->no_verify_flag && (!args->ca_path || !args->user_cn)) {
        fprintf(stderr, "错误: 使用证书加密时，必须提供 --ca 和 --user 参数进行验证。\n");
        fprintf(stderr, "      如果您确认要跳过验证，请添加 --no-verify 标志。\n");
        return false;
    }
    
    return true;
}

static int _prepare_recipient_pk(encrypt_args* args) {
    unsigned char* recipient_cert_pem = NULL;
    unsigned char* ca_cert_pem = NULL;
    int ret_code = HSC_ERROR_GENERAL;

    if (args->recipient_pk_file) {
        // [FIX]: Finding #4 - 支持 --force-non-interactive 绕过 TTY 检查
        if (!isatty(fileno(stdin))) {
            if (g_force_non_interactive) {
                fprintf(stderr, "\n\033[1;33m[警告] 检测到非交互式环境，但已设置 --force-non-interactive。\n");
                fprintf(stderr, "       正在绕过 TTY 安全检查。请确保您知晓 '原始公钥模式' 的风险！\033[0m\n");
            } else {
                fprintf(stderr, "错误: 检测到非交互式环境 (非 TTY)。\n");
                fprintf(stderr, "为防止误操作，默认禁止在脚本中通过管道使用此高风险模式。\n");
                fprintf(stderr, "若需在 CI/CD 中使用，请显式添加全局标志 --force-non-interactive\n");
                return HSC_ERROR_GENERAL;
            }
        } else {
            // 交互式环境：仍然需要手动确认
            fprintf(stderr, "\n\033[1;31m*** 严重安全警告 ***\033[0m\n");
            fprintf(stderr, "\033[33m您正在使用“原始公钥模式”(--recipient-pk-file) 进行加密。\n");
            fprintf(stderr, "此模式 \033[1;31m不会\033[0m 通过证书来验证接收者的身份。\n");
            fprintf(stderr, "如果您使用的公钥文件来源不可靠（例如，来自一个被篡改的网站），\n");
            fprintf(stderr, "您的数据将被加密给 \033[1;31m攻击者\033[0m。\n");
            fprintf(stderr, "请再次确认您绝对信任公钥文件 '%s' 的来源。\033[0m\n\n", args->recipient_pk_file);
            fprintf(stderr, "要继续此高风险操作，请输入 'yes': ");
            
            char confirmation[10] = {0};
            if (fgets(confirmation, sizeof(confirmation), stdin) == NULL || strncmp(confirmation, "yes\n", 4) != 0) {
                fprintf(stderr, "\n操作已由用户取消。加密中止。\n");
                return HSC_ERROR_GENERAL;
            }
            fprintf(stderr, "\n");
        }
        
        size_t pk_len;
        unsigned char* pk_buf = read_small_file(args->recipient_pk_file, &pk_len);
        if (!pk_buf || pk_len != HSC_MASTER_PUBLIC_KEY_BYTES) {
            fprintf(stderr, "错误: 读取或验证接收者公钥文件 '%s' 失败。\n", args->recipient_pk_file);
            // [FIX]: 使用安全释放
            if(pk_buf) hsc_secure_free(pk_buf);
            return HSC_ERROR_FILE_IO;
        }
        memcpy(args->recipient_pk, pk_buf, HSC_MASTER_PUBLIC_KEY_BYTES);
        hsc_secure_free(pk_buf);
        ret_code = HSC_OK;

    } else {
        // --- Certificate Mode ---
        size_t cert_len;
        recipient_cert_pem = read_small_file(args->recipient_cert_file, &cert_len);
        if (!recipient_cert_pem) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }

        if (args->no_verify_flag) {
            fprintf(stdout, "\n\033[31m[危险警告] 您已选择 --no-verify 选项。\n           系统将不会验证接收者证书的真实性、有效性或吊销状态。\n           请仅在完全信任此证书来源的情况下使用此选项。\033[0m\n\n");
        } else {
            size_t ca_len;
            ca_cert_pem = read_small_file(args->ca_path, &ca_len);
            if (!ca_cert_pem) { ret_code = HSC_ERROR_FILE_IO; goto cleanup; }

            printf("正在验证接收者证书 '%s' ...\n", args->recipient_cert_file);
            int verify_result = hsc_verify_user_certificate((const char*)recipient_cert_pem, (const char*)ca_cert_pem, args->user_cn);
            if (verify_result != HSC_OK) {
                fprintf(stderr, "错误: 接收者证书验证失败 (代码: %d)。加密操作已中止。\n", verify_result);
                if (verify_result == HSC_ERROR_CERT_NO_OCSP_URI) {
                    fprintf(stderr, "      原因: 证书缺少 OCSP 信息 (AIA)，安全策略拒绝放行。\n");
                }
                ret_code = verify_result;
                goto cleanup;
            }
            printf("✅ 接收者证书验证成功。\n");
        }

        if (hsc_extract_public_key_from_cert((const char*)recipient_cert_pem, args->recipient_pk) != HSC_OK) {
            fprintf(stderr, "错误: 无法从接收者证书 '%s' 中提取公钥。\n", args->recipient_cert_file);
            ret_code = HSC_ERROR_PKI_OPERATION;
            goto cleanup;
        }
        ret_code = HSC_OK;
    }

cleanup:
    // [FIX]: 使用安全释放
    if(recipient_cert_pem) hsc_secure_free(recipient_cert_pem);
    if(ca_cert_pem) hsc_secure_free(ca_cert_pem);
    return ret_code;
}

int handle_hybrid_encrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }

    encrypt_args args;
    if (!_parse_encrypt_args(argc, argv, &args)) {
        print_usage(argv[0]);
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), args.in_file, ".hsc")) {
        fprintf(stderr, "错误: 生成的输出文件名过长。\n");
        return 1;
    }
    
    int ret = 1;
    hsc_master_key_pair* sender_kp = NULL;
    
    if (_prepare_recipient_pk(&args) != HSC_OK) {
        goto cleanup;
    }
    
    sender_kp = hsc_load_master_key_pair_from_private_key(args.sender_priv_file);
    if (!sender_kp) {
        fprintf(stderr, "错误: 无法从 '%s' 加载发送者私钥。\n", args.sender_priv_file);
        goto cleanup;
    }
    
    printf("正在加密 %s -> %s ...\n", args.in_file, out_file);
    int result = hsc_hybrid_encrypt_stream_raw(out_file, args.in_file, args.recipient_pk, sender_kp);

    if (result == HSC_OK) {
        printf("✅ 混合加密完成！\n");
        ret = 0;
    } else {
        fprintf(stderr, "错误: 加密过程中发生错误 (代码: %d)。\n", result);
    }

cleanup:
    hsc_free_master_key_pair(&sender_kp);
    return ret;
}

int handle_hybrid_decrypt(int argc, char* argv[]) {
    if (argc < 3) { print_usage(argv[0]); return 1; }
    
    const char* in_file = NULL;
    const char* sender_cert_file = NULL;
    const char* sender_pk_file = NULL;
    const char* recipient_priv_file = NULL;
    const char* ca_path = NULL;
    const char* sender_cn = NULL;
    bool no_verify_flag = false;

    static struct option long_options[] = {
        {"to",             required_argument, 0, 't'},
        {"from",           required_argument, 0, 'f'},
        {"sender-pk-file", required_argument, 0, 's'},
        {"ca",             required_argument, 0, 'c'},
        {"user",           required_argument, 0, 'u'},
        {"no-verify",      no_argument,       0, 'n'},
        {"force-non-interactive", no_argument, 0, 'F'},
        {0, 0, 0, 0}
    };
    
    int opt;
    optind = 2; 
    while ((opt = getopt_long(argc, argv, "t:f:s:c:u:nF", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': recipient_priv_file = optarg; break;
            case 'f': sender_cert_file = optarg; break;
            case 's': sender_pk_file = optarg; break;
            case 'c': ca_path = optarg; break;
            case 'u': sender_cn = optarg; break;
            case 'n': no_verify_flag = true; break;
            case 'F': g_force_non_interactive = true; break;
            default: break;
        }
    }
    
    if (optind < argc) {
        in_file = argv[optind];
    } else {
        print_usage(argv[0]); return 1;
    }
    
    if (!in_file || !recipient_priv_file || (!sender_cert_file && !sender_pk_file)) {
        print_usage(argv[0]); return 1;
    }
    if (sender_cert_file && sender_pk_file) {
        fprintf(stderr, "错误: --from 和 --sender-pk-file 选项是互斥的。\n");
        return 1;
    }

    if (sender_cert_file && !no_verify_flag && (!ca_path || !sender_cn)) {
        fprintf(stderr, "错误: 使用证书解密时，必须提供 --ca 和 --user 参数以验证发送者身份。\n");
        fprintf(stderr, "      如果您确认要跳过验证（不推荐），请添加 --no-verify 标志。\n");
        return 1;
    }

    char out_file[FILENAME_MAX];
    if (!create_output_path(out_file, sizeof(out_file), in_file, ".decrypted")) {
        fprintf(stderr, "错误: 生成的输出文件名过长。\n"); return 1;
    }

    int ret = 1;
    unsigned char* sender_cert_pem = NULL;
    unsigned char* ca_cert_pem = NULL;
    hsc_master_key_pair* recipient_kp = NULL;
    unsigned char sender_pk[HSC_MASTER_PUBLIC_KEY_BYTES];

    if (sender_pk_file) {
        // [FIX]: Finding #4 - 支持 --force-non-interactive
        if (!isatty(fileno(stdin))) {
            if (g_force_non_interactive) {
                fprintf(stderr, "\n\033[1;33m[警告] 检测到非交互式环境，但已设置 --force-non-interactive。\n");
                fprintf(stderr, "       正在绕过 TTY 安全检查。解密操作将继续！\033[0m\n");
            } else {
                fprintf(stderr, "错误: 检测到非交互式环境 (非 TTY)。\n");
                fprintf(stderr, "为防止误操作，默认禁止在脚本中通过管道使用此高风险模式。\n");
                fprintf(stderr, "若需在 CI/CD 中使用，请显式添加全局标志 --force-non-interactive\n");
                return HSC_ERROR_GENERAL;
            }
        } else {
            fprintf(stderr, "\n\033[1;31m*** 严重安全警告 ***\033[0m\n");
            fprintf(stderr, "\033[33m您正在使用“原始公钥模式”(--sender-pk-file) 进行解密。\n");
            fprintf(stderr, "此模式 \033[1;31m不会\033[0m 通过证书来验证发送者的身份。\n");
            fprintf(stderr, "这意味着您无法确定加密文件的真实来源，它可能来自一个 \033[1;31m伪造的发送者\033[0m。\n");
            fprintf(stderr, "请再次确认您绝对信任公钥文件 '%s' 的来源。\033[0m\n\n", sender_pk_file);
            fprintf(stderr, "要继续此高风险操作，请输入 'yes': ");
            
            char confirmation[10] = {0};
            if (fgets(confirmation, sizeof(confirmation), stdin) == NULL || strncmp(confirmation, "yes\n", 4) != 0) {
                fprintf(stderr, "\n操作已由用户取消。解密中止。\n");
                return HSC_ERROR_GENERAL;
            }
            fprintf(stderr, "\n");
        }
        
        size_t pk_len;
        unsigned char* pk_buf = read_small_file(sender_pk_file, &pk_len);
        if (!pk_buf || pk_len != HSC_MASTER_PUBLIC_KEY_BYTES) {
            fprintf(stderr, "错误: 读取或验证发送者公钥文件 '%s' 失败。\n", sender_pk_file);
            if(pk_buf) hsc_secure_free(pk_buf);
            goto cleanup;
        }
        memcpy(sender_pk, pk_buf, HSC_MASTER_PUBLIC_KEY_BYTES);
        hsc_secure_free(pk_buf);

    } else {
        // --- Certificate Mode ---
        size_t cert_len;
        sender_cert_pem = read_small_file(sender_cert_file, &cert_len);
        if (!sender_cert_pem) goto cleanup;

        if (no_verify_flag) {
             fprintf(stdout, "\n\033[31m[危险警告] 您已选择 --no-verify 选项。\n           系统将不会验证发送者证书的真实性、有效性或吊销状态。\n           解密后的数据可能来自伪造的发送者。\033[0m\n\n");
        } else {
            size_t ca_len;
            ca_cert_pem = read_small_file(ca_path, &ca_len);
            if (!ca_cert_pem) { 
                fprintf(stderr, "错误: 无法读取 CA 证书文件 '%s'\n", ca_path);
                goto cleanup; 
            }

            printf("正在验证发送者证书 '%s' ...\n", sender_cert_file);
            int verify_result = hsc_verify_user_certificate((const char*)sender_cert_pem, (const char*)ca_cert_pem, sender_cn);
            
            if (verify_result != HSC_OK) {
                fprintf(stderr, "\033[31m[致命错误]\033[0m 发送者证书验证失败 (代码: %d)！\n", verify_result);
                if (verify_result == HSC_ERROR_CERT_NO_OCSP_URI) {
                     fprintf(stderr, "           原因: 证书缺少 OCSP URI (AIA扩展)，且策略设置为严格模式。\n");
                }
                fprintf(stderr, "可能原因: 证书过期、已被吊销、非受信任CA签发或用户名不匹配。\n");
                fprintf(stderr, "为保障安全，解密操作已中止。\n");
                goto cleanup; // Fail-Closed
            }
            printf("✅ 发送者身份验证成功。\n");
        }

        if (hsc_extract_public_key_from_cert((const char*)sender_cert_pem, sender_pk) != HSC_OK) {
            fprintf(stderr, "错误: 无法从发送者证书 '%s' 中提取公钥。\n", sender_cert_file);
            goto cleanup;
        }
    }

    recipient_kp = hsc_load_master_key_pair_from_private_key(recipient_priv_file);
    if (!recipient_kp) {
        fprintf(stderr, "错误: 无法从 '%s' 加载接收者私钥。\n", recipient_priv_file);
        goto cleanup;
    }
    
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
    // [FIX]: 使用安全释放
    if(sender_cert_pem) hsc_secure_free(sender_cert_pem);
    if(ca_cert_pem) hsc_secure_free(ca_cert_pem);
    hsc_free_master_key_pair(&recipient_kp);
    if (ret != 0) remove(out_file);
    return ret;
}

// --- Main 函数 ---
int main(int argc, char* argv[]) {
    // [FIX]: Finding #4 - 全局解析 --force-non-interactive
    // 简单的预解析：如果 argv 中包含该标志，则设置全局变量
    // 注意：这里的简单循环是为了确保它在任何子命令处理之前生效。
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force-non-interactive") == 0) {
            g_force_non_interactive = true;
            break;
        }
    }

    if (argc < 2) { print_usage(argv[0]); return 1; }
    
    // 初始化库
    if (hsc_init(NULL, NULL) != HSC_OK) {
        fprintf(stderr, "严重错误: 高安全内核库初始化失败！\n"); return 1;
    }
    
    hsc_set_log_callback(cli_logger);

    const char* command = argv[1];
    int ret = 1;
    
    // 重置 optind，因为我们在 main 和 helper 函数中都会使用 getopt
    optind = 1; 

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
        // 如果第一个参数不是命令（可能是全局 flag），打印帮助
        if (command[0] == '-') {
             fprintf(stderr, "错误: 请先指定命令，再使用全局选项。\n");
        } else {
             fprintf(stderr, "错误: 未知命令 '%s'\n", command);
        }
        print_usage(argv[0]);
    }
    hsc_cleanup();
    return ret;
}
/* --- END OF FILE src/cli.c --- */