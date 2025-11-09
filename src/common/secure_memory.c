/**
 * @file secure_memory.c
 * @brief 安全内存管理功能的实现。
 *
 * @details
 * 本文件通过直接调用 libsodium 相应的函数来实现 secure_memory.h 中定义的 API。
 * 这种封装提供了一个抽象层，使得项目的其他部分不直接依赖于 libsodium 的
 * 特定命名，增强了代码的模块化和可维护性。
 */

#include "secure_memory.h"
#include <sodium.h>

void* secure_alloc(size_t size) {
    // 调用 sodium_malloc 分配受保护的内存。
    // libsodium 会处理所有底层细节，如 mlock() 和 guard pages。
    return sodium_malloc(size);
}

void secure_free(void* ptr) {
    // 调用 sodium_free。它会在释放前自动、安全地擦除内存。
    sodium_free(ptr);
}

void secure_zero_memory(void* ptr, size_t len) {
    // 调用 sodium_memzero 保证内存被可靠地清零，防止编译器优化。
    sodium_memzero(ptr, len);
}