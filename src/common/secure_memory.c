#include "secure_memory.h"
#include <sodium.h>

void* secure_alloc(size_t size) {
    // 使用 sodium_malloc 分配锁定的内存，防止被交换到磁盘
    return sodium_malloc(size);
}

void secure_free(void* ptr) {
    // sodium_free 会在释放前自动擦除内存
    sodium_free(ptr);
}

void secure_zero_memory(void* ptr, size_t len) {
    // 显式地安全擦除内存
    sodium_memzero(ptr, len);
}