#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>

/**
 * @brief 分配一块受保护的、不可交换到磁盘的内存。
 * @param size 要分配的字节数。
 * @return 成功时返回指向受保护内存的指针，失败时返回 NULL。
 */
void* secure_alloc(size_t size);

/**
 * @brief 释放并安全地擦除一块受保护的内存。
 * @param ptr 指向由 secure_alloc 分配的内存的指针。
 */
void secure_free(void* ptr);

/**
 * @brief 安全地擦除（置零）一块内存区域。
 * @param ptr 指向要擦除的内存区域的指针。
 * @param len 要擦除的字节数。
 */
void secure_zero_memory(void* ptr, size_t len);

#endif // SECURE_MEMORY_H