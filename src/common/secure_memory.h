/**
 * @file secure_memory.h
 * @brief 提供用于处理密钥等敏感数据的安全内存分配和管理功能。
 *
 * @details
 * 这是一个至关重要的安全模块，旨在最小化敏感数据在内存中的暴露风险。
 * 直接使用 `malloc` 处理密钥等机密信息是危险的，因为操作系统可能会在不经意间
 * 将该内存页交换到磁盘上的交换文件(swap file)中，导致密钥持久化。
 *
 * 本模块提供的函数是对 libsodium 安全内存功能的封装，提供了以下保护：
 * 1.  **内存锁定 (Memory Locking)**: 分配的内存会被锁定（使用 mlock/VirtualLock），
 *     阻止操作系统将其写入磁盘。
 * 2.  **边界保护 (Guard Pages)**: 在分配区域的前后设置受保护的内存页，
 *     有助于检测缓冲区溢出。
 * 3.  **金丝雀值 (Canary)**: 在数据旁边放置一个秘密值，如果发生溢出，该值会被破坏，
 *     从而在内存被释放时检测到损坏。
 * 4.  **自动擦除**: `secure_free` 会在释放内存前，使用 `sodium_memzero`
 *     自动、安全地用零覆盖内存内容。
 */

#ifndef SECURE_MEMORY_H
#define SECURE_MEMORY_H

#include <stddef.h>

/**
 * @brief 分配一块受保护的、不可交换到磁盘的内存。
 *
 * @param[in] size 要分配的字节数。
 * @return 成功时返回指向受保护内存的指针，内存内容未初始化。
 *         如果内存分配失败，返回 NULL。
 */
void* secure_alloc(size_t size);

/**
 * @brief 安全地擦除并释放一块由 `secure_alloc` 分配的受保护内存。
 *
 * @param[in] ptr 指向由 secure_alloc 分配的内存的指针。如果 ptr 为 NULL，
 *                函数不执行任何操作。
 */
void secure_free(void* ptr);

/**
 * @brief 以恒定时间的方式安全地擦除（置零）一块内存区域。
 * @details
 * 使用 `sodium_memzero`，它可以防止聪明的编译器因发现写入的变量后续未被使用
 * 而将清零操作优化掉。
 *
 * @param[in] ptr 指向要擦除的内存区域的指针。
 * @param[in] len 要擦除的字节数。
 */
void secure_zero_memory(void* ptr, size_t len);

#endif // SECURE_MEMORY_H