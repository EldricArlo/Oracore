#ifndef INTERNAL_LOGGER_H
#define INTERNAL_LOGGER_H

// 日志级别，与 hsc_kernel.h 中定义的公共回调函数类型保持一致
#define HSC_LOG_LEVEL_INFO 0
#define HSC_LOG_LEVEL_WARN 1
#define HSC_LOG_LEVEL_ERROR 2

/**
 * @brief 内部日志记录函数。
 * 这是一个可变参数函数，它将格式化消息并将其传递给已注册的用户回调函数。
 * 这个函数本身将在 hsc_kernel.c 中实现。
 *
 * @param level 日志级别 (HSC_LOG_LEVEL_...)。
 * @param format 类似 printf 的格式化字符串。
 * @param ... 格式化字符串的参数。
 */
void _hsc_log(int level, const char* format, ...);

#endif // INTERNAL_LOGGER_H
