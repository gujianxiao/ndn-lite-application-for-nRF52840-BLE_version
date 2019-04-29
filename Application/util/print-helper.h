
#ifndef PRINT_HELPER_H
#define PRINT_HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define APP_LOG(...) printf(__VA_ARGS__)

void APP_LOG_HEX(const char *msg, const uint8_t *buf, size_t buf_len);

#endif // PRINT_HELPER_H