
#include "print-helper.h"

void APP_LOG_HEX(const char *msg, const uint8_t *buf, size_t buf_len) {
  APP_LOG(msg);
  APP_LOG("\n");
  int i;
  for (i = 0; i < buf_len; i++)
  {
    //if (i > 0) APP_LOG(":");
    APP_LOG("%02X", buf[i]);
  }
  APP_LOG("\n");
}