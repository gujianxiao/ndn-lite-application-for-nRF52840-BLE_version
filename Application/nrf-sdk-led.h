
#ifndef NRF_SDK_LED_H
#define NRF_SDK_LED_H

// includes for nrf sdk
#include "nrf_delay.h" // For basic delaying functions
#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "pca10056.h" // GPIO definitions for the nRF52840-DK (aka pca10056)

extern const uint32_t led;

extern const nrfx_gpiote_out_config_t led_config;

void nop(void);

void blink_led(int i);

#endif // NRF_SDK_LED_H