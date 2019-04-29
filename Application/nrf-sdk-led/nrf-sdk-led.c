
#include "nrf-sdk-led.h"

const uint32_t led = NRF_GPIO_PIN_MAP(0, 13);

const nrfx_gpiote_out_config_t led_config = {
    .init_state = GPIOTE_CONFIG_OUTINIT_Low,
    .task_pin = false};

void nop(void) {
  __asm__ __volatile__("nop" ::
                           :);
}

void blink_led(int i) {
  const uint32_t pin = NRF_GPIO_PIN_MAP(0, 12 + i); // LED
  nrf_gpio_cfg_output(pin);

  int counter = 0;
  while (counter < 10) {
    nrf_gpio_pin_toggle(pin);
    for (uint32_t i = 0; i < 0x320000; ++i)
      nop();
    counter++;
  }
}