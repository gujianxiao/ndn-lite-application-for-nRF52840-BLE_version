
#include "app-init-files/app_definitions.h"
#include "app-init-files/app_initialization_functions.h"

#include "print-helper.h"

// includes for nrf sdk
#include "nrf_crypto.h"

// includes for sign on client ble
#include "../../adaptation/app-support-adaptation/secure-sign-on-nrf-sdk-ble/sign-on-basic-client-nrf-sdk-ble.h" // sign on basic client implemented with nrf sdk ble
#include "sign-on-basic-credentials.h" // hardcoded credentials for the sign on basic client

// includes for adaptation between ndn-lite and nrf sdk
#include "../../adaptation/ndn-lite-over-nrf-sdk-init.h"
#include "../../adaptation/face/ndn-nrf-ble-face.h" // ndn-lite ble face using nrf sdk ble as a backend
#include "../../adaptation/security/ndn-lite-nrf-crypto-sec-config.h" // security configuration for nrf-sdk-specific security functions

// includes for ndn lite library
#include "../../ndn-lite/encode/data.h"
#include "../../ndn-lite/encode/encoder.h"
#include "../../ndn-lite/encode/interest.h"
#include "../../ndn-lite/forwarder/forwarder.h"
#include "../../ndn-lite/security/ndn-lite-sec-utils.h"
#include "../../ndn-lite/util/uniform-time.h"

// includes for manipulating led's timers with nrf sdk
#include "nrf-sdk-led.h"

// defines for ndn standalone library
uint16_t m_face_id_ble = 3;
ndn_nrf_ble_face_t *m_ndn_nrf_ble_face;

// Callback for when sign on has completed.
void m_on_sign_on_completed_callback(int result_code) {
  APP_LOG("in main, m_on_sign_on_completed_callback got called.\n");

  if (result_code == NDN_SUCCESS) {
    APP_LOG("Sign on completed succesfully.\n");
    blink_led(3);
    APP_LOG("Value of KD pri after completing sign on:\n");
    for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pri_len; i++) {
      APP_LOG("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pri_p[i]);
    }
    APP_LOG("\n");

    APP_LOG("Value of KD pub cert after completing sign on:\n");
    for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pub_cert_len; i++) {
      APP_LOG("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pub_cert_p[i]);
    }
    APP_LOG("\n");

    APP_LOG("Value of trust anchor cert after completing sign on:\n");
    for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->trust_anchor_cert_len; i++) {
      APP_LOG("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->trust_anchor_cert_p[i]);
    }
    APP_LOG("\n");

    // Create the name of the certificate to send an interest for.
    ndn_name_t dummy_interest_name;
    char dummy_interest_name_string[] = "/sign-on/cert/010101010101010101010101";
    ndn_name_from_string(&dummy_interest_name, dummy_interest_name_string, strlen(dummy_interest_name_string));

    // Create an interest, set its name to the certificate name.
    ndn_interest_t dummy_interest;
    ndn_interest_from_name(&dummy_interest, &dummy_interest_name);

    APP_LOG("Finished initializing the dummy interest.\n");

    // Initialize the interest encoder.
    ndn_encoder_t interest_encoder;
    uint32_t encoded_interest_max_size = 500;
    uint8_t encoded_interest_buf[encoded_interest_max_size];
    encoder_init(&interest_encoder, encoded_interest_buf, encoded_interest_max_size);

    APP_LOG("Finished initializing the interest encoder.\n");

    // TLV encode the interest.
    ndn_interest_tlv_encode(&interest_encoder, &dummy_interest);

    APP_LOG("Finished encoding the ndn interest.\n");
    APP_LOG_HEX("Encoded interest:", interest_encoder.output_value, interest_encoder.offset);

    //  // Express the encoded interest for the certificate.
    //  ndn_direct_face_express_interest(
    //      &dummy_interest_name,
    //      interest_encoder.output_value,
    //      interest_encoder.offset,
    //      m_on_data_callback,
    //      m_interest_timeout_callback);
  } else {
    APP_LOG("Sign on failed, error code: %d\n", result_code);
  }
}

////timeout do nothing
//int on_interest_timeout_callback(const uint8_t *interest, uint32_t interest_size) {
//  (void)interest;
//  (void)interest_size;
//  blink_led(interest_size);
//  return 0;
//}
//// data back do nothing
//int on_data_callback(const uint8_t *data, uint32_t data_size) {
//  (void)data;
//  (void)data_size;
//  return 0;
//}

APP_TIMER_DEF(m_ndn_lite_timer_id);

/**@brief Timeout handler for the ndn lite timer
 */
static void repeated_timer_handler(void * p_context)
{
    printf("The ndn lite timer reached its maximum count and reset.\n");
}

/**@brief Function for application main entry.
 */
int main(void) {

  APP_LOG("Entered main function of main_board1.c\n");

  ndn_lite_over_nrf_sdk_startup();

  ret_code_t err_code;

  //initialize the button and LED
  nrf_gpio_cfg_output(BSP_LED_0);                    //BSP_LED_0 is pin 13 in the nRF52840-DK. Configure pin 13 as standard output.
  nrf_gpio_cfg_input(BUTTON_1, NRF_GPIO_PIN_PULLUP); // Configure pin 11 as standard input with a pull up resister.
  nrf_gpio_cfg_input(BUTTON_2, NRF_GPIO_PIN_PULLUP); // Configure pin 12 as standard input with a pull up resister.
  nrf_gpio_cfg_input(BUTTON_3, NRF_GPIO_PIN_PULLUP); // Configure pin 12 as standard input with a pull up resister.
  nrf_gpio_pin_write(BSP_LED_0, 1);                  // Turn off LED1 (Active Low)

  // Initialize the log.
  log_init();

  // Initialize timers.
  timers_init();

  // Initialize power management.
  power_management_init();

  // Initialize the sign on client.
  sign_on_basic_client_nrf_sdk_ble_construct(
      SIGN_ON_BASIC_VARIANT_ECC_256,
      DEVICE_IDENTIFIER, sizeof(DEVICE_IDENTIFIER),
      DEVICE_CAPABILITIES, sizeof(DEVICE_CAPABILITIES),
      SECURE_SIGN_ON_CODE,
      BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER, sizeof(BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER),
      BOOTSTRAP_ECC_PRIVATE, sizeof(BOOTSTRAP_ECC_PRIVATE),
      m_on_sign_on_completed_callback);

  err_code = app_timer_init();
  APP_ERROR_CHECK(err_code);
  err_code = app_timer_create(&m_ndn_lite_timer_id,
                              APP_TIMER_MODE_REPEATED,
                              repeated_timer_handler);
  APP_ERROR_CHECK(err_code);
  err_code = app_timer_start(m_ndn_lite_timer_id, 0xFFFFFFFF, NULL);
  APP_ERROR_CHECK(err_code);

  for (int i = 0; i < 1000; i++) {
    printf("inside init function: %d\n", app_timer_cnt_get());
  }
  printf("done\n");

//
//  APP_LOG("Secure sign-on application successfully started.\n");
//
//  // Create the name for the certificate that we will have after sign-on.
//  ndn_name_t dummy_interest_name;
//  char dummy_interest_name_string[] = "/sign-on/cert/010101010101010101010101";
//  ndn_name_from_string(&dummy_interest_name, dummy_interest_name_string, strlen(dummy_interest_name_string));
//
//  // Create a ble face; the interest expressed will be sent through this face.
//  m_ndn_nrf_ble_face = ndn_nrf_ble_face_construct(m_face_id_ble);
//  m_ndn_nrf_ble_face->intf.state = NDN_FACE_STATE_UP;
//
//  // Insert the ble face into the forwarding information base with the certificate's name,
//  // so that the direct face's interest gets routed to this ble face
//  int ret;
//  if ((ret = ndn_forwarder_fib_insert(&dummy_interest_name, &m_ndn_nrf_ble_face->intf, 0)) != 0) {
//    APP_LOG("Problem inserting fib entry, error code %d\n", ret);
//  }
//
//  APP_LOG("Device bootstrapping: Finished creating ble face and inserting it into FIB.\n");
//
//  // Create a direct face, which we will use to send the interest for our certificate after sign on.
//  m_face = ndn_direct_face_construct(m_face_id_direct);
//
//  APP_LOG("Device bootstrapping: Finished constructing the direct face.\n");
//
////regeist the prefix to listen for the command of trust policy
//#ifdef BOARD_1
//  char schema_string[] = "/NDN-IoT/TrustChange/Board1";
//#endif
//#ifdef BOARD_2
//  char schema_string[] = "/NDN-IoT/TrustChange/Board2";
//#endif
//  ndn_name_t schema_prefix;
//  ndn_name_from_string(&schema_prefix, schema_string, sizeof(schema_string));
//  ndn_direct_face_register_prefix(&schema_prefix, on_trustInterest);
//
////regeist the prefix to listen for the command of turning on LED
//#ifdef BOARD_1
//  char CMD_string[] = "/NDN-IoT/Board1";
//#endif
//#ifdef BOARD_2
//  char CMD_string[] = "/NDN-IoT/Board2";
//#endif
//  ndn_name_t CMD_prefix;
//  ndn_name_from_string(&CMD_prefix, CMD_string, sizeof(CMD_string));
//  ndn_direct_face_register_prefix(&CMD_prefix, on_CMDInterest);
//
//  //register route for sending interest
//  char prefix_string[] = "/NDN-IoT";
//  ndn_name_t prefix;
//  ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
//
//  if ((ret = ndn_forwarder_fib_insert(&prefix, &m_ndn_nrf_ble_face->intf, 0)) != 0) {
//    APP_LOG("Problem inserting fib entry, error code %d\n", ret);
//  }
//
//  blink_led(3);
//
//  // Enter main loop.
//  for (;;) {
//    if (nrf_gpio_pin_read(BUTTON_1) == 0 && schematrust_flag) { // If button 1 is pressed (Active Low)
//      nrf_gpio_pin_write(BSP_LED_0, 0);                         // Turn on LED
//      APP_LOG("Button 1 pressed. schematrust_flag is %d\n", schematrust_flag);
//      nrf_delay_ms(100); // for debouncing
//    }
//    if (nrf_gpio_pin_read(BUTTON_2) == 0) { // If button 2 is pressed (Active Low)
//      nrf_gpio_pin_write(BSP_LED_0, 1);     // Turn off LED
//      APP_LOG("Button 2 pressed.schematrust_flag is %d\n", schematrust_flag);
//      nrf_delay_ms(100); // for debouncing
//    }
//    if (nrf_gpio_pin_read(BUTTON_3) == 0) { // If button 2 is pressed (Active Low)
//      //send Interest here
//      APP_LOG("Button 3 pressed. start to send Interest of turn on LED\n");
//      //construct interest
//      ndn_interest_t interest;
//      ndn_interest_init(&interest);
//#ifdef BOARD_1
//      char name_string[] = "/NDN-IoT/Board2/SD_LED/ON";
//#endif
//#ifdef BOARD_2
//      char name_string[] = "/NDN-IoT/Board1/SD_LED/ON";
//#endif
//      ndn_name_from_string(&interest.name, name_string, sizeof(name_string));
//      uint8_t interest_block[256] = {0};
//      ndn_encoder_t encoder;
//      encoder_init(&encoder, interest_block, 256);
//      ndn_interest_tlv_encode(&encoder, &interest);
//      //send interest
//      ndn_direct_face_express_interest(&interest.name,
//          interest_block, encoder.offset,
//          on_data_callback, on_interest_timeout_callback);
//      ndn_face_send(&m_ndn_nrf_ble_face->intf, &interest.name, interest_block, encoder.offset);
//      nrf_delay_ms(100); // for debouncing
//    }
//    //    idle_state_handle();
//  }
}

/**
 * @}
 */