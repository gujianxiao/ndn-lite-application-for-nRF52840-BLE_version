
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

#define ENCODER_BUFFER_SIZE 500

// defines for ndn standalone library
int schema_trust_flag = 0;
uint16_t m_face_id_ble = 3;
ndn_nrf_ble_face_t *m_ndn_nrf_ble_face;
ndn_encoder_t m_sign_on_interest_name_encoder;
uint8_t m_sign_on_interest_name_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_encoder_t m_schema_prefix_encoder;
uint8_t m_schema_prefix_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_encoder_t m_led_cmd_prefix_encoder;
uint8_t m_led_cmd_prefix_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_encoder_t m_board_to_board_prefix_encoder;
uint8_t m_board_to_board_prefix_encoded_buffer[ENCODER_BUFFER_SIZE];

int on_schema_interest(const uint8_t* interest, uint32_t interest_size, void *userdata)
{
  printf("on_schema_interest was triggered.\n");

  blink_led(3);
  //initiate the name prefix of different interest here
  ndn_name_t schema_prefix;
  ndn_name_t schema_prefix2;
#ifdef BOARD_1
  char schema_string[] = "/NDN-IoT/TrustChange/Board1/ControllerOnly";
  char schema_string2[] = "/NDN-IoT/TrustChange/Board1/AllNode";
#endif
#ifdef BOARD_2
  char schema_string[] = "/NDN-IoT/TrustChange/Board2/ControllerOnly";
  char schema_string2[] = "/NDN-IoT/TrustChange/Board2/AllNode";
#endif
  ndn_name_from_string(&schema_prefix, schema_string, sizeof(schema_string));
  ndn_name_from_string(&schema_prefix2, schema_string2, sizeof(schema_string2));

  ndn_interest_t check_interest;
  int result = ndn_interest_from_block(&check_interest, interest, interest_size);
  printf("compare results of controller only: %d\n", ndn_name_compare(&schema_prefix, &check_interest.name));
  printf("compare results of all nodes: %d\n", ndn_name_compare(&schema_prefix2, &check_interest.name));

  if (ndn_name_compare(&check_interest.name, &schema_prefix)==0){
    printf("Received an interest to change the board's trust policy to \"controller\" trust policy.\n");
    schema_trust_flag = 0;
    blink_led(4);
  }

  if (ndn_name_compare(&check_interest.name,&schema_prefix2)==0){
    printf("Received an interest to change board's trust policy to \"all boards\" trust policy.\n");
    schema_trust_flag = 1;
    blink_led(4);
  }
}

int on_led_cmd_interest(const uint8_t* interest, uint32_t interest_size, void *userdata)
{
  printf("on_cmd_interest was triggered.\n");

  //initiate the name prefix of different interest here
  ndn_name_t led_cmd_prefix;
#ifdef BOARD_1
  char led_cmd_string[] = "/NDN-IoT/Board1/SD_LED/ON";
#endif
#ifdef BOARD_2
  char led_cmd_string[] = "/NDN-IoT/Board2/SD_LED/ON";
#endif
  ndn_name_from_string(&led_cmd_prefix, led_cmd_string, sizeof(led_cmd_string));

  ndn_interest_t check_interest;
  int result = ndn_interest_from_block(&check_interest, interest, interest_size);

  if (ndn_name_compare(&check_interest.name,&led_cmd_prefix) == 0){
    printf("Received a command interest to turn on LED.\n");
		
    if (schema_trust_flag) {
      blink_led(1);
      printf("Finished blinking led 2.");
    }	
  }
}

void on_interest_timeout(void *userdata) {
  APP_LOG("on_interest_timeout was triggered.\n");
}

void on_data(const uint8_t *data, uint32_t data_size, void *userdata) {
  APP_LOG("on_data was triggered.\n");
}

// Callback for when sign on has completed.
void on_sign_on_completed(int result_code) {
  APP_LOG("on_sign_on_completed was triggered.\n");

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

    // Express the encoded interest for the certificate.
    ndn_forwarder_express_interest(
         interest_encoder.output_value,
         interest_encoder.offset,
         on_data,
         on_interest_timeout,
         NULL);

  } else {
    APP_LOG("Sign on failed, error code: %d\n", result_code);
  }
}

/**@brief Function for application main entry.
 */
int main(void) {

  APP_LOG("BLE example started (%s)\n", EXAMPLE_BOARD_NAME);

  ndn_lite_over_nrf_sdk_startup();

  int ret_val;

  //initialize the button and LED
  nrf_gpio_cfg_output(BSP_LED_0);                    // BSP_LED_0 is pin 13 in the nRF52840-DK. Configure pin 13 as standard output.
  nrf_gpio_cfg_input(BUTTON_1, NRF_GPIO_PIN_PULLUP); // Configure pin 11 as standard input with a pull up resister.
  nrf_gpio_cfg_input(BUTTON_2, NRF_GPIO_PIN_PULLUP); // Configure pin 12 as standard input with a pull up resister.
  nrf_gpio_cfg_input(BUTTON_3, NRF_GPIO_PIN_PULLUP); // Configure pin 12 as standard input with a pull up resister.
  nrf_gpio_pin_write(BSP_LED_0, 1);                  // Turn off LED1 (Active Low)

  // Initialize the log.
  log_init();

  // Initialize power management.
  power_management_init();

  // Initialize the sign on client.
  ret_val = sign_on_basic_client_nrf_sdk_ble_construct(
              SIGN_ON_BASIC_VARIANT_ECC_256,
              DEVICE_IDENTIFIER, sizeof(DEVICE_IDENTIFIER),
              DEVICE_CAPABILITIES, sizeof(DEVICE_CAPABILITIES),
              SECURE_SIGN_ON_CODE,
              BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER, sizeof(BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER),
              BOOTSTRAP_ECC_PRIVATE, sizeof(BOOTSTRAP_ECC_PRIVATE),
              on_sign_on_completed);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("Initialization of sign-on-basic client failed, error code: %d\n", ret_val);
    return -1;
  }

  APP_LOG("Initialization of BLE example done.\n");

  // Create the name for the sign-on interest / name of certificate that we will have after sign-on.
  ndn_name_t sign_on_interest_name;
  char sign_on_interest_name_string[] = "/sign-on/cert/010101010101010101010101";
  ret_val = ndn_name_from_string(&sign_on_interest_name, sign_on_interest_name_string, strlen(sign_on_interest_name_string));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_from_string failed, error code: %d\n", ret_val);
    return -1;
  }

  // Encode the sign-on interest name so it can be added to fib
  encoder_init(&m_sign_on_interest_name_encoder, m_sign_on_interest_name_encoded_buffer,
               sizeof(m_sign_on_interest_name_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_sign_on_interest_name_encoder, &sign_on_interest_name);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }

  // Create a ble face; the interest expressed will be sent through this face.
  m_ndn_nrf_ble_face = ndn_nrf_ble_face_construct(m_face_id_ble);
  m_ndn_nrf_ble_face->intf.state = NDN_FACE_STATE_UP;

  // Insert the ble face into the forwarding information base with the certificate's name,
  // so that the direct face's interest gets routed to this ble face
  if ((ret_val = ndn_forwarder_add_route(&m_ndn_nrf_ble_face->intf, m_sign_on_interest_name_encoder.output_value, 
                                     m_sign_on_interest_name_encoder.offset)) != 0) {
    APP_LOG("Problem inserting fib entry, error code: %d\n", ret_val);
    return -1;
  }

  APP_LOG("Finished creating ble face and inserting it into FIB.\n");
  APP_LOG("Route added for ble face, in order to send sign on interest to phone: ");
  for (int i = 0; i < sign_on_interest_name.components_size; i++) {
    APP_LOG("/%.*s", sign_on_interest_name.components[i].size, sign_on_interest_name.components[i].value);
  }
  APP_LOG("\n");

  // Register prefix to listen for interests to change trust policy
#ifdef BOARD_1
  char schema_string[] = "/NDN-IoT/TrustChange/Board1";
#endif
#ifdef BOARD_2
  char schema_string[] = "/NDN-IoT/TrustChange/Board2";
#endif
  ndn_name_t schema_prefix;
  ret_val = ndn_name_from_string(&schema_prefix, schema_string, sizeof(schema_string));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_from_string failed, error code: %d\n", ret_val);
    return -1;
  }
  // encode the schema prefix so that it can be registered with forwarder
  encoder_init(&m_schema_prefix_encoder, m_schema_prefix_encoded_buffer,
               sizeof(m_schema_prefix_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_schema_prefix_encoder, &schema_prefix);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }
  ret_val = ndn_forwarder_register_prefix(m_schema_prefix_encoder.output_value, m_schema_prefix_encoder.offset,
                                on_schema_interest, NULL);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_forwarder_register_prefix failed, error code: %d\n", ret_val);
    return -1;
  }

  APP_LOG("Finished registering prefix for interests to change trust policy.\n");
  APP_LOG("Prefix registered: ");
  for (int i = 0; i < schema_prefix.components_size; i++) {
    APP_LOG("/%.*s", schema_prefix.components[i].size, schema_prefix.components[i].value);
  }
  APP_LOG("\n");

  // Register prefix to listen for interests to turn on an LED
#ifdef BOARD_1
  char led_cmd_string[] = "/NDN-IoT/Board1";
#endif
#ifdef BOARD_2
  char led_cmd_string[] = "/NDN-IoT/Board2";
#endif
  ndn_name_t led_cmd_prefix;
  ret_val = ndn_name_from_string(&led_cmd_prefix, led_cmd_string, sizeof(led_cmd_string));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_from_string failed, error code: %d\n", ret_val);
    return -1;
  }
  encoder_init(&m_led_cmd_prefix_encoder, m_led_cmd_prefix_encoded_buffer,
               sizeof(m_led_cmd_prefix_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_led_cmd_prefix_encoder, &led_cmd_prefix);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }
  ret_val = ndn_forwarder_register_prefix(m_led_cmd_prefix_encoder.output_value, m_led_cmd_prefix_encoder.offset,
                                  on_led_cmd_interest, NULL);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_forwarder_register_prefix failed, error code: %d\n", ret_val);
    return -1;
  }

  APP_LOG("Finished registering prefix for interests to turn on led.\n");
  APP_LOG("Prefix registered: ");
  for (int i = 0; i < led_cmd_prefix.components_size; i++) {
    APP_LOG("/%.*s", led_cmd_prefix.components[i].size, led_cmd_prefix.components[i].value);
  }
  APP_LOG("\n");

  // Register route for sending interest to other boards
  char board_to_board_prefix_string[] = "/NDN-IoT";
  ndn_name_t board_to_board_prefix;
  ret_val = ndn_name_from_string(&board_to_board_prefix, board_to_board_prefix_string, 
                       sizeof(board_to_board_prefix_string));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_from_string failed, error code: %d\n", ret_val);
    return -1;
  }
  encoder_init(&m_board_to_board_prefix_encoder, m_board_to_board_prefix_encoded_buffer,
               sizeof(m_board_to_board_prefix_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_board_to_board_prefix_encoder, &board_to_board_prefix);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }
  if ((ret_val = ndn_forwarder_add_route(&m_ndn_nrf_ble_face->intf, m_board_to_board_prefix_encoder.output_value, 
                                     m_board_to_board_prefix_encoder.offset)) != 0) {
    APP_LOG("Problem inserting fib entry, error code: %d\n", ret_val);
    return -1;
  }

  APP_LOG("Finished adding route for board to send interests to other boards through ble face.\n");
  APP_LOG("Route added: ");
  for (int i = 0; i < board_to_board_prefix.components_size; i++) {
    APP_LOG("/%.*s", board_to_board_prefix.components[i].size, board_to_board_prefix.components[i].value);
  }
  APP_LOG("\n");

  blink_led(3);
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