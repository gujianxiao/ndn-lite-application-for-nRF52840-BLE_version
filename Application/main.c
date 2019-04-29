
// includes for nrf sdk
#include "nrf_crypto.h"
#include "app-init/app_definitions.h"
#include "app-init/app_initialization_functions.h"

#include "util/print-helper.h"

// includes for manipulating led's timers with nrf sdk
#include "nrf-sdk-led/nrf-sdk-led.h"

// includes for sign on client ble
#include "../../adaptation/app-support-adaptation/secure-sign-on-nrf-sdk-ble/sign-on-basic-client-nrf-sdk-ble.h" // sign on basic client implemented with nrf sdk ble
#include "ndn-sign-on/sign-on-basic-credentials.h" // hardcoded credentials for the sign on basic client

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

#define ENCODER_BUFFER_SIZE 500

int m_sign_on_completed = false;

// defines for ndn standalone library
int schema_trust_flag = 1;
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
ndn_encoder_t m_other_device_certificates_prefix_encoder;
uint8_t m_other_device_certificates_prefix_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_encoder_t m_phone_interest_prefix_encoder; // encoder for the prefix we register with forwarder to get interest from phone
uint8_t m_phone_interest_prefix_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_encoder_t m_phone_interest_response_encoder; // encoder for the data packet we send in response to interest from phone
uint8_t m_phone_interest_response_encoded_buffer[ENCODER_BUFFER_SIZE];
ndn_interest_t m_phone_interest; // interest we get from phone

void on_interest_timeout(void *userdata) {
  APP_LOG("on_interest_timeout was triggered.\n");
}

void on_data(const uint8_t *data, uint32_t data_size, void *userdata) {
  APP_LOG("on_data was triggered.\n");
}

int on_phone_interest(const uint8_t* interest, uint32_t interest_size, void *userdata) {
  APP_LOG("on_phone_interest was triggered.\n");
  APP_LOG_HEX("bytes of interest received from phone:", interest, interest_size);

  int ret_val = -1;

  ret_val = ndn_interest_from_block(&m_phone_interest, interest, interest_size);
  if (ret_val != 0) {
    APP_LOG("Error in on_phone_interest, ndn_interest_from_block, ret val: %d\n", ret_val);
    return -1;
  }

  ndn_data_t phone_response_data;
  ndn_data_init(&phone_response_data);

  ret_val = ndn_name_init(&phone_response_data.name, m_phone_interest.name.components, m_phone_interest.name.components_size);
  if (ret_val != 0) {
    APP_LOG("Error in on_phone_interest, ndn_name_init, ret val: %d\n", ret_val);
    return -1;
  }
  printf("Name of response data: "); ndn_name_print(&phone_response_data.name);
  
  uint8_t random_content[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  ret_val = ndn_data_set_content(&phone_response_data, random_content, sizeof(random_content));
  if (ret_val != 0) {
    APP_LOG("Error in on_phone_interest, ndn_data_set_content, ret val: %d\n", ret_val);
    return -1;
  }

  encoder_init(&m_phone_interest_response_encoder, m_phone_interest_response_encoded_buffer,
    sizeof(m_phone_interest_response_encoded_buffer));

  ret_val = ndn_data_tlv_encode_digest_sign(&m_phone_interest_response_encoder, &phone_response_data);
  if (ret_val != 0) {
    APP_LOG("Error in on_phone_interest, ndn_data_tlv_encode_digest_sign, ret val: %d\n", ret_val);
    return -1;
  }

  ret_val = ndn_forwarder_put_data(m_phone_interest_response_encoder.output_value, 
                                   m_phone_interest_response_encoder.offset);
  if (ret_val != 0) {
    APP_LOG("Error in on_phone_interest, ndn_forwarder_put_data, ret val: %d\n", ret_val);
    return -1;
  }

}

// Callback for when sign on has completed.
void on_sign_on_completed(int result_code) {
  APP_LOG("on_sign_on_completed was triggered.\n");

  if (result_code == NDN_SUCCESS) {
    APP_LOG("Sign on completed succesfully.\n");
    m_sign_on_completed = true;

    int ret_val = -1;

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

  // Initialize the ndn lite forwarder
  ndn_forwarder_init();

  // Create name to allow device to send interest to phone for other device's certificates
  ndn_name_t other_device_certificates_prefix;
  char other_device_certificates_prefix_string[] = "/sign-on/cert";
  ndn_name_from_string(&other_device_certificates_prefix, other_device_certificates_prefix_string, 
    strlen(other_device_certificates_prefix_string));
  // encode the prefix for other device's certificates so that it can be added as route to forwarder
  encoder_init(&m_other_device_certificates_prefix_encoder, m_other_device_certificates_prefix_encoded_buffer,
               sizeof(m_other_device_certificates_prefix_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_other_device_certificates_prefix_encoder, &other_device_certificates_prefix);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }

  // Create a ble face; the interests expressed to phone for other device's certificates will be sent through this face.
  m_ndn_nrf_ble_face = ndn_nrf_ble_face_construct(m_face_id_ble);
  m_ndn_nrf_ble_face->intf.state = NDN_FACE_STATE_UP;

  // Insert the ble face into the forwarding information base with the certificate's name, 
  // so that the direct face's interest gets routed to this ble face
  if ((ret_val = ndn_forwarder_add_route(&m_ndn_nrf_ble_face->intf, m_other_device_certificates_prefix_encoder.output_value,
                                          m_other_device_certificates_prefix_encoder.offset)) != 0) {
    printf("Problem inserting fib entry for ble face to phone, error code %d\n", ret_val);
    return -1;
  }

  printf("Device bootstrapping: Finished creating ble face and inserting it into FIB.\n");

  // Register prefix to listen for interest from phone
  char phone_test_interest_prefix_string[] = "/phone/test/interest";
  ndn_name_t phone_test_interest_prefix;
  ret_val = ndn_name_from_string(&phone_test_interest_prefix, phone_test_interest_prefix_string, 
    sizeof(phone_test_interest_prefix_string));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_from_string failed, error code: %d\n", ret_val);
    return -1;
  }
  // encode the phone interest prefix so that it can be registered with forwarder
  encoder_init(&m_phone_interest_prefix_encoder, m_phone_interest_prefix_encoded_buffer,
               sizeof(m_phone_interest_prefix_encoded_buffer));
  ret_val = ndn_name_tlv_encode(&m_phone_interest_prefix_encoder, &phone_test_interest_prefix);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_name_tlv_encode failed, error code: %d\n", ret_val);
    return -1;
  }
  ret_val = ndn_forwarder_register_prefix(m_phone_interest_prefix_encoder.output_value, m_phone_interest_prefix_encoder.offset,
                                on_phone_interest, NULL);
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_forwarder_register_prefix failed, error code: %d\n", ret_val);
    return -1;
  }

  printf("Device bootstrapping: Finished constructing the direct face.\n");

  // Enter main loop.
  for (;;) {
  }
}