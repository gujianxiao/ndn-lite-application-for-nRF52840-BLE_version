
#include "app-init-files/app_definitions.h"
#include "app-init-files/app_initialization_functions.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"

// includes for sign on client ble
#include "hardcoded-experimentation.h"
#include "ndn_standalone/app-support/bootstrapping.h"

// includes for ndn standalone library
#include "ndn_standalone/encode/data.h"
#include "ndn_standalone/encode/encoder.h"
#include "ndn_standalone/encode/interest.h"
#include "ndn_standalone/face/direct-face.h"
#include "ndn_standalone/face/ndn-nrf-ble-face.h"
#include "ndn_standalone/forwarder/forwarder.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"


#include "nrf_gpio.h"
#include "nrfx_gpiote.h"
#include "nrf_delay.h"   //For basic delaying functions
#include "pca10056.h"    //GPIO definitions for the nRF52840-DK (aka pca10056)

static uint8_t schematrust_flag=1;

static const uint32_t led = NRF_GPIO_PIN_MAP(0,13);

static const nrfx_gpiote_out_config_t led_config = {
  .init_state = GPIOTE_CONFIG_OUTINIT_Low,
  .task_pin = false
};

static void nop(void)
{
  __asm__ __volatile__("nop":::);
}

static void blink_led(int i) {
  const uint32_t pin = NRF_GPIO_PIN_MAP(0,12 + i); // LED
  nrf_gpio_cfg_output(pin);

  int counter = 0;
  while (counter < 10) {
    nrf_gpio_pin_toggle(pin);
    for(uint32_t i = 0; i < 0x320000; ++i)
      nop();
    counter++;
  }
}


// defines for ndn standalone library
ndn_direct_face_t *m_face;
uint16_t m_face_id_direct = 2;
uint16_t m_face_id_ble = 3;
ndn_nrf_ble_face_t *m_ndn_nrf_ble_face;

// Callback for when interest for certificate times out.
int m_interest_timeout_callback(const uint8_t *interest, uint32_t interest_size) {
  printf("Interest timeout callback was triggered.\n");
  return 0;
}

// Callback for when we receive data for the interest we send for the certificate.
int m_on_data_callback(const uint8_t *data, uint32_t data_size) {
  printf("On data callback was triggered.\n");

  ndn_data_t recvd_data;

  // Commented this out until the security implementation in ndn standalone is
  // made generic to prevent conflicts of security libraries.
  // The call to ndn_data_tlv_decode_digest_verify depends on the security
  // implementation inside of ndn-lite, which is why I have it commented out here.
//  if (ndn_data_tlv_decode_digest_verify(&recvd_data, data, data_size)) {
//    printf("Successfully decoded received data.\n");
//  }

  return 0;
}

// Callback for when sign on has completed.
void m_on_sign_on_completed_callback(enum sign_on_basic_client_nrf_sdk_ble_completed_result result) {
  printf("in main, m_on_sign_on_completed_callback got called.\n");

  if (result == SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_COMPLETED_SUCCESS) {
    printf("Sign on completed succesfully.\n");
      blink_led(3);
  } else {
    printf("Sign on failed, error code: %d\n");
  }

  printf("Value of KD pri after completing sign on:\n");
  for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pri_len; i++) {
    printf("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pri_p[i]);
  }
  printf("\n");

  printf("Value of KD pub cert after completing sign on:\n");
  for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pub_cert_len; i++) {
    printf("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->KD_pub_cert_p[i]);
  }
  printf("\n");

  printf("Value of trust anchor cert after completing sign on:\n");
  for (int i = 0; i < get_sign_on_basic_client_nrf_sdk_ble_instance()->trust_anchor_cert_len; i++) {
    printf("%02x", get_sign_on_basic_client_nrf_sdk_ble_instance()->trust_anchor_cert_p[i]);
  }
  printf("\n");

  // Create the name of the certificate to send an interest for.
  ndn_name_t dummy_interest_name;
  char dummy_interest_name_string[] = "/sign-on/cert/010101010101010101010101";
  ndn_name_from_string(&dummy_interest_name, dummy_interest_name_string, strlen(dummy_interest_name_string));

  // Create an interest, set its name to the certificate name.
  ndn_interest_t dummy_interest;
  ndn_interest_from_name(&dummy_interest, &dummy_interest_name);

  printf("Finished initializing the dummy interest.\n");

  // Initialize the interest encoder.
  ndn_encoder_t interest_encoder;
  uint32_t encoded_interest_max_size = 500;
  uint8_t encoded_interest_buf[encoded_interest_max_size];
  encoder_init(&interest_encoder, encoded_interest_buf, encoded_interest_max_size);

  printf("Finished initializing the interest encoder.\n");

  // TLV encode the interest.
  ndn_interest_tlv_encode(&interest_encoder, &dummy_interest);

  printf("Finished encoding the ndn interest.\n");
  APP_LOG_HEX("Encoded interest:", interest_encoder.output_value, interest_encoder.offset);

  // Express the encoded interest for the certificate.
  ndn_direct_face_express_interest(
      &dummy_interest_name,
      interest_encoder.output_value,
      interest_encoder.offset,
      m_on_data_callback,
      m_interest_timeout_callback);
}

int on_trustInterest(const uint8_t* interest, uint32_t interest_size)
{
        printf("Get into on_trustInterest... Start to decode received Interest");
        blink_led(3);
	//initiate the name prefix of different interest here
        ndn_name_t schema_prefix;
        ndn_name_t schema_prefix2;
        char schema_string[] = "/NDN-IoT/TrustChange/Board1/ControllerOnly";
        char schema_string2[] = "/NDN-IoT/TrustChange/Board1/AlLNode";
  	ndn_name_from_string(&schema_prefix, schema_string, sizeof(schema_string));
        ndn_name_from_string(&schema_prefix2, schema_string2, sizeof(schema_string2));
        ndn_interest_t check_interest;
	int result = ndn_interest_from_block(&check_interest, interest, interest_size);
        if(ndn_name_compare(&check_interest.name,&schema_prefix)){
        printf("Get into on_trustInterest... Trust policy change to controller");
		schematrust_flag=0;
		blink_led(4);
	}
        if(ndn_name_compare(&check_interest.name,&schema_prefix2)){
        printf("Get into on_trustInterest... Trust policy change to all nodes");
		schematrust_flag=1;
		blink_led(4);
	}


}

/**@brief Function for application main entry.
 */
int main(void) {

//initialize the button and LED
    nrf_gpio_cfg_output(BSP_LED_0); //BSP_LED_0 is pin 13 in the nRF52840-DK. Configure pin 13 as standard output. 
    nrf_gpio_cfg_input(BUTTON_1,NRF_GPIO_PIN_PULLUP);// Configure pin 11 as standard input with a pull up resister. 
    nrf_gpio_cfg_input(BUTTON_2,NRF_GPIO_PIN_PULLUP);// Configure pin 12 as standard input with a pull up resister. 
    nrf_gpio_pin_write(BSP_LED_0,1); // Turn off LED1 (Active Low)

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

  ret_code_t err_code;

  // Initialize the crypto subsystem
  err_code = nrf_crypto_init();
  APP_ERROR_CHECK(err_code);

  printf("Secure sign-on application successfully started.\n");
  printf("Size of sign_on_basic_client_t structure: %d\n", sizeof(struct sign_on_basic_client_t));

  // Initialize the ndn lite forwarder
  ndn_forwarder_init();

  // Create the name for the certificate that we will have after sign-on.
  ndn_name_t dummy_interest_name;
  char dummy_interest_name_string[] = "/sign-on/cert/010101010101010101010101";
  ndn_name_from_string(&dummy_interest_name, dummy_interest_name_string, strlen(dummy_interest_name_string));

  // Create a ble face; the interest expressed will be sent through this face.
  m_ndn_nrf_ble_face = ndn_nrf_ble_face_construct(m_face_id_ble);
  m_ndn_nrf_ble_face->intf.state = NDN_FACE_STATE_UP;

  // Insert the ble face into the forwarding information base with the certificate's name, 
  // so that the direct face's interest gets routed to this ble face
  int ret;
  if ((ret = ndn_forwarder_fib_insert(&dummy_interest_name, &m_ndn_nrf_ble_face->intf, 0)) != 0) {
    printf("Problem inserting fib entry, error code %d\n", ret);
  }

  printf("Device bootstrapping: Finished creating ble face and inserting it into FIB.\n");

  // Create a direct face, which we will use to send the interest for our certificate after sign on.
  m_face = ndn_direct_face_construct(m_face_id_direct);

  printf("Device bootstrapping: Finished constructing the direct face.\n");

  //regeist the prefix to listen for the command of trust policy
  char schema_string[] = "/NDN-IoT/TrustChange";
  ndn_name_t schema_prefix;
  ndn_name_from_string(&schema_prefix, schema_string, sizeof(schema_string));
  ndn_direct_face_register_prefix(&schema_prefix, on_trustInterest);

  blink_led(3);

  // Enter main loop.
  for (;;) {
   if (nrf_gpio_pin_read(BUTTON_1)==0&&schematrust_flag){ // If button 1 is pressed (Active Low)
            nrf_gpio_pin_write(BSP_LED_0,0); // Turn on LED 
            printf("Button 1 pressed. schematrust_flag is %d\n",schematrust_flag);
            nrf_delay_ms(100); // for debouncing 
          }
            if (nrf_gpio_pin_read(BUTTON_2)==0){ // If button 2 is pressed (Active Low)
            nrf_gpio_pin_write(BSP_LED_0,1); // Turn off LED 
            printf("Button 2 pressed.schematrust_flag is %d\n",schematrust_flag);
            nrf_delay_ms(100); // for debouncing  
          }
     
//    idle_state_handle();
  }
}

/**
 * @}
 */