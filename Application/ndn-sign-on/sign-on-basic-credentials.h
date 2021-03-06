/*
 * Copyright (C) Edward Lu
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */

#ifndef SIGN_ON_BASIC_CREDENTIALS_H
#define SIGN_ON_BASIC_CREDENTIALS_H

#include <stdint.h>
#include "../../ndn-lite/app-support/secure-sign-on/sign-on-basic-client-consts.h"
#include "../../ndn-lite/app-support/secure-sign-on/variants/ecc_256/sign-on-basic-ecc-256-consts.h"

#define BOARD_1
// #define BOARD_2

#ifdef BOARD_1
#define EXAMPLE_BOARD_NAME "board 1"
#endif
#ifdef BOARD_2
#define EXAMPLE_BOARD_NAME "board 2"
#endif

extern const uint8_t DEVICE_IDENTIFIER[SIGN_ON_BASIC_CLIENT_DEVICE_IDENTIFIER_MAX_LENGTH];

extern const uint8_t DEVICE_CAPABILITIES[SIGN_ON_BASIC_CLIENT_DEVICE_CAPABILITIES_MAX_LENGTH];

// these are the raw 32 bytes of the bootstrapping ecc private key (raw format is the format
// used and output by the micro-ecc library)
extern const uint8_t BOOTSTRAP_ECC_PRIVATE[32];

// these are the raw key bytes of the ecc public key without
// the point identifier
extern const uint8_t BOOTSTRAP_ECC_PUBLIC_NO_POINT_IDENTIFIER[64];

extern const uint8_t SECURE_SIGN_ON_CODE[SIGN_ON_BASIC_ECC_256_SECURE_SIGN_ON_CODE_LENGTH];

#endif // SIGN_ON_BASIC_CREDENTIALS_H