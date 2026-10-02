/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef KERNEL_MODE

#include <trezor_bsp.h>
#include <trezor_model.h>
#include <trezor_rtl.h>

#include <io/usb.h>
#include <io/usb_config.h>
#include <io/usb_hid.h>
#include <io/usb_vcp.h>
#include <io/usb_webusb.h>

#ifdef TREZOR_EMULATOR
#include <stdlib.h>
#endif

#if defined(AUTHENTICATOR) && !defined(TREZOR_EMULATOR)
#include "stm32/usb_authenticator_desc.h"
#endif

#define USB_IFACE_BASE_PORT 21324

#define USB_IFACE_WIRE_PORT_OFFSET 0
#define USB_IFACE_DEBUG_PORT_OFFSET 1
#define USB_IFACE_WEBAUTHN_PORT_OFFSET 2
#define USB_IFACE_VCP_PORT_OFFSET 3

#if defined(AUTHENTICATOR)
// None of this firmware is Trezor's, so none of it says it is. These three
// strings are the whole of what a host shows about the device -- a platform's
// device list, its security-key prompts, and its logs all read from them -- and
// they name whoever wrote the image rather than whoever made the board. The
// AUTH-DEV suffix stays a suffix: it is how a development build announces that it
// is not certifiable, in the one place nobody can miss, and the image audit
// requires it present in a development build and absent in a production one.
#define AUTH_USB_MANUFACTURER "vinchlabs"
#define AUTH_USB_INTERFACE "aylo"
#if PRODUCTION
#if !defined(AUTHENTICATOR_USB_VID) || !defined(AUTHENTICATOR_USB_PID)
#error "production authenticator requires allocated USB VID and PID"
#endif
#define AUTH_USB_VID AUTHENTICATOR_USB_VID
#define AUTH_USB_PID AUTHENTICATOR_USB_PID
#define AUTH_USB_PRODUCT "aylo AUTH"
#else
// Set when an allocated identity was supplied to the build, production or not.
// Without one the device falls back to Trezor's pid.codes pair, which is what
// makes a host call this product by Trezor's name no matter what the strings
// above say -- the name comes from the host's VID:PID table, not from the device.
#if defined(AUTHENTICATOR_USB_VID)
#define AUTH_USB_VID AUTHENTICATOR_USB_VID
#define AUTH_USB_PID AUTHENTICATOR_USB_PID
#else
#define AUTH_USB_VID 0x1209
#define AUTH_USB_PID 0x53C1
#endif
#define AUTH_USB_PRODUCT "aylo AUTH-DEV"
#endif
#endif
#ifdef AUTHENTICATOR
#if !defined(USE_USB_IFACE_WEBAUTHN) || defined(USE_USB_IFACE_WIRE) || \
    defined(USE_USB_IFACE_DEBUG) || defined(USE_USB_IFACE_VCP)
#error "authenticator must expose exactly one WebAuthn HID interface"
#endif
#ifndef TREZOR_EMULATOR
// The runtime copies these exact wire descriptors into its USB driver. The
// linked bytes are also the release audit artifact; there is no parallel
// declaration of interface or report metadata.
__attribute__((used, section(".rodata.authenticator_usb_descriptors")))
const authenticator_usb_descriptors_t g_authenticator_usb_descriptors = {
    .device = {
        .bLength = sizeof(usb_device_descriptor_t),
        .bDescriptorType = USB_DESC_TYPE_DEVICE,
        .bcdUSB = 0x0200,
        .bDeviceClass = 0,
        .bDeviceSubClass = 0,
        .bDeviceProtocol = 0,
        .bMaxPacketSize0 = USB_MAX_EP0_SIZE,
        .idVendor = AUTH_USB_VID,
        .idProduct = AUTH_USB_PID,
        .bcdDevice = 0x0200,
        .iManufacturer = USBD_IDX_MFC_STR,
        .iProduct = USBD_IDX_PRODUCT_STR,
        .iSerialNumber = USBD_IDX_SERIAL_STR,
        .bNumConfigurations = 1,
    },
    .config = {
        .bLength = sizeof(usb_config_descriptor_t),
        .bDescriptorType = USB_DESC_TYPE_CONFIGURATION,
        .wTotalLength = sizeof(usb_config_descriptor_t) +
                        sizeof(usb_hid_descriptor_block_t),
        .bNumInterfaces = 1,
        .bConfigurationValue = 1,
        .iConfiguration = 0,
        .bmAttributes = 0x80,
        .bMaxPower = 0x32,
    },
    .hid = {
        .iface = {sizeof(usb_interface_descriptor_t), USB_DESC_TYPE_INTERFACE,
                  0, 0, 2, 3, 0, 0, USBD_IDX_INTERFACE_STR},
        .hid = {9, 0x21, 0x0111, 0, 1, 0x22, AUTHENTICATOR_HID_REPORT_LEN},
        .ep_in = {sizeof(usb_endpoint_descriptor_t), USB_DESC_TYPE_ENDPOINT,
                  0x81, USBD_EP_TYPE_INTR, USB_PACKET_LEN, 1},
        .ep_out = {sizeof(usb_endpoint_descriptor_t), USB_DESC_TYPE_ENDPOINT,
                   0x01, USBD_EP_TYPE_INTR, USB_PACKET_LEN, 1},
    },
    .report = {
        0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20,
        0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
        0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00,
        0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
    },
};
_Static_assert(sizeof(g_authenticator_usb_descriptors) == 93);
#endif
#endif

static secbool usb_device_init(void) {
#if defined(AUTHENTICATOR) && !defined(TREZOR_EMULATOR)
  if (((volatile const uint8_t *)&g_authenticator_usb_descriptors)[0] != 18) {
    return secfalse;
  }
#endif
#if defined(BOOTLOADER)
  usb_dev_info_t dev_info_default = {
      .device_class = 0x00,
      .device_subclass = 0x00,
      .device_protocol = 0x00,
      .vendor_id = 0x1209,
      .product_id = 0x53C0,
      .release_num = 0x0200,
      .manufacturer = MODEL_USB_MANUFACTURER,
      .product = MODEL_USB_PRODUCT,
      .serial_number = "000000000000000000000000",
      .interface = "TREZOR Interface",
      .usb21_enabled = sectrue,
      .usb21_landing = secfalse,
  };
#else
  static const usb_dev_info_t dev_info_default = {
      .device_class = 0x00,
      .device_subclass = 0x00,
      .device_protocol = 0x00,
      .vendor_id =
#ifdef AUTHENTICATOR
          AUTH_USB_VID,
#else
          0x1209,
#endif
      .product_id =
#ifdef AUTHENTICATOR
          AUTH_USB_PID,
#else
          0x53C1,
#endif
      .release_num = 0x0200,
      .manufacturer =
#ifdef AUTHENTICATOR
          AUTH_USB_MANUFACTURER,
#else
          MODEL_USB_MANUFACTURER,
#endif
      .product =
#ifdef AUTHENTICATOR
          AUTH_USB_PRODUCT,
#else
          MODEL_USB_PRODUCT,
#endif
      .serial_number = "000000000000000000000000",
      .interface =
#ifdef AUTHENTICATOR
          AUTH_USB_INTERFACE,
#else
          "TREZOR Interface",
#endif
      .usb21_enabled = sectrue,
      .usb21_landing = secfalse,
  };
#endif

  usb_dev_info_t dev_info = dev_info_default;

  // Microsoft OS 1.0 descriptors advertise interface 0 as WINUSB. This is
  // correct only when interface 0 is a vendor-specific Wire/Debug interface.
  // Without either, interface 0 is CDC or HID and must use its class driver.
#if !defined(USE_USB_IFACE_WIRE) && !defined(USE_USB_IFACE_DEBUG)
  dev_info.usb21_enabled = secfalse;
#endif

  return usb_init(&dev_info);
}

#ifdef TREZOR_EMULATOR
static uint16_t usb_emu_port(uint16_t port_offset) {
  const char *base_port = getenv("TREZOR_UDP_PORT");
  return port_offset + (base_port ? atoi(base_port) : USB_IFACE_BASE_PORT);
}
#endif

// ----------------------------------------------------------------

#ifdef USE_USB_IFACE_WIRE
static secbool usb_wire_iface_init(uint8_t *iface_num) {
  static uint8_t wire_iface_buffer[USB_PACKET_LEN];

  const usb_webusb_info_t wire_iface = {
      .handle = SYSHANDLE_USB_WIRE,
      .rx_buffer = wire_iface_buffer,
      .iface_num = *iface_num,
#ifdef TREZOR_EMULATOR
      .emu_port = usb_emu_port(USB_IFACE_WIRE_PORT_OFFSET),
#else
      .ep_in = 0x01 + *iface_num,
      .ep_out = 0x01 + *iface_num,
#endif
      .subclass = 0x00,
      .protocol = 0x00,
      .polling_interval = 1,
      .max_packet_len = sizeof(wire_iface_buffer),
  };

  if (sectrue != usb_webusb_add(&wire_iface)) {
    return secfalse;
  }

  *iface_num += 1;

  return sectrue;
}
#endif  // USE_USB_IFACE_WIRE

#ifdef USE_USB_IFACE_DEBUG
static secbool usb_debug_iface_init(uint8_t *iface_num) {
  static uint8_t debug_iface_buffer[USB_PACKET_LEN];

  const usb_webusb_info_t debug_iface = {
      .handle = SYSHANDLE_USB_DEBUG,
      .rx_buffer = debug_iface_buffer,
      .iface_num = *iface_num,
#ifdef TREZOR_EMULATOR
      .emu_port = usb_emu_port(USB_IFACE_DEBUG_PORT_OFFSET),
#else
      .ep_in = 0x01 + *iface_num,
      .ep_out = 0x01 + *iface_num,
#endif
      .subclass = 0x00,
      .protocol = 0x00,
      .polling_interval = 1,
      .max_packet_len = sizeof(debug_iface_buffer),
  };

  if (sectrue != usb_webusb_add(&debug_iface)) {
    return secfalse;
  }

  *iface_num += 1;

  return sectrue;
}
#endif  // USE_USB_IFACE_DEBUG

#ifdef USE_USB_IFACE_WEBAUTHN
static secbool usb_webauthn_iface_init(uint8_t *iface_num) {
#if !defined(AUTHENTICATOR) || defined(TREZOR_EMULATOR)
  static const uint8_t webauthn_report_map[] = {
      0x06, 0xd0, 0xf1,  // USAGE_PAGE (FIDO Alliance)
      0x09, 0x01,        // USAGE (U2F HID Authenticator Device)
      0xa1, 0x01,        // COLLECTION (Application)
      0x09, 0x20,        //  USAGE (Input Report Data)
      0x15, 0x00,        //  LOGICAL_MINIMUM (0)
      0x26, 0xff, 0x00,  //  LOGICAL_MAXIMUM (255)
      0x75, 0x08,        //  REPORT_SIZE (8)
      0x95, 0x40,        //  REPORT_COUNT (64)
      0x81, 0x02,        //  INPUT (Data,Var,Abs)
      0x09, 0x21,        //  USAGE (Output Report Data)
      0x15, 0x00,        //  LOGICAL_MINIMUM (0)
      0x26, 0xff, 0x00,  //  LOGICAL_MAXIMUM (255)
      0x75, 0x08,        //  REPORT_SIZE (8)
      0x95, 0x40,        //  REPORT_COUNT (64)
      0x91, 0x02,        //  OUTPUT (Data,Var,Abs)
      0xc0,              // END_COLLECTION
  };
#endif

  static uint8_t webauthn_iface_buffer[USB_PACKET_LEN];

  const usb_hid_info_t webauthn_iface = {
      .handle = SYSHANDLE_USB_WEBAUTHN,
#if !defined(AUTHENTICATOR) || defined(TREZOR_EMULATOR)
      .report_desc = webauthn_report_map,
      .report_desc_len = sizeof(webauthn_report_map),
#else
      .report_desc = g_authenticator_usb_descriptors.report,
      .report_desc_len = sizeof(g_authenticator_usb_descriptors.report),
#endif
      .rx_buffer = webauthn_iface_buffer,
#if defined(AUTHENTICATOR) && !defined(TREZOR_EMULATOR)
      .max_packet_len = g_authenticator_usb_descriptors.hid.ep_in.wMaxPacketSize,
#else
      .max_packet_len = sizeof(webauthn_iface_buffer),
#endif
      .iface_num = *iface_num,
#ifdef TREZOR_EMULATOR
      .emu_port = usb_emu_port(USB_IFACE_WEBAUTHN_PORT_OFFSET),
#elif defined(AUTHENTICATOR)
      .ep_in = g_authenticator_usb_descriptors.hid.ep_in.bEndpointAddress &
               ~USB_EP_DIR_IN,
      .ep_out = g_authenticator_usb_descriptors.hid.ep_out.bEndpointAddress,
#else
      .ep_in = 0x01 + *iface_num,
      .ep_out = 0x01 + *iface_num,
#endif
#if defined(AUTHENTICATOR) && !defined(TREZOR_EMULATOR)
      .subclass = g_authenticator_usb_descriptors.hid.iface.bInterfaceSubClass,
      .protocol = g_authenticator_usb_descriptors.hid.iface.bInterfaceProtocol,
      .polling_interval = g_authenticator_usb_descriptors.hid.ep_in.bInterval,
#else
      .subclass = 0x00,
      .protocol = 0x00,
      .polling_interval = 1,
#endif
  };

  if (sectrue != usb_hid_add(&webauthn_iface)) {
    return secfalse;
  }

  *iface_num += 1;

  return sectrue;
}
#endif  // USE_USB_IFACE_WEBAUTHN

#if defined(USE_USB_HS) && !defined(USE_USB_HS_IN_FS)
#define VCP_PACKET_LEN 512  // HS periperal in HS mode
#elif defined(USE_USB_HS) && defined(USE_USB_HS_IN_FS)
#define VCP_PACKET_LEN 64  // HS peripheral in FS mode
#elif defined(USE_USB_FS)
#define VCP_PACKET_LEN 64
#elif defined(TREZOR_EMULATOR)
#define VCP_PACKET_LEN 64
#else
#error "USB type not defined"
#endif

#define VCP_TX_BUFFER_LEN 2048
#define VCP_RX_BUFFER_LEN 2048

#ifdef USE_USB_IFACE_VCP
static secbool usb_vcp_iface_init(uint8_t *iface_num,
                                  usb_vcp_intr_callback_t vcp_intr_callback) {
  static uint8_t vcp_tx_packet[VCP_PACKET_LEN];
  static uint8_t vcp_tx_buffer[VCP_TX_BUFFER_LEN];
  static uint8_t vcp_rx_packet[VCP_PACKET_LEN];
  static uint8_t vcp_rx_buffer[VCP_RX_BUFFER_LEN];

  const usb_vcp_info_t vcp_info = {
      .handle = SYSHANDLE_USB_VCP,
      .tx_packet = vcp_tx_packet,
      .tx_buffer = vcp_tx_buffer,
      .rx_packet = vcp_rx_packet,
      .rx_buffer = vcp_rx_buffer,
      .tx_buffer_len = sizeof(vcp_tx_buffer),
      .rx_buffer_len = sizeof(vcp_rx_buffer),
      .max_packet_len = VCP_PACKET_LEN,
      .rx_intr_fn = vcp_intr_callback,
      .rx_intr_byte = 3,  // Ctrl-C
      .iface_num = *iface_num,
      .data_iface_num = *iface_num + 1,
#ifdef TREZOR_EMULATOR
      .emu_port = usb_emu_port(USB_IFACE_VCP_PORT_OFFSET),
#else
      .ep_cmd = 0x01 + *iface_num + 1,
      .ep_in = 0x01 + *iface_num,
      .ep_out = 0x01 + *iface_num,
#endif
      .polling_interval = 10,
  };

  if (sectrue != usb_vcp_add(&vcp_info)) {
    return secfalse;
  }

  *iface_num += 2;  // increment by data iface

  return sectrue;
}
#endif  // USE_USB_IFACE_VCP

secbool usb_configure(usb_vcp_intr_callback_t vcp_intr_callback) {
  if (sectrue != usb_device_init()) {
    goto cleanup;
  }

  uint8_t iface_num = 0;

#ifdef USE_USB_IFACE_WIRE
  if (sectrue != usb_wire_iface_init(&iface_num)) {
    goto cleanup;
  }
#endif

#ifdef USE_USB_IFACE_DEBUG
  if (sectrue != usb_debug_iface_init(&iface_num)) {
    goto cleanup;
  }
#endif

#ifdef USE_USB_IFACE_WEBAUTHN
  if (sectrue != usb_webauthn_iface_init(&iface_num)) {
    goto cleanup;
  }
#endif

#ifdef USE_USB_IFACE_VCP
  if (sectrue != usb_vcp_iface_init(&iface_num, vcp_intr_callback)) {
    goto cleanup;
  }
#endif

#if defined(AUTHENTICATOR) && !defined(TREZOR_EMULATOR)
  if (iface_num != 1 || !usb_authenticator_descriptors_match()) {
    goto cleanup;
  }
#endif

  return sectrue;

cleanup:

  usb_deinit();
  return secfalse;
}

#endif  // KERNEL_MODE
