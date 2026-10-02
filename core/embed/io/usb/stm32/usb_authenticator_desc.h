#pragma once

#include "usb_internal.h"

typedef struct __attribute__((packed)) {
  uint8_t bLength;
  uint8_t bDescriptorType;
  uint16_t bcdHID;
  uint8_t bCountryCode;
  uint8_t bNumDescriptors;
  uint8_t bReportDescriptorType;
  uint16_t wReportDescriptorLength;
} usb_hid_descriptor_t;

typedef struct __attribute__((packed)) {
  usb_interface_descriptor_t iface;
  usb_hid_descriptor_t hid;
  usb_endpoint_descriptor_t ep_in;
  usb_endpoint_descriptor_t ep_out;
} usb_hid_descriptor_block_t;

#ifdef AUTHENTICATOR
#define AUTHENTICATOR_HID_REPORT_LEN 34

// This is the wire descriptor source copied into the runtime USB driver.
// The trailing report descriptor is consumed by HID GET_DESCRIPTOR.
typedef struct __attribute__((packed)) {
  usb_device_descriptor_t device;
  usb_config_descriptor_t config;
  usb_hid_descriptor_block_t hid;
  uint8_t report[AUTHENTICATOR_HID_REPORT_LEN];
} authenticator_usb_descriptors_t;

extern const authenticator_usb_descriptors_t g_authenticator_usb_descriptors;
bool usb_authenticator_descriptors_match(void);
#endif
