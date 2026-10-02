    .syntax unified

#include "version.h"

    .section .header, "a"

    .type g_header, %object
    .size g_header, .-g_header

g_header:
    .byte 'T','R','Z','F'
    .word g_header_end - g_header
    .word 1
    .word _codelen
    .byte VERSION_MAJOR
    .byte VERSION_MINOR
    .byte VERSION_PATCH
    .byte VERSION_BUILD
    .byte FIX_VERSION_MAJOR
    .byte FIX_VERSION_MINOR
    .byte FIX_VERSION_PATCH
    .byte FIX_VERSION_BUILD
    .word HW_MODEL
    .byte HW_REVISION
    .byte FIRMWARE_MONOTONIC_VERSION
    . = . + 2
    . = . + 512
    . = . + 415
    .byte 0
    . = . + 64
g_header_end:
