# micropython.mk — build rules for the AES-256 native module
#
# This file is auto-discovered by MicroPython's build system when the
# parent directory is passed to USER_C_MODULES:
#
#   cd micropython/ports/rp2040
#   make USER_C_MODULES=$(pwd)/../../../pico-hsm/pico/native/micropython.mk
#
# The .c file must live in the same directory as this .mk.

USERMODULES_DIR := $(USERMOD_DIR)

CFLAGS_USERMOD += -I$(USERMODULES_DIR)

SRC_USERMOD += $(USERMODULES_DIR)/aes.c
