
include .config

# Leave these commented out in case we
# compile for OpenWrt:
# CC = gcc
# LD = ld

SUBDIRS = accesspoint_list arg_parse deauth ieee802_11 raw_socket set_channel utils

INCLUDE_DIRS = $(patsubst %,-I../%/,$(SUBDIRS)) -I/usr/include/libnl3/

# Configuration
ifdef DEAUTH_METHOD
	CFLAGS += -DDEAUTH_METHOD_$(DEAUTH_METHOD)
endif
ifdef DEBUG_MODE
	ifeq ($(DEBUG_MODE), y)
		CFLAGS += -DWIREDEAUTH_DEBUG
		CFLAGS += -g
	endif
endif
ifdef PROG_VER
	CFLAGS += "-DPROG_VER=\"${PROG_VER}\""
else
$(error Program version not defined in .config)
endif
CFLAGS += $(INCLUDE_DIRS)

export

TARGET_LIB = wiredeauth.o

OBJ_FILES = \
	accesspoint_list/accesspoint_list.o \
	arg_parse/arg_parse.o \
	deauth/deauth.o \
	deauth/deauth_wld.o \
	ieee802_11/ieee802_11_common.o \
	raw_socket/raw_socket.o \
	set_channel/set_channel.o \
	utils/wiredeauth_debug.o \

LDFLAGS = -r

all: $(OBJ_FILES)
	$(LD) $(LDFLAGS) $(OBJ_FILES) -o $(TARGET_LIB)
$(OBJ_FILES):
	for d in $(SUBDIRS); do $(MAKE) -C $$d compile; done
clean:
	for d in $(SUBDIRS); do $(MAKE) -C $$d clean; done
	rm -f *.o
