
# Leave this commented out in case we
# compile for OpenWrt:
# CC = gcc
C_FILES = $(wildcard *.c)
PROGRAM = wiredeauth
WIREDEAUTH_LIB = ../src/wiredeauth.o
SUBDIRS = accesspoint_list arg_parse deauth ieee802_11 raw_packet set_channel
REQUIRED_LIBS += -lnl-genl-3 -lnl-3

INCLUDE_DIRS = $(patsubst %,-I../src/%/,$(SUBDIRS))
OBJ_FILES = $(patsubst %.c,%.o,$(C_FILES))
CFLAGS += -g
CFLAGS += $(INCLUDE_DIRS)

all: $(WIREDEAUTH_LIB) $(OBJ_FILES)
	$(CC) -o $(PROGRAM) $(WIREDEAUTH_LIB) $(OBJ_FILES) $(REQUIRED_LIBS)
$(WIREDEAUTH_LIB):
	$(MAKE) -C ../src/
$(OBJ_FILES):
	$(CC) $(CFLAGS) -c $(patsubst %.o,%.c,$@)
clean:
	$(MAKE) -C ../src/ clean
	rm -f *.o $(PROGRAM)
