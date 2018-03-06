
C_FILES = $(wildcard *.c)

LOCAL_OBJS = $(patsubst %.c,%.o,$(C_FILES))

compile: $(LOCAL_OBJS)
$(LOCAL_OBJS):
	$(CC) $(CFLAGS) -c $(patsubst %.o,%.c,$@)
clean:
	rm -f ./*.o
