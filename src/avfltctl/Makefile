CC = gcc
CFLAGS += -Wall -pedantic

ifdef DEBUG
CFLAGS += -g -O0
endif

BIN_NAME := avfltctl
BIN_OBJS := avfltctl.o
BIN_SRCS := avfltctl.c
BIN_DIR ?= /usr/bin
INCLUDE ?= -I../libavfltctl -I../librfsctl
DEP_FILE := .deps
LIB_DIR ?= /opt/redirfs/lib

.PHONY: all install uninstall clean

all: $(BIN_NAME)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(BIN_NAME): $(BIN_OBJS)
	$(CC) -o $(BIN_NAME) $(BIN_OBJS) -L$(LIB_DIR) -lavfltctl -lrfsctl -Wl,-rpath,$(LIB_DIR)

install: $(BIN_NAME)
	cp $(BIN_NAME) $(BIN_DIR)/$(BIN_NAME)

uninstall:
	$(RM) $(BIN_DIR)/$(BIN_NAME)
clean:
	$(RM) $(BIN_NAME) $(BIN_OBJS) $(DEP_FILE)

-include $(DEP_FILE)

$(DEP_FILE): $(BIN_SRCS)
	$(CC) -M -MF $@ $(INCLUDE) $(BIN_SRCS)

