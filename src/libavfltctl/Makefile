CC = gcc
CFLAGS += -Wall -pedantic -fpic

ifdef DEBUG
CFLAGS += -g -O0
endif

VMAR := 1
VMIN := 0
VREL := 0
LIB_NAME := libavfltctl
LIB_OBJS := avfltctl.o
LIB_SRCS := avfltctl.c
LIB_DIR ?= /opt/redirfs/lib
HDR_NAME := avfltctl.h
HDR_DIR ?= /usr/include
DEP_FILE := .deps
INCLUDE ?= -I../librfsctl

.PHONY: all install uninstall clean

all: $(LIB_NAME).a  $(LIB_NAME).so

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $@ $<

$(LIB_NAME).a: $(LIB_OBJS)
	$(AR) $(ARFLAGS) $(LIB_NAME).a $(LIB_OBJS)

$(LIB_NAME).so: $(LIB_OBJS)
	$(CC) -shared -Wl,-soname,$(LIB_NAME).so.$(VMAR) \
		-o $(LIB_NAME).so $(LIB_OBJS) -L$(lib_DIR) -lrfsctl -Wl,-rpath,$(LIB_DIR) 

install: $(LIB_NAME).a $(LIB_NAME).so
	mkdir -p $(HDR_DIR)
	mkdir -p $(LIB_DIR)
	cp $(HDR_NAME) $(HDR_DIR)/$(HDR_NAME)
	cp $(LIB_NAME).a $(LIB_DIR)/$(LIB_NAME).a
	cp $(LIB_NAME).so $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL)
	ln -sf $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL) \
		$(LIB_DIR)/$(LIB_NAME).so.$(VMAR)
	ln -sf $(LIB_DIR)/$(LIB_NAME).so.$(VMAR) \
		$(LIB_DIR)/$(LIB_NAME).so

uninstall:
	$(RM) $(HDR_DIR)/$(HDR_NAME)
	$(RM) $(LIB_DIR)/$(LIB_NAME).a
	$(RM) $(LIB_DIR)/$(LIB_NAME).so
	$(RM) $(LIB_DIR)/$(LIB_NAME).so.$(VMAR)
	$(RM) $(LIB_DIR)/$(LIB_NAME).so.$(VMAR).$(VMIN).$(VREL)

clean:
	$(RM) $(LIB_NAME).a $(LIB_NAME).so $(LIB_OBJS) $(DEP_FILE)

-include $(DEP_FILE)

$(DEP_FILE): $(LIB_SRCS)
	$(CC) -M -MF $@ $(INCLUDE) $(LIB_SRCS)

