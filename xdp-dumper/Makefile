XDP_TARGETS := xdp-dumper-kern
USER_TARGETS := xdp-dumper-user
USER_LIBS=-lpcap -lpthread

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
COMMON_DIR = ../common

all: xdp-dumper.o

xdp-dumper.o: xdp-dumper.c xdp-dumper.h
	$(CC) $(CFLAGS) -c -o $@ $<

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o xdp-dumper.o
