XDP_TARGETS := xdp-dumper-kern
USER_TARGETS := xdp-dumper-user
USER_LIBS=-lpcap

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
COMMON_DIR = ../common

all: xdp-dumper-hook.o

xdp-dumper-hook.o: xdp-dumper-hook.c xdp-dumper-hook.h
	$(CC) $(CFLAGS) -c -o $@ $<

include $(COMMON_DIR)/common.mk
COMMON_OBJS := $(COMMON_DIR)/common_params.o xdp-dumper-hook.o
