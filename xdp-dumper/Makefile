XDP_TARGETS := xdp-dumper-kern
USER_TARGETS := xdp-dumper-user
USER_LIBS=-lpcap

LLC ?= llc
CLANG ?= clang
CC := gcc

LIBBPF_DIR = ../libbpf/src
COMMON_DIR = ../common

include $(COMMON_DIR)/common.mk

all: xdp-dumper-hook.o

xdp-dumper-hook.o: xdp-dumper-hook.c xdp-dumper-hook.h
	$(CC) $(CFLAGS) -c -o $@ $<

COMMON_OBJS := $(COMMON_DIR)/common_params.o xdp-dumper-hook.o
