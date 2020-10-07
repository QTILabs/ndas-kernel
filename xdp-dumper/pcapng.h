/* SPDX-License-Identifier: GPL-2.0 */

/*****************************************************************************
 * Multiple include protection
 *****************************************************************************/
#ifndef __PCAPNG_H__
#define __PCAPNG_H__

#include <stdint.h>

/*****************************************************************************
 * Handle
 *****************************************************************************/
struct pcapng_dumper;

/*****************************************************************************
 * Flag variables
 *****************************************************************************/
enum pcapng_epb_flags { PCAPNG_EPB_FLAG_INBOUND = 0x1, PCAPNG_EPB_FLAG_OUTBOUND = 0x2 };

/*****************************************************************************
 * EPB options structure
 *****************************************************************************/
struct pcapng_epb_options_s {
    enum pcapng_epb_flags flags;
    uint64_t dropcount;
    uint64_t* packetid;
    uint32_t* queue;
    int64_t* xdp_verdict;
    const char* comment;
};

/*****************************************************************************
 * APIs
 *****************************************************************************/
extern struct pcapng_dumper* pcapng_dump_open(const char* file, const char* comment, const char* hardware,
                                              const char* os, const char* user_application);
extern void pcapng_dump_close(struct pcapng_dumper* pd);
extern int pcapng_dump_flush(struct pcapng_dumper* pd);
extern int pcapng_dump_add_interface(struct pcapng_dumper* pd, uint16_t snap_len, const char* name,
                                     const char* description, const uint8_t* mac, uint64_t speed, uint8_t ts_resolution,
                                     const char* hardware);
extern bool pcapng_dump_enhanced_pkt(struct pcapng_dumper* pd, uint32_t ifid, const uint8_t* pkt, uint32_t len,
                                     uint32_t caplen, uint64_t timestamp, struct pcapng_epb_options_s* options);

/*****************************************************************************
 * End-of include file
 *****************************************************************************/
#endif /* __PCAPNG_H__ */
