/*-
 * Copyright (c) <2010-2020>, Intel Corporation. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/* Created 2021 by Diego Rossi Mafioletti @ gmail.com */

#define RTE_ETHER_TYPE_PON_US_FIRST     0x1f44
#define RTE_ETHER_TYPE_PON_US_LAST      0x1b94
#define RTE_ETHER_TYPE_PON_BWMAP        0x5678

#define RTE_PON_PTKSIZE_NORM(_size) (_size+14)     // adds 14 bytes to the packet size

#define BWMAP_ALLOC_STRUCT_COUNT 128

typedef struct {
    uint32_t buff_occ:24;
    uint8_t crc;
} dbru_t;

typedef struct pon_packet_s {
    uint64_t dbru_tsc_sync;
    uint64_t curr_tsc;
    uint64_t prev_tsc;
} pon_packet_t;

typedef struct {
	uint64_t timestamp;
	uint16_t magic;
} tstamp_t;


struct rte_pon_us_ether_hdr {
    // outer ethernet: integrated with the standard Ethernet header
    // uint64_t out_dstAddr:48;
    // uint64_t out_srcAddr:48;
    // uint16_t out_chunck_len;
    
    // FS chunck meta data
    uint16_t burst_id;
    uint8_t burst_seq;

    uint8_t flags;                  // 0x01 == last chunck | 0x02 == first chunck
    uint32_t padding;               // extra padding (4 bytes * 0x00)
    uint8_t ploamu[48];             // 8.2.1.4 Upstream PLOAM (PLOAMu) field (0 or 48 bytes - OPTIONAL * 0x44)
} __rte_packed;

struct rte_pon_dbru_hdr {
    uint32_t buff_occ:24;
    uint8_t crc;
} __rte_packed;

struct rte_pon_xgem_h {
    uint16_t pli:14;            /* The length L, in bytes, of an SDU or an SDU fragment in the XGEM payload following the 
                                XGEM header. The 14-bit field allows to represent an integer from 0 to 16383. 
                                */
    uint8_t index:2;            /* The indicator of the data encryption key used to encrypt the XGEM payload */
    uint16_t port_id;           /* The identifier of XGEM Port to which the frame belongs */
    uint32_t options:18;        /* The use of this field remains for further study. The field is set to 0x00000 by 
                                the transmitter and ignored by the receiver. 
                                */
    uint8_t lf:1;               /* The last fragment indicator. If the fragment encapsulated into the XGEM frame 
                                    is the last fragment of an SDU or a complete SDU, the LF bit is set to 1; 
                                    otherwise, LF bit is 0.
                                */
    uint16_t hec:13;            /* The error detection and correction field for the XGEM header, which is a combination of 
                                    a BCH(63, 12, 2) code operating on the 63 initial bits of the header and a single 
                                    parity bit (annex A @ ITU-T G.987.3)
                                */
} __rte_packed;

// HLend is a 4-byte structure that controls the size of the variable length partitions within the XGTC header
struct rte_pon_hlend_h {
    uint16_t bwmap_length:11;   // contains an unsigned integer, N, indicating the number of allocation structures in the BWmap partition.
    uint8_t ploam_count;        // contains an unsigned integer, P, indicating the number of PLOAM messages in the PLOAMd partition.
    uint16_t hec:13;            /* an error detection and correction field for the HLend structure, which is a combination of a truncated 
                                    BCH(63,12,2) code operating on the 31 initial bits of the HLend structure and a single parity bit. 
                                    The details of the HEC construction and verification are specified in Annex A.
                                */
} __rte_packed;


struct rte_pon_bwmap_alloc_structure_h {
    uint16_t alloc_id:14;       // The allocation ID field contains the 14-bit number that indicates the recipient of the bandwidth allocation
    uint8_t dbru:1;             /* If this bit is set, the ONU should send the DBRu report for the given Alloc-ID. 
                                    If the bit is not set, the DBRu report is not transmitted.
                                */
    uint8_t ploamu:1;
    uint16_t start_time;        /* The StartTime field contains a 16-bit number that indicates the location of the first byte of the 
                                    upstream XGTC burst within the upstream PHY frame. StartTime is measured from the beginning of the 
                                    upstream PHY frame and has a granularity of 1 word (4 bytes). 
                                    The value of StartTime = 0 corresponds to the first word of the upstream PHY frame; the value of 
                                    StartTime = 9719 corresponds to the last word of the upstream PHY frame.
                                */
    uint16_t grant_size;        /* The GrantSize field contains the 16-bit number that indicates the combined length of the XGTC payload 
                                    data with DBRu overhead transmitted within the given allocation. (Notably, GrantSize does not include 
                                    XGTC header, XGTC trailer, or FEC overhead.) GrantSize has the granularity of 1 word (4 bytes). The 
                                    value of GrantSize is equal to zero for the PLOAM-only grants, including serial number grants and 
                                    ranging grants used in the process of ONU activation. The minimum possible non-zero value of GrantSize 
                                    is 1, which corresponds to as single word (4 byte) allocation for a DBRu-only transmission. The minimum
                                    allocation for XGTC payload proper (DBRu flag not set) is 4 words (16 bytes), in which case GrantSize = 4.
                                */
    uint8_t fwi:1;              /* When addressing an ONU that supports the protocol-based power management, the OLT sets the FWI bit to 
                                    expedite waking up an ONU that has been in a low power mode.
                                */
    uint8_t burst_profile:2;    /* The BurstProfile field is a 2-bit field that contains the index of the burst profile to be used by the 
                                    PHY adaptation sublayer of the ONU to form the PHY burst
                                */
    uint16_t hec:13;
} __rte_packed;

// custom ethernet header (22 bytes)
struct rte_pon_ethernet_h {
    uint64_t dstaddr:48;
    uint64_t srcaddr:48;
    uint32_t vlan_tag;
    uint16_t ether_type;
} __rte_packed;


struct rte_timestamp_h {
	uint64_t timestamp;
	uint16_t magic;
} __rte_packed;


typedef struct {
    uint16_t bwmap_length:11;
    uint8_t ploam_count;
    uint16_t hec:13;
    struct rte_pon_bwmap_alloc_structure_h alloc_struct[BWMAP_ALLOC_STRUCT_COUNT];
} hlend_t;
