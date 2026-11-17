/* User-defined SDLS Extended Procedure (EP) for the PQC handshake (ML-KEM-768 + ML-DSA-65).
 * EP packets are found by their Space Packet header, as in NOS3 CryptoLib crypto.c:910.
 * They are handled inside CI_LAB and never reach the Software Bus. */
#ifndef _pqc_sdls_my_h_
#define _pqc_sdls_my_h_

#include "cfe.h"
#include "ci_lab_msgids.h"

/* First two Space Packet header octets of an EP packet (APID 0x180, MID 0x1980). */
#define PQC_SDLS_MY_EP_HDR0 0x19
#define PQC_SDLS_MY_EP_HDR1 0x80

/* Downlink MID for EP replies (ci_lab_msgids.h); TO_LAB must subscribe to it. */
#define PQC_SDLS_MY_EP_TLM_MID CI_LAB_PQC_EP_TLM_MID

/* SPIs from the handshake figure; unused while SDLS is disabled. */
#define PQC_SDLS_MY_SPI_HANDSHAKE 0
#define PQC_SDLS_MY_SPI_SESSION   1

/* Algorithm sizes in bytes (ML-KEM-768 and ML-DSA-65). */
#define PQC_SDLS_MY_KEM_EK_LENGTH 1184
#define PQC_SDLS_MY_KEM_CT_LENGTH 1088
#define PQC_SDLS_MY_KEM_SS_LENGTH 32
#define PQC_SDLS_MY_DSA_SIG_LENGTH 3309
#define PQC_SDLS_MY_SESSION_KEY_LENGTH 32

/* Session ID length is not fixed by the figure; 4 bytes is a prototype choice. */
#define PQC_SDLS_MY_SESSION_ID_LENGTH 4

/* Packet layout: [Space Packet header 6][Tag 1][Length 2, in bits][Value].
 * Same layout as the NOS3 EP path without a PUS header (crypto.c:1005-1010). */
#define PQC_SDLS_MY_SPP_HDR_LENGTH 6
#define PQC_SDLS_MY_TLV_HDR_LENGTH 3

/* Tag octet: Type 1 bit (0 command, 1 reply), User Flag 1 bit, Service Group 2 bits, PID 4 bits.
 * The User Flag is 1 because these procedures are user-defined. */
#define PQC_SDLS_MY_TAG(type, pid)  ((uint8)(((type) << 7) | (1 << 6) | (0 << 4) | ((pid) & 0x0F)))
#define PQC_SDLS_MY_TAG_TYPE(tag)   (((tag) >> 7) & 0x01)
#define PQC_SDLS_MY_TAG_UF(tag)     (((tag) >> 6) & 0x01)
#define PQC_SDLS_MY_TAG_PID(tag)    ((tag) & 0x0F)
#define PQC_SDLS_MY_TYPE_COMMAND    0
#define PQC_SDLS_MY_TYPE_REPLY      1

/* Procedure IDs, one per command in the handshake figure. */
#define PQC_SDLS_MY_PID_HS_REQ   1 /* 1. HS_REQ (Session ID)  -> 2. HS_REQ_R (Session ID) */
#define PQC_SDLS_MY_PID_HS_KEX   2 /* 3. HS_KEX (ek + Sig_G)  -> 4. HS_KEX_R (ct)         */
#define PQC_SDLS_MY_PID_ACTIVATE 3 /* 5. Activation, Rekey, Start (no reply)             */
#define PQC_SDLS_MY_PID_PING     4 /* 6. Ping                 -> 7. Ping reply            */

/* HS_KEX (3 + 4493 bytes) is larger than one TC frame, so it is split with the
 * Space Packet Sequence Flags and joined again in this buffer. */
#define PQC_SDLS_MY_EP_MAX_LENGTH \
    (PQC_SDLS_MY_TLV_HDR_LENGTH + PQC_SDLS_MY_KEM_EK_LENGTH + PQC_SDLS_MY_DSA_SIG_LENGTH)

#define PQC_SDLS_MY_SEQ_CONTINUATION 0
#define PQC_SDLS_MY_SEQ_FIRST        1
#define PQC_SDLS_MY_SEQ_LAST         2
#define PQC_SDLS_MY_SEQ_UNSEGMENTED  3

#define PQC_SDLS_MY_SUCCESS        (0)
#define PQC_SDLS_MY_IN_PROGRESS    (1) /* Segment stored, more segments expected */
#define PQC_SDLS_MY_INVALID_LENGTH (-3)
#define PQC_SDLS_MY_INVALID_SEQ    (-4)
#define PQC_SDLS_MY_INVALID_STATE  (-5)
#define PQC_SDLS_MY_INVALID_TAG    (-6)
#define PQC_SDLS_MY_SEND_ERROR     (-7)
// #define PQC_SDLS_MY_SECURITY_ERROR (-8)

/* Resets the handshake state. Call once from CI_LAB_TaskInit. */
void PQC_SDLS_myInit(void);

/* Returns true if the Space Packet header marks this packet as an EP packet. */
bool PQC_SDLS_myIsEpPacket(const uint8 *pPacket, int32 packetSize);

/* Handles one EP packet (or one segment of it) and sends the reply, if any.
 * Returns PQC_SDLS_MY_SUCCESS, PQC_SDLS_MY_IN_PROGRESS or a negative error. */
int32 PQC_SDLS_myProcessEp(const uint8 *pPacket, int32 packetSize);

#endif /* _pqc_sdls_my_h_ */
