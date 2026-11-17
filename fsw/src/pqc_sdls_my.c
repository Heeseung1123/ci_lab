/* User-defined SDLS Extended Procedure for the PQC handshake, satellite side.
 * Flow follows the "PQC Handshake procedure" figure (HS_REQ, HS_KEX, Activation, Ping).
 * PQC and SA calls are commented out because no PQC library or SDLS is used yet. */
#include "pqc_sdls_my.h"
#include "ci_lab_events.h"
// #include "api.h" /* ML-KEM-768 and ML-DSA-65, for example from pqm4 or PQClean */

typedef enum
{
    PQC_SDLS_MY_STATE_IDLE = 0,      /* Waiting for HS_REQ */
    PQC_SDLS_MY_STATE_WAIT_KEX,      /* HS_REQ_R sent, waiting for HS_KEX */
    PQC_SDLS_MY_STATE_WAIT_ACTIVATE, /* HS_KEX_R sent, waiting for Activation */
} PQC_SDLS_myState_t;

typedef struct
{
    PQC_SDLS_myState_t State;
    bool               SessionActive; /* SPI 1 SA holds valid session keys */
    uint8              SessionId[PQC_SDLS_MY_SESSION_ID_LENGTH];

    /* Joined EP packet: [Tag][Length][Value]. */
    uint8  EpBuffer[PQC_SDLS_MY_EP_MAX_LENGTH];
    uint32 EpLength;
    bool   Joining;
    uint16 NextSeqCount;

    /* Session keys from KDF(ss). They go into the SPI 1 SA on Activation. */
    // uint8 KeyUp[PQC_SDLS_MY_SESSION_KEY_LENGTH];
    // uint8 KeyDn[PQC_SDLS_MY_SESSION_KEY_LENGTH];
} PQC_SDLS_myData_t;

static PQC_SDLS_myData_t PQC_SDLS_myData;

/* Provisioned ML-DSA-65 public key of the Ground System. */
// static const uint8 PQC_SDLS_myPkGround[1952] = { ... };

void PQC_SDLS_myInit(void)
{
    CFE_PSP_MemSet(&PQC_SDLS_myData, 0, sizeof(PQC_SDLS_myData));
}

bool PQC_SDLS_myIsEpPacket(const uint8 *pPacket, int32 packetSize)
{
    /* Same test as NOS3 crypto.c:910: compare the first two header octets. */
    return (packetSize >= PQC_SDLS_MY_SPP_HDR_LENGTH) && (pPacket[0] == PQC_SDLS_MY_EP_HDR0) &&
           (pPacket[1] == PQC_SDLS_MY_EP_HDR1);
}

/* Drops a half-joined packet and erases it, since it may hold key material. */
static void PQC_SDLS_myResetJoin(void)
{
    CFE_PSP_MemSet(PQC_SDLS_myData.EpBuffer, 0, sizeof(PQC_SDLS_myData.EpBuffer));
    PQC_SDLS_myData.EpLength = 0;
    PQC_SDLS_myData.Joining  = false;
}

/* Allocates an SB buffer for a reply and writes its Tag and Length.
 * Returns the start of the Value field, or NULL if no buffer is free. */
static uint8 *PQC_SDLS_myAllocReply(CFE_SB_Buffer_t **ppBuf, uint8 pid, uint16 valueLength)
{
    size_t replySize = sizeof(CFE_MSG_TelemetryHeader_t) + PQC_SDLS_MY_TLV_HDR_LENGTH + valueLength;
    uint8 *pTlv;
    uint32 lengthBits = (uint32)valueLength * 8;

    *ppBuf = CFE_SB_AllocateMessageBuffer(replySize);
    if (*ppBuf == NULL)
    {
        return NULL;
    }

    CFE_MSG_Init(&(*ppBuf)->Msg, CFE_SB_ValueToMsgId(PQC_SDLS_MY_EP_TLM_MID), replySize);
    pTlv    = (*ppBuf)->Msg.Byte + sizeof(CFE_MSG_TelemetryHeader_t);
    pTlv[0] = PQC_SDLS_MY_TAG(PQC_SDLS_MY_TYPE_REPLY, pid);
    pTlv[1] = (uint8)(lengthBits >> 8);
    pTlv[2] = (uint8)(lengthBits & 0xFF);

    return pTlv + PQC_SDLS_MY_TLV_HDR_LENGTH;
}

/* Sends a reply to TO_LAB through the Software Bus. */
static int32 PQC_SDLS_mySendReply(CFE_SB_Buffer_t *pBuf)
{
    CFE_SB_TimeStampMsg(&pBuf->Msg);

    /* Downlink protection with SPI 0 (or SPI 1 for Ping) is done in TO_LAB later. */
    if (CFE_SB_TransmitBuffer(pBuf, true) != CFE_SUCCESS)
    {
        CFE_SB_ReleaseMessageBuffer(pBuf);
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP reply not sent");
        return PQC_SDLS_MY_SEND_ERROR;
    }

    return PQC_SDLS_MY_SUCCESS;
}

/* Checks the state of the current encrypted session before a new handshake.
 * An active session stays in use until the new keys are activated (rekey). */
static void PQC_SDLS_myVerifyEncryptedSession(void)
{
    if (PQC_SDLS_myData.State != PQC_SDLS_MY_STATE_IDLE)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "CI: PQC unfinished handshake restarted");
    }
    else if (PQC_SDLS_myData.SessionActive)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "CI: PQC session active, starting rekey");
    }
}

/* 1. HS_REQ (Session ID) -> 2. HS_REQ_R (Session ID). */
static int32 PQC_SDLS_myHandleHsReq(const uint8 *pValue, uint32 valueLength)
{
    CFE_SB_Buffer_t *pBuf;
    uint8           *pReply;

    if (valueLength != PQC_SDLS_MY_SESSION_ID_LENGTH)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC HS_REQ bad length %u",
                          (unsigned int)valueLength);
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    PQC_SDLS_myVerifyEncryptedSession();
    CFE_PSP_MemCpy(PQC_SDLS_myData.SessionId, pValue, PQC_SDLS_MY_SESSION_ID_LENGTH);

    pReply = PQC_SDLS_myAllocReply(&pBuf, PQC_SDLS_MY_PID_HS_REQ, PQC_SDLS_MY_SESSION_ID_LENGTH);
    if (pReply == NULL)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC no buffer for HS_REQ_R");
        return PQC_SDLS_MY_SEND_ERROR;
    }
    CFE_PSP_MemCpy(pReply, PQC_SDLS_myData.SessionId, PQC_SDLS_MY_SESSION_ID_LENGTH);

    PQC_SDLS_myData.State = PQC_SDLS_MY_STATE_WAIT_KEX;
    CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "CI: PQC HS_REQ session %02x%02x%02x%02x", PQC_SDLS_myData.SessionId[0],
                      PQC_SDLS_myData.SessionId[1], PQC_SDLS_myData.SessionId[2], PQC_SDLS_myData.SessionId[3]);

    return PQC_SDLS_mySendReply(pBuf);
}

/* 3. HS_KEX (ek + Sig_G) -> 4. HS_KEX_R (ct).
 * Verifies Sig_G, encapsulates with ek and derives K_up and K_dn from ss. */
static int32 PQC_SDLS_myHandleHsKex(const uint8 *pValue, uint32 valueLength)
{
    CFE_SB_Buffer_t *pBuf;
    uint8           *pCt;
    uint8            ss[PQC_SDLS_MY_KEM_SS_LENGTH];
    const uint8     *pEk  = pValue;
    const uint8     *pSig = pValue + PQC_SDLS_MY_KEM_EK_LENGTH;

    if (PQC_SDLS_myData.State != PQC_SDLS_MY_STATE_WAIT_KEX)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC HS_KEX without HS_REQ");
        return PQC_SDLS_MY_INVALID_STATE;
    }
    if (valueLength != PQC_SDLS_MY_KEM_EK_LENGTH + PQC_SDLS_MY_DSA_SIG_LENGTH)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC HS_KEX bad length %u",
                          (unsigned int)valueLength);
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    /* Sig_G must be valid for the provisioned Ground key before ek is used.
     * The signed message (here Session ID || ek) must match the Ground System. */
    // if (crypto_sign_verify(pSig, PQC_SDLS_MY_DSA_SIG_LENGTH, msg, msgLength, PQC_SDLS_myPkGround) != 0)
    // {
    //     PQC_SDLS_myData.State = PQC_SDLS_MY_STATE_IDLE;
    //     return PQC_SDLS_MY_SECURITY_ERROR;
    // }
    (void)pSig;

    /* ct is written straight into the reply buffer, so no extra copy is needed. */
    pCt = PQC_SDLS_myAllocReply(&pBuf, PQC_SDLS_MY_PID_HS_KEX, PQC_SDLS_MY_KEM_CT_LENGTH);
    if (pCt == NULL)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC no buffer for HS_KEX_R");
        return PQC_SDLS_MY_SEND_ERROR;
    }

    /* The random seed m stays inside crypto_kem_enc and is erased there. */
    // crypto_kem_enc(pCt, ss, pEk);
    // KDF(ss) -> PQC_SDLS_myData.KeyUp, PQC_SDLS_myData.KeyDn
    (void)pEk;
    CFE_PSP_MemSet(pCt, 0, PQC_SDLS_MY_KEM_CT_LENGTH); /* Placeholder ct until ML-KEM is linked */

    /* Erase ss here; ek and Sig_G are erased with the joined buffer by the caller. */
    CFE_PSP_MemSet(ss, 0, sizeof(ss));

    PQC_SDLS_myData.State = PQC_SDLS_MY_STATE_WAIT_ACTIVATE;
    CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION, "CI: PQC HS_KEX done, ct %u bytes",
                      (unsigned int)PQC_SDLS_MY_KEM_CT_LENGTH);

    return PQC_SDLS_mySendReply(pBuf);
}

/* 5. Activation, Rekey, Start: puts K_up and K_dn into the SPI 1 SA. No reply. */
static int32 PQC_SDLS_myHandleActivate(uint32 valueLength)
{
    if (PQC_SDLS_myData.State != PQC_SDLS_MY_STATE_WAIT_ACTIVATE)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC Activation without HS_KEX");
        return PQC_SDLS_MY_INVALID_STATE;
    }
    if (valueLength != 0)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC Activation bad length %u",
                          (unsigned int)valueLength);
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    /* Load the session keys into the SPI 1 SA, start it, then erase the local copies. */
    // SA[PQC_SDLS_MY_SPI_SESSION] <- KeyUp (uplink), KeyDn (downlink); SA state = OPERATIONAL
    // CFE_PSP_MemSet(PQC_SDLS_myData.KeyUp, 0, PQC_SDLS_MY_SESSION_KEY_LENGTH);
    // CFE_PSP_MemSet(PQC_SDLS_myData.KeyDn, 0, PQC_SDLS_MY_SESSION_KEY_LENGTH);

    PQC_SDLS_myData.SessionActive = true;
    PQC_SDLS_myData.State         = PQC_SDLS_MY_STATE_IDLE;
    CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION, "CI: PQC SPI %d session active",
                      PQC_SDLS_MY_SPI_SESSION);

    return PQC_SDLS_MY_SUCCESS;
}

/* 6. Ping -> 7. Ping reply. Both use the SPI 1 SA, which confirms the session keys. */
static int32 PQC_SDLS_myHandlePing(uint32 valueLength)
{
    CFE_SB_Buffer_t *pBuf;

    if (!PQC_SDLS_myData.SessionActive)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC Ping without active session");
        return PQC_SDLS_MY_INVALID_STATE;
    }
    if (valueLength != 0)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC Ping bad length %u",
                          (unsigned int)valueLength);
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    if (PQC_SDLS_myAllocReply(&pBuf, PQC_SDLS_MY_PID_PING, 0) == NULL)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC no buffer for Ping reply");
        return PQC_SDLS_MY_SEND_ERROR;
    }

    CFE_EVS_SendEvent(CI_LAB_PQC_EP_INF_EID, CFE_EVS_EventType_INFORMATION, "CI: PQC Ping");
    return PQC_SDLS_mySendReply(pBuf);
}

/* Stores one segment. Segments are marked with the Space Packet Sequence Flags
 * and must arrive in order with consecutive Sequence Counts. */
static int32 PQC_SDLS_myJoin(uint8 seqFlags, uint16 seqCount, const uint8 *pData, uint32 dataLength)
{
    if ((seqFlags == PQC_SDLS_MY_SEQ_FIRST) || (seqFlags == PQC_SDLS_MY_SEQ_UNSEGMENTED))
    {
        PQC_SDLS_myResetJoin();
        PQC_SDLS_myData.Joining = (seqFlags == PQC_SDLS_MY_SEQ_FIRST);
    }
    else if (!PQC_SDLS_myData.Joining || (seqCount != PQC_SDLS_myData.NextSeqCount))
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP segment out of order (%u)",
                          (unsigned int)seqCount);
        PQC_SDLS_myResetJoin();
        return PQC_SDLS_MY_INVALID_SEQ;
    }

    if (PQC_SDLS_myData.EpLength + dataLength > sizeof(PQC_SDLS_myData.EpBuffer))
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP longer than %u bytes",
                          (unsigned int)sizeof(PQC_SDLS_myData.EpBuffer));
        PQC_SDLS_myResetJoin();
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    CFE_PSP_MemCpy(PQC_SDLS_myData.EpBuffer + PQC_SDLS_myData.EpLength, pData, dataLength);
    PQC_SDLS_myData.EpLength += dataLength;
    PQC_SDLS_myData.NextSeqCount = (seqCount + 1) & 0x3FFF;

    if ((seqFlags == PQC_SDLS_MY_SEQ_FIRST) || (seqFlags == PQC_SDLS_MY_SEQ_CONTINUATION))
    {
        return PQC_SDLS_MY_IN_PROGRESS;
    }

    PQC_SDLS_myData.Joining = false;
    return PQC_SDLS_MY_SUCCESS;
}

/* Checks the Tag and Length of the joined packet and calls its procedure. */
static int32 PQC_SDLS_myDispatch(void)
{
    const uint8 *pTlv = PQC_SDLS_myData.EpBuffer;
    uint32       lengthBits;
    uint32       valueLength;
    const uint8 *pValue = pTlv + PQC_SDLS_MY_TLV_HDR_LENGTH;

    if (PQC_SDLS_myData.EpLength < PQC_SDLS_MY_TLV_HDR_LENGTH)
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP too short (%u)",
                          (unsigned int)PQC_SDLS_myData.EpLength);
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    /* The Length field counts bits, as in NOS3 crypto.c:1009-1018. */
    lengthBits  = ((uint32)pTlv[1] << 8) | pTlv[2];
    valueLength = lengthBits / 8;
    if (((lengthBits % 8) != 0) || (PQC_SDLS_MY_TLV_HDR_LENGTH + valueLength != PQC_SDLS_myData.EpLength))
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR,
                          "CI: PQC EP length %u bits != received %u bytes", (unsigned int)lengthBits,
                          (unsigned int)(PQC_SDLS_myData.EpLength - PQC_SDLS_MY_TLV_HDR_LENGTH));
        return PQC_SDLS_MY_INVALID_LENGTH;
    }

    if ((PQC_SDLS_MY_TAG_TYPE(pTlv[0]) != PQC_SDLS_MY_TYPE_COMMAND) || (PQC_SDLS_MY_TAG_UF(pTlv[0]) != 1))
    {
        CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP bad tag 0x%02x",
                          (unsigned int)pTlv[0]);
        return PQC_SDLS_MY_INVALID_TAG;
    }

    switch (PQC_SDLS_MY_TAG_PID(pTlv[0]))
    {
        case PQC_SDLS_MY_PID_HS_REQ:
            return PQC_SDLS_myHandleHsReq(pValue, valueLength);
        case PQC_SDLS_MY_PID_HS_KEX:
            return PQC_SDLS_myHandleHsKex(pValue, valueLength);
        case PQC_SDLS_MY_PID_ACTIVATE:
            return PQC_SDLS_myHandleActivate(valueLength);
        case PQC_SDLS_MY_PID_PING:
            return PQC_SDLS_myHandlePing(valueLength);
        default:
            CFE_EVS_SendEvent(CI_LAB_PQC_EP_ERR_EID, CFE_EVS_EventType_ERROR, "CI: PQC EP unknown PID %u",
                              (unsigned int)PQC_SDLS_MY_TAG_PID(pTlv[0]));
            return PQC_SDLS_MY_INVALID_TAG;
    }
}

int32 PQC_SDLS_myProcessEp(const uint8 *pPacket, int32 packetSize)
{
    uint8  seqFlags = (pPacket[2] >> 6) & 0x03;
    uint16 seqCount = (uint16)(((pPacket[2] & 0x3F) << 8) | pPacket[3]);
    int32  status;

    /* EPs must use SPI 0 (SPI 1 for Ping), like valid_ep_sa in NOS3 crypto.c:903-907.
     * SDLS is disabled, so there is no SPI to check yet. */
    // if (spi != PQC_SDLS_MY_SPI_HANDSHAKE) { return PQC_SDLS_MY_SECURITY_ERROR; }

    status = PQC_SDLS_myJoin(seqFlags, seqCount, pPacket + PQC_SDLS_MY_SPP_HDR_LENGTH,
                             (uint32)(packetSize - PQC_SDLS_MY_SPP_HDR_LENGTH));
    if (status != PQC_SDLS_MY_SUCCESS)
    {
        return status;
    }

    status = PQC_SDLS_myDispatch();

    /* The joined packet may hold ek and Sig_G, so it is erased after use. */
    PQC_SDLS_myResetJoin();

    return status;
}
