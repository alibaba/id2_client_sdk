/*
 * Copyright (C) 2018 Alibaba Group Holding Limited
 */


#include <windows.h>
#include <winscard.h>
#include <string.h>
#include "se_driver.h"

static const char* g_readerName = "OMNIKEY Smart Card Reader USB 0";
static SCARDCONTEXT g_scardContext;
static SCARDHANDLE g_hCard;
static const SCARD_IO_REQUEST* g_lpIoSendPci;

irot_result_t se_open_session(void** handle)
{
    LONG lRet;
    DWORD dwPro;
    lRet = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &g_scardContext);
    if (lRet != SCARD_S_SUCCESS)
    {
        return IROT_ERROR_COMMUNICATION;
    }
    dwPro = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    lRet = SCardConnect(g_scardContext, g_readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &g_hCard, &dwPro);
    if (lRet != SCARD_S_SUCCESS)
    {
        return IROT_ERROR_COMMUNICATION;
    }
    switch (dwPro)
    {
    case SCARD_PROTOCOL_T0:
        {
            g_lpIoSendPci = SCARD_PCI_T0;
        }
        break;
    case SCARD_PROTOCOL_T1:
        {
            g_lpIoSendPci = SCARD_PCI_T1;
        }
        break;
    default:
        {
            g_lpIoSendPci = SCARD_PCI_RAW;
        }
        break;
    }
    return IROT_SUCCESS;
}

irot_result_t se_transmit(void* handle, const uint8_t* cmd_apdu, const uint32_t cmd_len, uint8_t* rsp_buf, uint32_t* rsp_len)
{
    LONG lRet;

    lRet = SCardTransmit(g_hCard, g_lpIoSendPci, cmd_apdu, cmd_len, NULL, rsp_buf, (LPDWORD)rsp_len);
    if (lRet != SCARD_S_SUCCESS)
    {
        return IROT_ERROR_COMMUNICATION;
    }
    else
    {
        return IROT_SUCCESS;
    }
}

irot_result_t se_close_session(void* handle)
{
    LONG lRet;

    lRet = SCardDisconnect(g_hCard, SCARD_UNPOWER_CARD);
    if (lRet != SCARD_S_SUCCESS)
    {
        return IROT_ERROR_COMMUNICATION;
    }
    lRet = SCardReleaseContext(g_scardContext);
    if (lRet != SCARD_S_SUCCESS)
    {
        return IROT_ERROR_COMMUNICATION;
    }
    return IROT_SUCCESS;
}
