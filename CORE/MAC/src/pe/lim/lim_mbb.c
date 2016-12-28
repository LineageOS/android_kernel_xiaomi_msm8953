/*
 * Copyright (c) 2017, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *  * Neither the name of The Linux Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "aniGlobal.h"
#include "limTypes.h"
#include "limUtils.h"
#include "limFT.h"
#include "limSendMessages.h"

/**
 * lim_post_pre_auth_reassoc_rsp() -Posts preauth_reassoc response to SME
 * @mac: MAC context
 * @status: status
 * @session_entry: session entry
 *
 * This function process preauth request received from CSR
 */
void lim_post_pre_auth_reassoc_rsp(tpAniSirGlobal mac,
     tSirRetStatus status, tpPESession session_entry)
{
    tpSirFTPreAuthRsp pre_auth_rsp;
    tSirMsgQ mmh_msg;
    tANI_U16 rsp_len = sizeof(tSirFTPreAuthRsp);

    pre_auth_rsp = (tpSirFTPreAuthRsp)vos_mem_malloc(rsp_len);
    if (NULL == pre_auth_rsp) {
        limLog(mac, LOGE, FL("Failed to allocate memory"));
        return;
    }

    vos_mem_zero(pre_auth_rsp, rsp_len);
    pre_auth_rsp->messageType = eWNI_SME_MBB_PRE_AUTH_REASSOC_RSP;
    pre_auth_rsp->length = (tANI_U16)rsp_len;
    pre_auth_rsp->status = status;

    if (session_entry)
        pre_auth_rsp->smeSessionId = session_entry->smeSessionId;

    /* The bssid of the AP we are sending Auth1 to. */
    if (mac->ft.ftPEContext.pFTPreAuthReq)
        sirCopyMacAddr(pre_auth_rsp->preAuthbssId,
                       mac->ft.ftPEContext.pFTPreAuthReq->preAuthbssId);

    if (status != eSIR_SUCCESS) {
        limLog(mac, LOG1, "Pre-Auth Failed, Cleanup!");
        limFTCleanup(mac);
    }

    mmh_msg.type = pre_auth_rsp->messageType;
    mmh_msg.bodyptr = pre_auth_rsp;
    mmh_msg.bodyval = 0;

    limLog(mac, LOG1,
           FL("Posted Auth Rsp to SME with status of 0x%x"), status);

    limSysProcessMmhMsgApi(mac, &mmh_msg, ePROT);
}

/*
 * lim_process_preauth_mbb_result() -process pre auth result
 * @mac: MAC context
 * @status: status
 * @data: pointer to data
 *
 * This function invokes resume callback
 */
static inline void lim_process_preauth_mbb_result(tpAniSirGlobal mac,
     eHalStatus status, tANI_U32 *data)
{
    tpPESession session_entry;

    if (!mac->ft.ftPEContext.pFTPreAuthReq) {
        limLog(mac, LOG1, "Pre-Auth request is NULL!");
        return;
    }

    session_entry = (tpPESession)data;

    /* Post the FT Pre Auth Response to SME in case of failure*/
    if (mac->ft.ftPEContext.ftPreAuthStatus == eSIR_FAILURE) {
        lim_post_pre_auth_reassoc_rsp(mac,
                  mac->ft.ftPEContext.ftPreAuthStatus, session_entry);
        return;
    }

    /* Flow for preauth success */
    limFTSetupAuthSession(mac, session_entry);
}

/*
 * lim_perform_post_preauth_mbb_channel_change() -invokes resume callback
 * @mac: MAC context
 * @status: status
 * @data: pointer to data
 * @session_entry: session entry
 *
 * This function invokes resume callback after successful reception of
 * pre auth
 */
static inline
void lim_perform_post_preauth_mbb_channel_change(tpAniSirGlobal mac,
     eHalStatus status, tANI_U32 *data, tpPESession session_entry)
{
    peSetResumeChannel(mac, 0, 0);
    limResumeLink(mac, lim_process_preauth_mbb_result,
                                (tANI_U32 *)session_entry);
}

/*
 * lim_handle_pre_auth_mbb_rsp() -handles preauth response
 * @mac: MAC context
 * @status: status of message
 * @session_entry: session entry
 *
 * This function process preauth response
 */
void lim_handle_pre_auth_mbb_rsp(tpAniSirGlobal mac,
     tSirRetStatus status, tpPESession session_entry)
{
    tpPESession ft_session_entry;
    tANI_U8 session_id;
    tpSirBssDescription  bss_description;

    mac->ft.ftPEContext.ftPreAuthStatus = status;

    mac->ft.ftPEContext.saved_auth_rsp_length = 0;

    limLog(mac, LOG1, FL("preauth status %d"),
                         mac->ft.ftPEContext.ftPreAuthStatus);

    /* Create FT session for the re-association at this point */
    if (mac->ft.ftPEContext.ftPreAuthStatus == eSIR_SUCCESS) {
        bss_description = mac->ft.ftPEContext.pFTPreAuthReq->pbssDescription;
        if((ft_session_entry = peCreateSession(mac, bss_description->bssId,
                                  &session_id, mac->lim.maxStation)) == NULL) {
            limLog(mac, LOGE,
                   FL("session can not be created for pre-auth AP"));
            mac->ft.ftPEContext.ftPreAuthStatus = eSIR_FAILURE;
            goto out;
        }
        ft_session_entry->peSessionId = session_id;
        sirCopyMacAddr(ft_session_entry->selfMacAddr,
                                 session_entry->selfMacAddr);
        sirCopyMacAddr(ft_session_entry->limReAssocbssId,
                                     bss_description->bssId);
        ft_session_entry->bssType = session_entry->bssType;

        if (ft_session_entry->bssType == eSIR_INFRASTRUCTURE_MODE)
            ft_session_entry->limSystemRole = eLIM_STA_ROLE;

        ft_session_entry->limSmeState = eLIM_SME_WT_REASSOC_STATE;
        mac->ft.ftPEContext.pftSessionEntry = ft_session_entry;
        limLog(mac, LOG1,"%s:created session (%p) with id = %d",
               __func__, ft_session_entry, ft_session_entry->peSessionId);

        /* Update the ReAssoc BSSID of the current session */
        sirCopyMacAddr(session_entry->limReAssocbssId, bss_description->bssId);
        limPrintMacAddr(mac, session_entry->limReAssocbssId, LOG1);
    }
out:
    if (session_entry->currentOperChannel !=
        mac->ft.ftPEContext.pFTPreAuthReq->preAuthchannelNum) {
        limChangeChannelWithCallback(mac, session_entry->currentOperChannel,
              lim_perform_post_preauth_mbb_channel_change, NULL, session_entry);
     } else {
        /* Link needs to be resumed as link was suspended for same channel */
        peSetResumeChannel(mac, 0, 0);
        limResumeLink(mac, lim_process_preauth_mbb_result,
                                           (tANI_U32 *)session_entry);
     }
}

/**
 * lim_process_preauth_mbb_rsp_timeout() -Process preauth response timeout
 * @mac: MAC context
 *
 * This function is called if preauth response is not received from the AP
 * within timeout
 */
void lim_process_preauth_mbb_rsp_timeout(tpAniSirGlobal mac)
{
    tpPESession session_entry;

    /*
     * Pre auth is failed. Need to resume link and get back on
     * to home channel.
     */
    limLog(mac, LOG1, FL("Pre-Auth MBB Time Out!!!!"));

    if((session_entry = peFindSessionBySessionId(mac,
        mac->lim.limTimers.glim_pre_auth_mbb_rsp_timer.sessionId))== NULL) {
        limLog(mac, LOGE, FL("session does not exist for given session id"));
        return;
    }

    /*
     * To handle the race condition where we recieve preauth rsp after
     * timer has expired.
     */
    if (mac->ft.ftPEContext.pFTPreAuthReq == NULL) {
        limLog(mac, LOGE, FL("Auth Rsp might already be posted to SME"
               "and cleanup done! sessionId:%d"),
                mac->lim.limTimers.glim_pre_auth_mbb_rsp_timer.sessionId);
        return;
    }

    if (eANI_BOOLEAN_TRUE ==
         mac->ft.ftPEContext.pFTPreAuthReq->bPreAuthRspProcessed) {
         limLog(mac, LOGE,
                FL("Auth rsp already posted to SME session %p"), session_entry);
         return;
    } else {
    /*
     * Here we are sending preauth rsp with failure state
     * and which is forwarded to SME. Now, if we receive an preauth
     * resp from AP with success it would create a FT pesession, but
     * will be dropped in SME leaving behind the pesession.
     * Mark Preauth rsp processed so that any rsp from AP is dropped in
     * limProcessAuthFrameNoSession.
     */
     limLog(mac,LOG1,
            FL("Auth rsp not yet posted to SME session %p)"), session_entry);
            mac->ft.ftPEContext.pFTPreAuthReq->bPreAuthRspProcessed =
           eANI_BOOLEAN_TRUE;
     }
     /*
      * Ok, so attempted a Pre-Auth and failed. If we are off channel. We need
      * to get back.
      */
     lim_handle_pre_auth_mbb_rsp(mac, eSIR_FAILURE, session_entry);
 }

/**
 * lim_perform_pre_auth_reassoc() -Sends preauth request
 * @mac: MAC context
 * @status: status of message
 * @data: gives information of session
 * @session_entry: session entry
 *
 * This function process preauth request received from CSR
 */
static inline
void lim_perform_pre_auth_reassoc(tpAniSirGlobal mac, eHalStatus status,
     tANI_U32 *data, tpPESession session_entry)
{
    tSirMacAuthFrameBody authFrame;

    if (status != eHAL_STATUS_SUCCESS) {
        limLog(mac, LOGE,
               FL("Change channel not successful for pre-auth"));
        goto preauth_fail;
    }

    limLog(mac, LOGE,
           FL("session id %d"), session_entry->peSessionId);

    mac->ft.ftPEContext.psavedsessionEntry = session_entry;

    authFrame.authAlgoNumber = eSIR_OPEN_SYSTEM;
    authFrame.authTransactionSeqNumber = SIR_MAC_AUTH_FRAME_1;
    authFrame.authStatusCode = 0;

    /* Start timer here to come back to operating channel. */
    mac->lim.limTimers.glim_pre_auth_mbb_rsp_timer.sessionId =
                                                session_entry->peSessionId;

    limSendAuthMgmtFrame(mac, &authFrame,
         mac->ft.ftPEContext.pFTPreAuthReq->preAuthbssId,
         LIM_NO_WEP_IN_FC, session_entry, eSIR_FALSE);

    if(TX_SUCCESS !=
          tx_timer_activate(&mac->lim.limTimers.glim_pre_auth_mbb_rsp_timer)) {
       limLog(mac, LOGE, FL("Pre Auth MBB Rsp Timer Start Failed"));

       mac->ft.ftPEContext.psavedsessionEntry = NULL;
       goto preauth_fail;
    }

    return;

preauth_fail:
     lim_handle_pre_auth_mbb_rsp(mac, eSIR_FAILURE, session_entry);
     return;
}

/**
 * pre_auth_mbb_suspend_link_handler() -Handler for suspend link
 * @mac: MAC context
 * @status: status of message
 * @data: gives information of session
 *
 * This function process preauth request received from CSR
 */
static inline
void pre_auth_mbb_suspend_link_handler(tpAniSirGlobal mac,
     eHalStatus status, tANI_U32 *data)
{
    tpPESession session_entry;

    if (status != eHAL_STATUS_SUCCESS) {
        limLog(mac, LOGE, FL("Link suspend failed"));
        lim_post_pre_auth_reassoc_rsp(mac, eSIR_FAILURE, (tpPESession)data);
        return;
    }

    session_entry = (tpPESession)data;

    if (session_entry->currentOperChannel !=
                mac->ft.ftPEContext.pFTPreAuthReq->preAuthchannelNum) {
        limChangeChannelWithCallback(mac,
                mac->ft.ftPEContext.pFTPreAuthReq->preAuthchannelNum,
                lim_perform_pre_auth_reassoc, NULL, session_entry);
        return;
    } else {
        lim_perform_pre_auth_reassoc(mac, eHAL_STATUS_SUCCESS,
                                  NULL, session_entry);
        return;
    }
}

/**
 * lim_process_pre_auth_reassoc_req() -Process preauth request
 * @hal: HAL context
 * @msg: message
 *
 * This function process preauth request received from CSR
 */
void lim_process_pre_auth_reassoc_req(tpAniSirGlobal mac, tpSirMsgQ msg)
{
    tpPESession session_entry;
    tANI_U8 session_id;

    limFTInit(mac);

    /* Can set it only after sending auth */
    mac->ft.ftPEContext.ftPreAuthStatus = eSIR_FAILURE;

    /* We need information from the Pre-Auth Req. Lets save that */
    mac->ft.ftPEContext.pFTPreAuthReq = (tpSirFTPreAuthReq)msg->bodyptr;
    if (!mac->ft.ftPEContext.pFTPreAuthReq) {
        limLog(mac, LOGE,
               FL("pFTPreAuthReq is NULL"));
        lim_post_pre_auth_reassoc_rsp(mac, eSIR_FAILURE, NULL);
        return;
    }

    /* Get the current session entry */
    session_entry = peFindSessionByBssid(mac,
                    mac->ft.ftPEContext.pFTPreAuthReq->currbssId, &session_id);
    if (session_entry == NULL) {
        limLog(mac, LOGE,
               FL("Unable to find session for the following bssid"));
        limPrintMacAddr(mac,
                        mac->ft.ftPEContext.pFTPreAuthReq->currbssId, LOGE);

        /* Post the pre auth response to SME */
        lim_post_pre_auth_reassoc_rsp(mac, eSIR_FAILURE, NULL);
    }

    limLog(mac, LOG1,
           FL("set link with eSIR_LINK_PRE_AUTH_REASSOC_STATE"));

    if (limSetLinkState(mac, eSIR_LINK_PRE_AUTH_REASSOC_STATE,
                        session_entry->bssId, session_entry->selfMacAddr,
                        NULL, NULL) != eSIR_SUCCESS) {
        limLog(mac, LOGE,
               FL("set link failed for eSIR_LINK_PRE_AUTH_REASSOC_STATE"));
        lim_post_pre_auth_reassoc_rsp(mac, eSIR_FAILURE, NULL);
        return;
    }

    /*
     * Suspend link for same channel or different channel so that STA
     * can be in power save for connected AP.
     */
    limLog(mac, LOG1,
           FL("pre-auth on channel %d (session %p) currentOperChannel %d"),
           mac->ft.ftPEContext.pFTPreAuthReq->preAuthchannelNum,
           session_entry, session_entry->currentOperChannel);
    limSuspendLink(mac, eSIR_CHECK_ROAMING_SCAN,
                   pre_auth_mbb_suspend_link_handler,
                  (tANI_U32 *)session_entry);
}
