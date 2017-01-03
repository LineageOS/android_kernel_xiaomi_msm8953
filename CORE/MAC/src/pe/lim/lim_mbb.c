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
#include "limAssocUtils.h"
#include "limSerDesUtils.h"
#include "limSmeReqUtils.h"


#define PREAUTH_REASSOC_TIMEOUT 500


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
 * lim_reassoc_fail_cleanup() -handles cleanup during reassoc failure
 * @mac: MAC context
 * @status: status
 * @data: pointer to data
 *
 * This function handles cleanup during reassoc failure
 */
void lim_reassoc_fail_cleanup(tpAniSirGlobal mac,
     eHalStatus status, tANI_U32 *data)
{
    tpPESession session_entry;

    session_entry = (tpPESession)data;

    if (!mac->ft.ftPEContext.pFTPreAuthReq) {
        limLog(mac, LOGE, FL("pFTPreAuthReq is NULL"));
        return;
    }

    if (dphDeleteHashEntry(mac,
               mac->ft.ftPEContext.pFTPreAuthReq->preAuthbssId,
               DPH_STA_HASH_INDEX_PEER,
               &session_entry->dph.dphHashTable) != eSIR_SUCCESS) {
        limLog(mac, LOGE, FL("error deleting hash entry"));
    }

    /* Delete session as session was created during preauth success */
    peDeleteSession(mac, session_entry);

    /* Add bss parameter cleanup happens as part of this processing*/
    lim_post_pre_auth_reassoc_rsp(mac,
                eSIR_FAILURE, NULL);
}

/*
 * lim_perform_post_reassoc_mbb_channel_change() -invokes resume callback
 * @mac: MAC context
 * @status: status
 * @data: pointer to data
 * @session_entry: session entry
 *
 * This function invokes resume callback
 */
void lim_perform_post_reassoc_mbb_channel_change(tpAniSirGlobal mac,
     eHalStatus status, tANI_U32 *data, tpPESession session_entry)
{
    peSetResumeChannel(mac, 0, 0);
    limResumeLink(mac, lim_reassoc_fail_cleanup,
                                (tANI_U32 *)session_entry);
}

/*
 * lim_handle_reassoc_mbb_fail() -handles reassoc failure
 * @mac: MAC context
 * @session_entry: session entry
 *
 * This function handles reassoc failure
 */
void lim_handle_reassoc_mbb_fail(tpAniSirGlobal mac,
     tpPESession session_entry)
{
    /* Change channel if required as channel might be changed during preauth */
    if (session_entry->currentOperChannel !=
            mac->ft.ftPEContext.pFTPreAuthReq->preAuthchannelNum) {
        limChangeChannelWithCallback(mac, session_entry->currentOperChannel,
           lim_perform_post_reassoc_mbb_channel_change, NULL, session_entry);
    } else {
       /*
        * Link needs to be resumed as link was suspended
        * for same channel during preauth.
        */
       peSetResumeChannel(mac, 0, 0);
       limResumeLink(mac, lim_reassoc_fail_cleanup,
                     (tANI_U32 *)session_entry);
    }
}

/*
 * lim_handle_reassoc_mbb_success() -handles reassoc success
 * @mac: MAC context
 * @session_entry: session entry
 * @assoc_rsp: pointer to assoc response
 * @sta_ds : station entry
 *
 * This function handles reassoc success
 */
void lim_handle_reassoc_mbb_success(tpAniSirGlobal mac,
     tpPESession session_entry, tpSirAssocRsp  assoc_rsp, tpDphHashNode sta_ds)
{

    limUpdateAssocStaDatas(mac, sta_ds, assoc_rsp, session_entry);

    /* Store assigned AID for TIM processing */
    session_entry->limAID = assoc_rsp->aid & 0x3FFF;

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
    tpPESession session_entry, ft_session_entry;
    tpDphHashNode sta_ds;
    tAddBssParams *add_bss_params;
    tSirSmeJoinReq *reassoc_req;
    tLimMlmReassocReq *mlm_reassoc_req;
    tANI_U16 caps;
    tANI_U16 nSize;
    tpSirSmeJoinReq pReassocReq = NULL;

    if (!mac->ft.ftPEContext.pFTPreAuthReq) {
        limLog(mac, LOG1, "Pre-Auth request is NULL!");
        goto end;
    }

    session_entry = (tpPESession)data;

    /* Post the FT Pre Auth Response to SME in case of failure*/
    if (mac->ft.ftPEContext.ftPreAuthStatus == eSIR_FAILURE)
        goto end;

    /* Flow for preauth success */
    limFTSetupAuthSession(mac, session_entry);

    /*
     * Prepare reassoc request. Memory allocated for tSirSmeJoinReq
     *reassoc_req in csr_fill_reassoc_req. Free that memory here.
     */
    mac->sme.roaming_mbb_callback(mac, mac->ft.ftSmeContext.smeSessionId,
                            mac->ft.ftPEContext.pFTPreAuthReq->pbssDescription,
                            &reassoc_req, SIR_PREPARE_REASSOC_REQ);
    if (reassoc_req  == NULL) {
        limLog(mac, LOGE,
               FL("reassoc req is NULL"));
        goto end;
    }

    nSize = __limGetSmeJoinReqSizeForAlloc((tANI_U8 *) reassoc_req);
    pReassocReq = vos_mem_malloc(nSize);
    if ( NULL == pReassocReq )
    {
        limLog(mac, LOGE,
               FL("call to AllocateMemory failed for pReassocReq"));
        goto end;
    }
    vos_mem_set((void *) pReassocReq, nSize, 0);
    if ((limJoinReqSerDes(mac, (tpSirSmeJoinReq) pReassocReq,
                          (tANI_U8 *) reassoc_req) == eSIR_FAILURE) ||
        (!limIsSmeJoinReqValid(mac,
                               (tpSirSmeJoinReq) pReassocReq)))
    {
        limLog(mac, LOGE,
               FL("received SME_REASSOC_REQ with invalid data"));
        goto end;
    }

    ft_session_entry = mac->ft.ftPEContext.pftSessionEntry;

    ft_session_entry->pLimReAssocReq = pReassocReq;
    vos_mem_free(reassoc_req);

    add_bss_params = mac->ft.ftPEContext.pAddBssReq;

    mlm_reassoc_req = vos_mem_malloc(sizeof(tLimMlmReassocReq));
    if (NULL == mlm_reassoc_req) {
        limLog(mac, LOGE,
               FL("call to AllocateMemory failed for mlmReassocReq"));
        goto end;
    }

    vos_mem_copy(mlm_reassoc_req->peerMacAddr,
                 ft_session_entry->limReAssocbssId,
                 sizeof(tSirMacAddr));
    mlm_reassoc_req->reassocFailureTimeout = PREAUTH_REASSOC_TIMEOUT;

    if (cfgGetCapabilityInfo(mac, &caps, ft_session_entry) != eSIR_SUCCESS) {
        limLog(mac, LOGE, FL("could not retrieve Capabilities value"));
        vos_mem_free(mlm_reassoc_req);
        goto end;
    }

    lim_update_caps_info_for_bss(mac, &caps,
                        reassoc_req->bssDescription.capabilityInfo);

    limLog(mac, LOG1, FL("Capabilities info Reassoc: 0x%X"), caps);

    mlm_reassoc_req->capabilityInfo = caps;
    mlm_reassoc_req->sessionId = ft_session_entry->peSessionId;
    mlm_reassoc_req->listenInterval = WNI_CFG_LISTEN_INTERVAL_STADEF;

    if ((sta_ds = dphAddHashEntry(mac, add_bss_params->bssId,
                  DPH_STA_HASH_INDEX_PEER,
                  &ft_session_entry->dph.dphHashTable)) == NULL) {
        limLog(mac, LOGE, FL("could not add hash entry at DPH"));
        limPrintMacAddr(mac, add_bss_params->bssId, LOGE);
        vos_mem_free(mlm_reassoc_req);
        goto end;
    }

    /* Start timer here to handle reassoc timeout */
    mac->lim.limTimers.glim_reassoc_mbb_rsp_timer.sessionId =
                                                ft_session_entry->peSessionId;

    if(TX_SUCCESS !=
          tx_timer_activate(&mac->lim.limTimers.glim_reassoc_mbb_rsp_timer)) {
       limLog(mac, LOGE, FL("Reassoc MBB Rsp Timer Start Failed"));

       if (ft_session_entry->pLimReAssocReq) {
           vos_mem_free(ft_session_entry->pLimReAssocReq);
           ft_session_entry->pLimReAssocReq = NULL;
       }

       vos_mem_free(mlm_reassoc_req);
       goto end;
    }

    /* To do: Add changes for reassoc fail timer */
    limSendReassocReqWithFTIEsMgmtFrame(mac,
                     mlm_reassoc_req, ft_session_entry);

    ft_session_entry->limMlmState = eLIM_MLM_WT_REASSOC_RSP_STATE;

    limLog(mac, LOG1,  FL("Set the mlm state to %d session=%d"),
           ft_session_entry->limMlmState, ft_session_entry->peSessionId);
    return;

end:
    lim_handle_reassoc_mbb_fail(mac, ft_session_entry);
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

        /* Prepare session for roamable AP */
        lim_process_preauth_mbb_result(mac,
               mac->ft.ftPEContext.ftPreAuthStatus, (tANI_U32 *)session_entry);
        return;
    }
out:
    /* This sequence needs to be executed in case of failure*/
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
 * lim_process_reassoc_mbb_rsp_timeout() -Process reassoc response timeout
 * @mac: MAC context
 *
 * This function is called if preauth response is not received from the
 * AP within timeout
 */
void lim_process_reassoc_mbb_rsp_timeout(tpAniSirGlobal mac)
{
    tpPESession session_entry, ft_session_entry;
    tANI_U8 session_id;

    if((ft_session_entry = peFindSessionBySessionId(mac,
        mac->lim.limTimers.glim_reassoc_mbb_rsp_timer.sessionId))== NULL) {
        limLog(mac, LOGE,
               FL("ft session does not exist for given session id %d"),
               mac->lim.limTimers.glim_reassoc_mbb_rsp_timer.sessionId);
        return;
    }

    limLog(mac, LOG1, FL("Reassoc timeout happened in state %d"),
                         ft_session_entry->limMlmState);

    if((session_entry = peFindSessionByBssid(mac,
          mac->ft.ftPEContext.pFTPreAuthReq->currbssId, &session_id))== NULL) {
        limLog(mac, LOGE,
               FL("session does not exist for given BSSID" MAC_ADDRESS_STR),
               MAC_ADDR_ARRAY(mac->ft.ftPEContext.pFTPreAuthReq->currbssId));
        return;
    }

    lim_handle_reassoc_mbb_fail(mac, ft_session_entry);

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

