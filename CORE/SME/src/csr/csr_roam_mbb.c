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
#include "smeInside.h"
#include "csrInsideApi.h"
#include "smsDebug.h"
#include "macTrace.h"
#include "csrNeighborRoam.h"

#define PREAUTH_REASSOC_MBB_TIMER_VALUE    60

#define CSR_NEIGHBOR_ROAM_STATE_TRANSITION(newState)\
{\
    mac->roam.neighborRoamInfo.prevNeighborRoamState = mac->roam.neighborRoamInfo.neighborRoamState;\
    mac->roam.neighborRoamInfo.neighborRoamState = newState;\
    VOS_TRACE (VOS_MODULE_ID_SME, VOS_TRACE_LEVEL_DEBUG, \
               FL("Neighbor Roam Transition from state %s ==> %s"), \
               csrNeighborRoamStateToString (mac->roam.neighborRoamInfo.prevNeighborRoamState), \
               csrNeighborRoamStateToString (newState));\
}

/**
 * csr_roam_issue_preauth_reassoc_req() -Prepares preauth request
 * @hal: HAL context
 * @session_id: session id
 * @bss_description: BSS description
 *
 * This function prepares preauth request and sends request to PE
 *
 * Return: eHAL_STATUS_SUCCESS on success,
 *           : eHAL_STATUS_RESOURCES when resource allocation is failure
 *           : eHAL_STATUS_FAILURE otherwise
 */
eHalStatus csr_roam_issue_preauth_reassoc_req(tHalHandle hal,
                     tANI_U32 session_id, tpSirBssDescription bss_description)
{
    tpAniSirGlobal mac = PMAC_STRUCT(hal);
    tpSirFTPreAuthReq pre_auth_req;
    tANI_U16 auth_req_len = 0;
    tCsrRoamSession *session = CSR_GET_SESSION(mac, session_id);

    auth_req_len = sizeof(tSirFTPreAuthReq);
    pre_auth_req = (tpSirFTPreAuthReq)vos_mem_malloc(auth_req_len);
    if (NULL == pre_auth_req) {
        smsLog(mac, LOGE,
               FL("Memory allocation for Preauth request failed"));
        return eHAL_STATUS_RESOURCES;
    }

    /*
     * Save the SME Session ID here. We need it while processing
     * the preauth response.
     */
    mac->ft.ftSmeContext.smeSessionId = session_id;
    vos_mem_zero(pre_auth_req, auth_req_len);

    pre_auth_req->pbssDescription = (tpSirBssDescription)vos_mem_malloc(
            sizeof(bss_description->length) + bss_description->length);

    pre_auth_req->messageType =
                     pal_cpu_to_be16(eWNI_SME_MBB_PRE_AUTH_REASSOC_REQ);

    pre_auth_req->preAuthchannelNum = bss_description->channelId;

    /*
     * Set is_preauth_lfr_mbb which will be checked in
     * limProcessAuthFrameNoSession
     */
    mac->ft.ftSmeContext.is_preauth_lfr_mbb = true;
    smsLog(mac, LOG1, FL("is_preauth_lfr_mbb %d"),
           mac->ft.ftSmeContext.is_preauth_lfr_mbb);

    vos_mem_copy((void *)&pre_auth_req->currbssId,
                 (void *)session->connectedProfile.bssid, sizeof(tSirMacAddr));
    vos_mem_copy((void *)&pre_auth_req->preAuthbssId,
                 (void *)bss_description->bssId, sizeof(tSirMacAddr));

    vos_mem_copy(pre_auth_req->pbssDescription, bss_description,
                 sizeof(bss_description->length) + bss_description->length);
    pre_auth_req->length = pal_cpu_to_be16(auth_req_len);
    return palSendMBMessage(mac->hHdd, pre_auth_req);
}

/**
 * csr_neighbor_roam_issue_preauth_reassoc() -issues  preauth_reassoc request
 * @mac: MAC context
 *
 * This function issues preauth_reassoc request to PE with the 1st AP
 * entry in the roamable AP list
 *
 * Return: eHAL_STATUS_SUCCESS on success, eHAL_STATUS_FAILURE otherwise
 */
eHalStatus csr_neighbor_roam_issue_preauth_reassoc(tpAniSirGlobal mac)
{
    tpCsrNeighborRoamControlInfo neighbor_roam_info =
                                           &mac->roam.neighborRoamInfo;
    eHalStatus status = eHAL_STATUS_SUCCESS;
    tpCsrNeighborRoamBSSInfo neighbor_bss_node;

    VOS_ASSERT(neighbor_roam_info->FTRoamInfo.preauthRspPending ==
                                                         eANI_BOOLEAN_FALSE);

    neighbor_bss_node = csrNeighborRoamGetRoamableAPListNextEntry(mac,
                               &neighbor_roam_info->roamableAPList, NULL);

    if (neighbor_bss_node == NULL)
    {
        smsLog(mac, LOGE, FL("Roamable AP list is empty"));
        return eHAL_STATUS_FAILURE;
    }
    else
    {
        status = csrRoamEnqueuePreauth(mac,
                 neighbor_roam_info->csrSessionId,
                 neighbor_bss_node->pBssDescription,
                 ecsr_mbb_perform_preauth_reassoc,
                 eANI_BOOLEAN_TRUE);

        smsLog(mac, LOG1, FL("Before Pre-Auth: BSSID "MAC_ADDRESS_STR", Ch:%d"),
               MAC_ADDR_ARRAY(neighbor_bss_node->pBssDescription->bssId),
               neighbor_bss_node->pBssDescription->channelId);

        if (eHAL_STATUS_SUCCESS != status)
        {
            smsLog(mac, LOGE,
                   FL("Send Preauth request to PE failed with status %d"),
                   status);
            return status;
        }
    }

    neighbor_roam_info->FTRoamInfo.preauthRspPending = eANI_BOOLEAN_TRUE;

    CSR_NEIGHBOR_ROAM_STATE_TRANSITION(eCSR_NEIGHBOR_ROAM_STATE_MBB_PREAUTH_REASSOC)
    return status;
}

/**
 * csr_stop_preauth_reassoc_mbb_timer() -stops preauth_reassoc timer
 * @mac: MAC context
 *
 * This function stops preauth_reassoc timer
 *
 */
void csr_stop_preauth_reassoc_mbb_timer(tpAniSirGlobal mac)
{
    if (mac->roam.neighborRoamInfo.is_pre_auth_reassoc_mbb_timer_started)
        vos_timer_stop(&mac->ft.ftSmeContext.pre_auth_reassoc_mbb_timer);
}


/**
 * csr_preauth_reassoc_mbb_timer_callback() -preauth_reassoc timer callback
 * @mac: MAC context
 *
 * This function issues preauth_reassoc with another roamable entry
 *
 */
void csr_preauth_reassoc_mbb_timer_callback(void *context)
{
    tpAniSirGlobal mac = (tpAniSirGlobal)context;

    mac->roam.neighborRoamInfo.is_pre_auth_reassoc_mbb_timer_started = 0;
    csr_neighbor_roam_issue_preauth_reassoc(mac);
}


/**
 * csr_roam_dequeue_preauth_reassoc() -Dequeues
 * ecsr_mbb_perform_preauth_reassoc
 * @mac: MAC context
 *
 * This function dequeues ecsr_mbb_perform_preauth_reassoc
 *
 */
eHalStatus csr_roam_dequeue_preauth_reassoc(tpAniSirGlobal mac)
{
    tListElem *entry;
    tSmeCmd *command;
    entry = csrLLPeekHead(&mac->sme.smeCmdActiveList, LL_ACCESS_LOCK);
    if (entry) {
        command = GET_BASE_ADDR(entry, tSmeCmd, Link);
        if ((eSmeCommandRoam == command->command) &&
            (ecsr_mbb_perform_preauth_reassoc ==
                                    command->u.roamCmd.roamReason)) {
            smsLog(mac, LOG1, FL("DQ-Command = %d, Reason = %d"),
                    command->command, command->u.roamCmd.roamReason);
            if (csrLLRemoveEntry( &mac->sme.smeCmdActiveList,
                                       entry, LL_ACCESS_LOCK)) {
                csrReleaseCommandPreauth( mac, command );
            }
        } else {
            smsLog(mac, LOGE, FL("Command = %d, Reason = %d "),
                    command->command, command->u.roamCmd.roamReason);
        }
    }
    else {
        smsLog(mac, LOGE,
               FL("pEntry NULL for eWNI_SME_MBB_PRE_AUTH_REASSOC_RSP"));
    }
    smeProcessPendingQueue( mac );
    return eHAL_STATUS_SUCCESS;
}

/**
 * csr_neighbor_roam_preauth_reassoc_rsp_handler() -handles preauth
 * reassoc response
 * @mac: MAC context
 * @lim_status: status of preauth reassoc response from lim
 *
 * This function handles preauth_reassoc response from PE. When
 * preauth_reassoc response failure is received, preauth reassoc
 * with new candidate will be attempted. In success case, candidate will be
 * removed from roamable entry.
 *
 */
eHalStatus
csr_neighbor_roam_preauth_reassoc_rsp_handler(tpAniSirGlobal mac,
          tSirRetStatus lim_status)
{
    tpCsrNeighborRoamControlInfo neighbor_roam_info =
                                      &mac->roam.neighborRoamInfo;
    eHalStatus status = eHAL_STATUS_SUCCESS;
    eHalStatus preauth_processed = eHAL_STATUS_SUCCESS;
    tpCsrNeighborRoamBSSInfo preauth_rsp_node = NULL;

    if (eANI_BOOLEAN_FALSE ==
                neighbor_roam_info->FTRoamInfo.preauthRspPending) {
       /*
        * This can happen when we disconnect immediately after sending
        * a pre-auth request. During processing of the disconnect command,
        * we would have reset preauthRspPending and transitioned to INIT state.
        */
       smsLog(mac, LOGE,
              FL("Unexpected pre-auth response in state %d"),
              neighbor_roam_info->neighborRoamState);
       preauth_processed = eHAL_STATUS_FAILURE;
       goto DEQ_PREAUTH;
    }

    if ((neighbor_roam_info->neighborRoamState !=
                            eCSR_NEIGHBOR_ROAM_STATE_MBB_PREAUTH_REASSOC)) {
        smsLog(mac, LOGE,
               FL("Preauth response received in state %s"),
               macTraceGetNeighbourRoamState(
                      neighbor_roam_info->neighborRoamState));
        preauth_processed = eHAL_STATUS_FAILURE;
        goto DEQ_PREAUTH;
    }

    neighbor_roam_info->FTRoamInfo.preauthRspPending = eANI_BOOLEAN_FALSE;

    if (eSIR_SUCCESS == lim_status)
        preauth_rsp_node = csrNeighborRoamGetRoamableAPListNextEntry(mac,
                                  &neighbor_roam_info->roamableAPList, NULL);

    if ((eSIR_SUCCESS == lim_status) && (NULL != preauth_rsp_node)) {
        smsLog(mac, LOG1, FL("MBB Reassoc completed successfully"));

        smsLog(mac, LOG1, FL("After MBB reassoc BSSID "MAC_ADDRESS_STR" Ch %d"),
               MAC_ADDR_ARRAY(preauth_rsp_node->pBssDescription->bssId),
               preauth_rsp_node->pBssDescription->channelId);

        /*
        * MBB Reassoc competer successfully. Insert the preauthenticated
        * node to tail of preAuthDoneList
        */
        csrNeighborRoamRemoveRoamableAPListEntry(mac,
                         &neighbor_roam_info->roamableAPList, preauth_rsp_node);
        csrLLInsertTail(&neighbor_roam_info->FTRoamInfo.preAuthDoneList,
                                  &preauth_rsp_node->List, LL_ACCESS_LOCK);
    } else {
        tpCsrNeighborRoamBSSInfo    neighbor_bss_node = NULL;
        tListElem                   *entry;

        smsLog(mac, LOG1,
               FL("Pre-Auth failed BSSID "MAC_ADDRESS_STR" Ch:%d status = %d"),
               MAC_ADDR_ARRAY(preauth_rsp_node->pBssDescription->bssId),
               preauth_rsp_node->pBssDescription->channelId, lim_status);

        /*
        * Pre-auth failed. Add the bssId to the preAuth failed list MAC Address.
        * Also remove the AP from roamable AP list. The one in the head of the
        * list should be one with which we issued pre-auth and failed.
        */
        entry = csrLLRemoveHead(&neighbor_roam_info->roamableAPList,
                                  LL_ACCESS_LOCK);
        if(entry) {
           neighbor_bss_node = GET_BASE_ADDR(entry,
                                            tCsrNeighborRoamBSSInfo, List);
           /*
            * Add the BSSID to pre-auth fail list if it is
            * not requested by HDD
            */
           status = csrNeighborRoamAddBssIdToPreauthFailList(mac,
                                 neighbor_bss_node->pBssDescription->bssId);

           /* Now we can free this node */
           csrNeighborRoamFreeNeighborRoamBSSNode(mac, neighbor_bss_node);
        }

        /* Dequeue ecsr_mbb_perform_preauth_reassoc */
        csr_roam_dequeue_preauth_reassoc(mac);

        /*
        * Move state to Connected. Connected state here signifies connection
        * with current AP as preauth failed with roamable AP. Still driver has
        * connection with current AP.
        */
        CSR_NEIGHBOR_ROAM_STATE_TRANSITION(eCSR_NEIGHBOR_ROAM_STATE_CONNECTED)

        /* Start a timer to issue preauth_reassoc request for the next entry*/
        status = vos_timer_start(&mac->ft.ftSmeContext.
                   pre_auth_reassoc_mbb_timer, PREAUTH_REASSOC_MBB_TIMER_VALUE);
        if (eHAL_STATUS_SUCCESS != status) {
            smsLog(mac, LOGE,
                   FL("pre_auth_reassoc_mbb_timer start failed status %d"),
                   status);
            return eHAL_STATUS_FAILURE;
        }
        mac->roam.neighborRoamInfo.is_pre_auth_reassoc_mbb_timer_started = true;
        return eHAL_STATUS_SUCCESS;
    }

DEQ_PREAUTH:
    csr_roam_dequeue_preauth_reassoc(mac);
    return preauth_processed;
}

/**
 * csr_roam_preauth_rsp_mbb_processor() -handles
 * eWNI_SME_MBB_PRE_AUTH_REASSOC_RSP
 * @hal: HAL context
 *
 * This function invokes preauth reassoc response handler and
 * updates CSR with new connection information.
 *
 */
void csr_roam_preauth_rsp_mbb_processor(tHalHandle hal,
     tpSirFTPreAuthRsp pre_auth_rsp)
{
    tpAniSirGlobal mac = PMAC_STRUCT(hal);
    eHalStatus  status;

    mac->ft.ftSmeContext.is_preauth_lfr_mbb = false;
    smsLog(mac, LOG1, FL("is_preauth_lfr_mbb %d"),
                         mac->ft.ftSmeContext.is_preauth_lfr_mbb);

    status = csr_neighbor_roam_preauth_reassoc_rsp_handler(mac,
                                                pre_auth_rsp->status);
    if (status != eHAL_STATUS_SUCCESS) {
        smsLog(mac, LOGE,FL("Preauth was not processed: %d SessionID: %d"),
                            status, pre_auth_rsp->smeSessionId);
        return;
    }

    /*
     * The below function calls/timers should be invoked only
     * if the pre-auth is successful.
     */
    if (VOS_STATUS_SUCCESS != (VOS_STATUS)pre_auth_rsp->status)
        return;

    mac->ft.ftSmeContext.FTState = eFT_AUTH_COMPLETE;

    /* Save the received response */
    vos_mem_copy((void *)&mac->ft.ftSmeContext.preAuthbssId,
                 (void *)pre_auth_rsp->preAuthbssId, sizeof(tCsrBssid));


    /* To Do: add code to update CSR for new connection */

    CSR_NEIGHBOR_ROAM_STATE_TRANSITION(eCSR_NEIGHBOR_ROAM_STATE_CONNECTED)
}

