/*
 * Copyright (c) 2012-2013,2017 The Linux Foundation. All rights reserved.
 *
 * Previously licensed under the ISC license by Qualcomm Atheros, Inc.
 *
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * This file was originally distributed by Qualcomm Atheros, Inc.
 * under proprietary terms before Copyright ownership was assigned
 * to the Linux Foundation.
 */

#ifndef WLAN_QCT_WDI_CTS_H
#define WLAN_QCT_WDI_CTS_H

/*===========================================================================

         W L A N   C O N T R O L    T R A N S P O R T   S E R V I C E  
                       E X T E R N A L  A P I
                
                   
DESCRIPTION
  This file contains the external API exposed by the wlan control transport
  service module.
  
      
===========================================================================*/


/*===========================================================================

                      EDIT HISTORY FOR FILE


  This section contains comments describing changes made to the module.
  Notice that changes are listed in reverse chronological order.


  $Header:$ $DateTime: $ $Author: $


when        who    what, where, why
--------    ---    ----------------------------------------------------------
08/04/10    mss     Created module.

===========================================================================*/



/*===========================================================================

                          INCLUDE FILES FOR MODULE

===========================================================================*/

/*----------------------------------------------------------------------------
 * Include Files
 * -------------------------------------------------------------------------*/
#include "wlan_qct_pal_type.h" 
#include "wlan_qct_pal_msg.h"
#include "wlan_qct_os_sync.h"
#include "wlan_qct_os_list.h"
#ifdef EXISTS_MSM_SMD
#include <mach/msm_smd.h>
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
#include <linux/rpmsg.h>
#else
#include <soc/qcom/smd.h>
#endif
#endif

/*----------------------------------------------------------------------------
 * Preprocessor Definitions and Constants
 * -------------------------------------------------------------------------*/
 #ifdef __cplusplus
 extern "C" {
 #endif 

/* time to wait for SMD channel to open (in msecs) */
#define WCTS_SMD_OPEN_TIMEOUT 5000

/*----------------------------------------------------------------------------
 *  Type Declarations
 * -------------------------------------------------------------------------*/

/* Control Transport Service Handle Type*/
typedef void*  WCTS_HandleType;

/*--------------------------------------------------------------------------- 
   WCTS_NotifyEventType
 ---------------------------------------------------------------------------*/
typedef enum
{
   WCTS_EVENT_OPEN,
   WCTS_EVENT_CLOSE,
   WCTS_EVENT_MAX
} WCTS_NotifyEventType;

struct WdiSmdStats
{
  int smd_event_data;
  int smd_event_open;
  int smd_event_close;
  int smd_event_status;
  int smd_event_reopen_ready;
  int smd_event_err;
};

/*----------------------------------------------------------------------------
 *   WDI callback types
 *--------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------
   WCTS_NotifyCBType
 
   DESCRIPTION   
 
   This callback is invoked by the control transport when it wishes to send
   up a notification like the ones mentioned above.
 
   PARAMETERS 

    IN
    wctsHandle:       handle to the control transport service 
    wctsEvent:        the event being notified
    wctsNotifyCBData: the callback data of the user 
    
  
  RETURN VALUE 
    None
---------------------------------------------------------------------------*/
typedef void (*WCTS_NotifyCBType) (WCTS_HandleType        wctsHandle, 
                                   WCTS_NotifyEventType   wctsEvent,
                                   void*                  wctsNotifyCBData);

/*---------------------------------------------------------------------------
   WCTS_RxMsgCBType
 
   DESCRIPTION   
 
   This callback is invoked by the control transport when it wishes to send
   up a packet received over the bus. Upon return of Rx callback, the ownership
   of the message belongs to the CT and this one is free to deallocate any
   buffer that was used to get this message. If WDI wishes to maintain the
   information beyond the lifetime of the call, it must make a copy of it.
 
   PARAMETERS 

    IN
    wctsHandle:  handle to the control transport service 
    pMsg:        the packet
    uLen:        the packet length
    wctsRxMsgCBData: the callback data of the user 
    
  
  RETURN VALUE 
    None
---------------------------------------------------------------------------*/
typedef void (*WCTS_RxMsgCBType) (WCTS_HandleType       wctsHandle, 
                                  void*                 pMsg,
                                  wpt_uint32            uLen,
                                  void*                 wctsRxMsgCBData);

/*--------------------------------------------------------------------------- 
   WCTS Transport Callbacks holder type
 ---------------------------------------------------------------------------*/
typedef struct
{
     WCTS_NotifyCBType      wctsNotifyCB;
     void*                  wctsNotifyCBData;
     WCTS_RxMsgCBType       wctsRxMsgCB;
     void*                  wctsRxMsgCBData;
} WCTS_TransportCBsType;

/*---------------------------------------------------------------------------
   WCTS_StateType
 ---------------------------------------------------------------------------*/
typedef enum
{
   WCTS_STATE_CLOSED,       /* Closed */
   WCTS_STATE_OPEN_PENDING, /* Waiting for the OPEN event from SMD */
   WCTS_STATE_OPEN,         /* Open event received from SMD */
   WCTS_STATE_DEFERRED,     /* Write pending, SMD chennel is full */
   WCTS_STATE_REM_CLOSED,   /* Remote end closed the SMD channel */
   WCTS_STATE_MAX
} WCTS_StateType;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
#define wcts_channel struct rpmsg_endpoint
#else
#define wcts_channel smd_channel_t
#endif
/*---------------------------------------------------------------------------
   Control Transport Control Block Type
 ---------------------------------------------------------------------------*/
typedef struct
{
   WCTS_NotifyCBType      wctsNotifyCB;
   void*                  wctsNotifyCBData;
   WCTS_RxMsgCBType       wctsRxMsgCB;
   void*                  wctsRxMsgCBData;
   WCTS_StateType         wctsState;
   vos_spin_lock_t        wctsStateLock;
   wcts_channel            *wctsChannel;
   wpt_list               wctsPendingQueue;
   wpt_uint32             wctsMagic;
   wpt_msg                wctsOpenMsg;
   wpt_msg                wctsDataMsg;
   wpt_event              wctsEvent;
} WCTS_ControlBlockType;

/*========================================================================
 *     Function Declarations and Documentation
 ==========================================================================*/
/**
 @brief     This function is used by the DAL Core to initialize the Control
            Transport for processing. It must be called prior to calling any
            other APIs of the Control Transport. 


 @param szName:   unique name for the channel that is to be opened 
         uSize:   size of the channel that must be opened (should fit the
                  largest size of  packet that the Dal Core wishes to send)
         wctsCBs:  a list of callbacks that the CT needs to use to send
                  notification and messages back to DAL 
 
 @see 
 @return  A handle that must be used for further communication with the CTS. 
         This is an opaque structure for the caller and it will be used in
         all communications to and from the CTS. 

*/
WCTS_HandleType  
WCTS_OpenTransport 
( 
  const wpt_uint8*         szName,
  wpt_uint32               uSize,  
  WCTS_TransportCBsType*   wctsCBs
);

/**
 @brief    This function is used by the DAL Core to to close the
           Control Transport when its services are no longer
           needed. Full close notification will be receive
           asynchronously on the notification callback
           registered on Open


 @param wctsHandlehandle:  received upon open
 
 @see 
 @return   0 for success
*/
wpt_uint32
WCTS_CloseTransport 
(
  WCTS_HandleType      wctsHandle
);

/**
 @brief    This function is used by the DAL Core to to send a 
           message over to  the WLAN sub-system.
 
           Once a buffer has been passed into the Send Message
 API, CT takes full ownership of it and it is responsible for 
 freeing the associated resources. (This prevents a memcpy in 
 case of a deffered write) 

 The messages transported through the CT on both RX and TX are 
 flat memory buffers that can be accessed and manipulated 
 through standard memory functions. 

 @param wctsHandlehandle:  received upon open
        pMsg:  the message to be sent
        uLen: the length of the message

 @see 
 @return   0 for success
*/
wpt_uint32
WCTS_SendMessage 
(
  WCTS_HandleType      wctsHandle,
  void*                pMsg,
  wpt_uint32           uLen
);

/**
 @brief    This helper function is used to clean up the pending
           messages in the transport queue

 @param wctsHandlehandle:  transport handle

 @see
 @return   0 for success
*/
wpt_uint32
WCTS_ClearPendingQueue
(
   WCTS_HandleType      wctsHandle
);

void WCTS_Dump_Smd_status(void);

/**
 * Notification callback when SMD needs to communicate asynchronously with
 * the client.
 *
 * This callback function may be called from interrupt context; clients must
 * not block or call any functions that block.
 *
 * @param[in] data   The user-supplied data provided to smd_named_open_on_edge()
 * @param[in] event  The event that occurred
 *
 * @return void
 */
void WCTS_NotifyCallback( void *data, unsigned event);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0))
/**
 * WCTS_smd_resp_process() - Response callback to process recieved data
 *
 * @rpdev: rpmsg device
 * @buf: received data
 * @len: received data length
 * @priv: The user-supplied data provided to wcnss_open_channel()
 * @addr: address
 *
 * @return status
 */
int WCTS_smd_resp_process(struct rpmsg_device *rpdev,
			  void *buf, int len, void *priv, u32 addr);

enum wcnss_driver_state;
/**
 * WCTS_driver_state_process() - Callback to process driver state info
 *
 * @priv: The user-supplied data provided in wcnss_register_driver()
 * @state: driver state
 *
 * @return status
 */
int WCTS_driver_state_process(void *priv, enum wcnss_driver_state state);

struct bt_profile_state;
/**
 * WCTS_bt_profile_state_process() - Callback to process bt state info
 *
 * @priv: The user-supplied data provided in wcnss_register_driver()
 * @state: bt state
 *
 * @return status
 */
int WCTS_bt_profile_state_process(void *priv, struct bt_profile_state *state);

/**
 * wcts_close_channel() - api to close the smd channel
 * @wctsHandle: transport handle
 *
 * @return none
 */
void wcts_close_channel(WCTS_HandleType wctsHandle);
#endif
#endif /* #ifndef WLAN_QCT_WDI_CTS_H */
