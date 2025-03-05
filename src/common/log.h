//
// Created by tedqu on 24-9-26.
//

#ifndef NAT_LB_LOG_H
#define NAT_LB_LOG_H

#include <rte_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_LOGTYPE_RX RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_TX RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_IP RTE_LOGTYPE_USER3
#define RTE_LOGTYPE_CT RTE_LOGTYPE_USER4
#define RTE_LOGTYPE_LB RTE_LOGTYPE_USER5
#define RTE_LOGTYPE_ROUTE RTE_LOGTYPE_USER6
#define RTE_LOGTYPE_DEV RTE_LOGTYPE_USER7

#endif //NAT_LB_LOG_H
