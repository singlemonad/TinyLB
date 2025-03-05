//
// Created by tedqu on 24-11-18.
//

#ifndef NAT_LB_PIPELINE_H
#define NAT_LB_PIPELINE_H

#include "skb.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PIPELINE_PRIORITY_MIN = 0,
    PIPELINE_PRIORITY_CT = 100,
    PIPELINE_PRIORITY_ACL = 200,
    PIPELINE_PRIORITY_SG = 300,
    PIPELINE_PRIORITY_LB = 400,
    PIPELINE_PRIORITY_CONFIRM = 500,
    PIPELINE_PRIORITY_ROUTE = 600,
}pipeline_priority;

typedef enum {
    PIPELINE_ACTION_NEXT,
    PIPELINE_ACTION_DROP,
    PIPELINE_ACTION_LOCAL_IN,
    PIPELINE_ACTION_FORWARD,
    PIPELINE_ACTION_STOLEN,
}pipeline_actions;

typedef pipeline_actions (*pipeline_func)(sk_buff_t *skb);

int pipeline_register(const char *name, pipeline_func func, int priority, void *data);
pipeline_actions run_pipeline_for_skb(struct sk_buff *skb);

#endif //NAT_LB_PIPELINE_H
