//
// Created by tedqu on 25-5-27.
//

#ifndef NAT_LB_SCHEDULE_H
#define NAT_LB_SCHEDULE_H

#include "../common/list.h"
#include "../common/skb.h"
#include "svc.h"

#define SCH_NAME_SIZE 64

enum scheduler_type {
    SCHEDULER_TYPE_WRR = 0,
    SCHEDULER_TYPE_MAX = 1
};

struct scheduler {
    struct list_head node;
    char name[SCH_NAME_SIZE];
    void *data;
    void (*init_service)(struct svc* svc);
    void (*update_service)(struct svc* svc);
    struct rs* (*schedule)(struct svc* svc, struct sk_buff* skb);
};

struct scheduler* get_scheduler(char *name);

#endif //NAT_LB_SCHEDULE_H
