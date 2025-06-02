//
// Created by tedqu on 25-5-27.
//

#include "../common/log.h"
#include "../common/util.h"
#include "lb.h"
#include "schedule.h"

extern struct scheduler scheduler_array[SCHEDULER_TYPE_MAX];

#define SWAP(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

static int gcd(int a, int b)
{
    int r;

    if (a < b)
        SWAP(a, b);
    while ((r = a % b) != 0) {
        a = b;
        b = r;
    }
    return b;
}

static int wrr_gcd_weight(struct svc* svc) {
    int weight, g = 0;
    struct rs* rs;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        weight = rs->weight;
        if (weight > 0) {
            if (g > 0) {
                g = gcd(weight, g);
            } else {
                g = weight;
            }
        }
    }
    return g ? g : 1;
}

static int wrr_max_weight(struct svc* svc) {
    int weight = 0;
    struct rs* rs;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (rs->weight > weight) {
            weight = rs->weight;
        }
    }
    return weight;
}

static void wrr_init_service(struct svc* svc) {
    int lcore_id;
    for (lcore_id = 0; lcore_id < MAX_LCORE; lcore_id++) {
        if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
            struct wrr_sch_data* data = (struct wrr_sch_data*)&svc->sch_data[lcore_id];
            data->cl = container_of(&svc->rs_list, struct rs, rs_node);
            data->di = wrr_gcd_weight(svc);
            data->mw = wrr_max_weight(svc);
            data->cw = data->mw;
        }
    }
}

static void wrr_update_service(struct svc* svc) {
    int lcore_id;
    for (lcore_id = 0; lcore_id < MAX_LCORE; lcore_id++) {
        if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
            struct wrr_sch_data* data = (struct wrr_sch_data*)&svc->sch_data[lcore_id];
            data->di = wrr_gcd_weight(svc);
            data->mw = wrr_max_weight(svc);
            data->cw = data->mw;
        }
    }
}

static struct rs* wrr_schedule(struct svc* svc, struct sk_buff* skb) {
    struct rs* dest;
    uint16_t lcore_id = rte_lcore_id();

    struct wrr_sch_data *sched_data = (struct wrr_sch_data*)&svc->sch_data[lcore_id];
    if (sched_data->cl == NULL || sched_data->mw == 0) {
        goto not_found;
    }

    dest = sched_data->cl;
    while (true) {
        list_for_each_entry_continue(dest, &svc->rs_list, rs_node) {
            if (dest->weight >= sched_data->cw) {
                goto found;
            }
        }

        sched_data->cw -= sched_data->di;
        if (sched_data->cw <= 0) {
            sched_data->cw = sched_data->mw;

        }
    }

found:
    sched_data->cl = dest;
    // RTE_LOG(INFO, NAT_LB, "%s: schedule rs ip=%s, rs port=%d\n", __func__, be_ip_to_str(dest->rs_ip), ntohs(dest->rs_port));
    return dest;

not_found:
    return NULL;
}

void wrr_init(void) {
    struct scheduler *sch = &scheduler_array[SCHEDULER_TYPE_WRR];
    memset(sch->name, 0, sizeof(sch->name));
    strcpy(sch->name, "wrr");
    sch->init_service = wrr_init_service;
    sch->update_service = wrr_update_service;
    sch->schedule = wrr_schedule;
}