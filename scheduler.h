//
// Created by tedqu on 24-9-8.
//

#ifndef NAT_LB_SCHEDULER_H
#define NAT_LB_SCHEDULER_H

#include <rte_common.h>
#include "list.h"
#include "lcore.h"

enum lcore_job_type {
    LCORE_JOB_INIT,
    LCORE_JOB_LOOP,
    LCORE_JOB_SLOW,
    LCORE_JOB_TYPE_MAX,
};

typedef void (*job_func)(void *arg);

struct lcore_job {
    char name[32];
    enum lcore_job_type type;
    void (*func) (void *arg);
    void *data;
    struct list_head job_list_node;
} __rte_cache_aligned;

struct lcore_job_array{
    struct lcore_job job;
    enum lcore_type type;
};

int scheduler_init(void);
int lcore_job_init(struct lcore_job *job, char *name, enum lcore_job_type job_type, job_func func);
int lcore_job_register(struct lcore_job *job, enum lcore_type lcore_type);
int lcore_job_unregister(struct lcore_job *job, enum lcore_type lcore_type);
int lcore_start(bool);

#endif //NAT_LB_SCHEDULER_H
