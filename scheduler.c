//
// Created by tedqu on 24-9-8.
//

#include "common.h"
#include "list.h"
#include "scheduler.h"

static struct list_head g_lcore_jobs[LCORE_TYPE_MAX][LCORE_JOB_TYPE_MAX];

int scheduler_init(void) {
    int i, j;
    for (i = 0; i < LCORE_TYPE_MAX; i++) {
        for (j = 0; j < LCORE_JOB_TYPE_MAX; j++) {
            INIT_LIST_HEAD(&g_lcore_jobs[i][j]);
        }
    }
    return NAT_LB_OK;
}

int lcore_job_init(struct lcore_job *job, char *name, enum lcore_job_type job_type, job_func func) {
    if (NULL == job) {
        return NAT_LB_INVALID;
    }

    job->type = job_type;
    job->func = func;
    snprintf(job->name, sizeof(job->name) - 1, "%s", name);
    return NAT_LB_OK;
}

int lcore_job_register(struct lcore_job *job, enum lcore_type lcore_type) {
    if (NULL == job || lcore_type >= LCORE_TYPE_MAX) {
        return NAT_LB_INVALID;
    }

    struct lcore_job *curr;
    list_for_each_entry(curr, &g_lcore_jobs[lcore_type][job->type], job_list_node) {
        if (curr == job) {
            return NAT_LB_EXIST;
        }
    }

    list_add_tail(&job->job_list_node, &g_lcore_jobs[lcore_type][job->type]);
    return NAT_LB_OK;
}

int lcore_job_unregister(struct lcore_job *job, enum lcore_type lcore_type) {
    if (NULL == job || lcore_type >= LCORE_TYPE_MAX) {
        return NAT_LB_INVALID;
    }

    list_del(&job->job_list_node);
    return NAT_LB_OK;
}

static void do_lcore_job(struct lcore_job *job) {
    job->func(job->data);
}

_Noreturn static int job_loop(void *arg) {
    unsigned int cid;
    enum lcore_type lcore_type;
    struct lcore_job *job;

    cid = rte_lcore_id();
    lcore_type = get_lcore_type(cid);

    fprintf(stdout, "Start lcore %d type %d loop.\n", cid, lcore_type);

    while (1) {
        list_for_each_entry(job, &g_lcore_jobs[lcore_type][LCORE_JOB_LOOP], job_list_node) {
            do_lcore_job(job);
        }
    }
}

int lcore_start(bool in_master) {
    return rte_eal_mp_remote_launch(job_loop, NULL, in_master);
}