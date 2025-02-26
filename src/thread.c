//
// Created by tedqu on 25-2-25.
//

#include <rte_malloc.h>
#include <rte_log.h>
#include "../include/thread.h"
#include "../include/log.h"
#include "../include/dev.h"

#define MAX_LCORE 16
#define MAX_THREAD_PER_LCORE 64

static struct thread* lcore_2_threads[MAX_LCORE][MAX_THREAD_PER_LCORE];

static void rx_thread_work_func(struct thread_cfg *cfg) {
    struct rx_thread_cfg *rx_cfg = (struct rx_thread_cfg*)cfg;
    uint16_t port_id, queue_id;
    int idx = 0, n_rx;

    for ( ; idx < rx_cfg->n_queue; idx++) {
        port_id = rx_cfg->queues[idx].port_id;
        queue_id = rx_cfg->queues[idx].queue_id;

        n_rx = dev_port_rx_burst(port_id, queue_id, (struct sk_buff **) &rx_cfg->queues[idx].mbufs);
        if (0 != n_rx) {
            RTE_LOG(INFO, DEV, "Receive %d pkt.\n", n_rx);
        }

        // TODO deliver pkt
    }
}

struct thread* create_rx_thread(struct rx_thread_cfg *cfg) {
    struct thread* t = rte_malloc("thread", sizeof(struct thread), RTE_CACHE_LINE_SIZE);
    if (NULL == t) {
        RTE_LOG(ERR, EAL, "No memory, %s.", __func__ );
        return NULL;
    }

    t->type = RX_THREAD;
    t->cfg = (struct thread_cfg*)cfg;
    t->work_func = rx_thread_work_func;
    return t;
}

static int thread_loop(void *args) {
    uint16_t lcore_id = rte_lcore_id();
    struct thread** threads = lcore_2_threads[lcore_id];

    int idx;
    struct thread *thread;
    for (; true; )
    {
        idx = 0;
        thread = threads[idx];
        while (NULL != thread && idx < MAX_THREAD_PER_LCORE) {
            thread->work_func(thread->cfg);
            idx += 1;
            thread = threads[idx];
        }
    }
}

void lcore_add_thread(uint16_t lcore_id, struct thread* thread) {
    struct thread **threads = lcore_2_threads[lcore_id];
    int idx = 0;

    struct thread *head = threads[idx];
    while (NULL != head && idx < MAX_THREAD_PER_LCORE) {
        idx++;
    }
    if (idx==MAX_THREAD_PER_LCORE) {
        rte_exit(EXIT_FAILURE, "lcore has %d threads, can't add anymore");
    }
    threads[idx] = thread;
}

void start_lcore(uint16_t lcore) {
    int ret = rte_eal_remote_launch(thread_loop, NULL, lcore);
    if (0 != ret) {
        rte_exit(EXIT_FAILURE, "launch lcore %d failed, %s", rte_strerror(rte_errno));
    }
}