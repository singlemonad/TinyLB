//
// Created by tedqu on 24-9-8.
//

#include <rte_malloc.h>
#include "lcore.h"
#include "scheduler.h"
#include "dev.h"
#include "l2.h"

static struct lcore_conf g_lcore_conf[MAX_LCORE];

void add_lcore_configure(struct lcore_conf lcore_conf) {
    g_lcore_conf[lcore_conf.lcore_id] = lcore_conf;
}

struct lcore_port_conf* get_lcore_port_conf(uint16_t cid, uint16_t port_id) {
    return &g_lcore_conf[cid].ports[port_id];
}

struct lcore_queue_conf* get_lcore_tx_queue_conf(uint16_t cid, uint16_t port_id, uint16_t qid) {
    return &g_lcore_conf[cid].ports[port_id].txq[qid];
}

struct lcore_queue_conf* get_lcore_rx_queue_conf(uint16_t cid, uint16_t port_id, uint16_t qid) {
    return &g_lcore_conf[cid].ports[port_id].rxq[qid];
}

enum lcore_type get_lcore_type(uint16_t cid) {
    return g_lcore_conf[cid].type;
}

static void lcore_fwd_loop(void *arg) {
    int i, j;
    unsigned int k;
    unsigned int cid;
    unsigned int port_id;
    unsigned int rx_n;
    struct dev_port *port;
    struct lcore_queue_conf* queue_conf;

    cid = rte_lcore_id();
    for (i = 0; i < g_lcore_conf[cid].ports_n; i++) {
        port_id = g_lcore_conf[cid].ports[i].port_id;
        for (j = 0; j < g_lcore_conf[cid].ports[i].rxq_n; j++) {
            queue_conf = get_lcore_rx_queue_conf(cid, port_id, j);

            rx_n = port_rx_burst(port_id, queue_conf->queue_id);
            for (k = 0; k < rx_n; k++) {

                l2_rcv(cid, queue_conf->mbufs[k]);
            }
        }
    }
}

static void lcore_fwd_role_init(void) {
    struct lcore_job *fwd_job;
    char job_name[64];

    snprintf(job_name, 64, "fwd-worker");
    fwd_job = rte_zmalloc("job", sizeof (struct lcore_job), RTE_CACHE_LINE_SIZE);
    if (NULL == fwd_job) {
        rte_exit(EXIT_FAILURE, "No memory, %s", __func__ );
    }

    lcore_job_init(fwd_job, job_name, LCORE_JOB_LOOP, lcore_fwd_loop);
    lcore_job_register(fwd_job, LCORE_TYPE_FWD_WORKER);
}

void lcore_init(void) {
    lcore_fwd_role_init();
}