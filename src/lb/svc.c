//
// Created by tedqu on 24-9-29.
//

#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include "../common/util.h"
#include "svc.h"

#define MAX_SVC_BUCKETS 64

static struct list_head g_svc[MAX_SVC_BUCKETS];

static uint32_t get_svc_hash(uint32_t vip, uint16_t vport) {
    return rte_hash_crc_4byte(vip, vport) % MAX_SVC_BUCKETS;
}

static svc_t* svc_new(void) {
    svc_t *svc;

    svc = rte_malloc("svc", sizeof(svc_t), RTE_CACHE_LINE_SIZE);
    if (NULL == svc) {
        RTE_LOG(ERR, EAL, "No memory, %s", __func__ );
        return NULL;
    }

    INIT_LIST_HEAD(&svc->rs_list);
    return svc;
}

int svc_add(uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    hash = get_svc_hash(vip, vport);
    list_for_each_entry(svc, &g_svc[hash], svc_node) {
        if (svc->vip == vip && svc->vport == vport) {
            return NAT_LB_EXIST;
        }
    }

    svc = svc_new();
    if (NULL == svc) {
        return NAT_LB_NOMEM;
    }
    svc->vip = vip;
    svc->vport = vport;
    svc->rs_cnt = 0;
    svc->next_schedule_rs = 0;
    list_add(&svc->svc_node, &g_svc[hash]);

    return NAT_LB_OK;
}

int svc_del(uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    svc = NULL;
    hash = get_svc_hash(vip, vport);
    list_for_each_entry(svc, &g_svc[hash], svc_node) {
        if (svc->vip == vip && svc->vport == vport) {
            break;
        }
    }

    if (svc != NULL) {
        list_del(&svc->svc_node);
        rte_free(svc);
        return NAT_LB_OK;
    }

    return NAT_LB_NOT_EXIST;
}

svc_t* svc_find(uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    hash = get_svc_hash(vip, vport);
    list_for_each_entry(svc, &g_svc[hash], svc_node) {
        if (svc->vip == vip && svc->vport == vport) {
            return svc;
        }
    }

    return NULL;
}

static uint32_t get_rs_hash(uint32_t vip, uint16_t vport) {
    return rte_hash_crc_4byte(vip, vport) % MAX_RS_BUCKETS;
}

static rs_t *rs_new(void) {
    return rte_malloc("rs", sizeof(rs_t), RTE_CACHE_LINE_SIZE);
}

int rs_add(svc_t *svc, uint32_t rs_ip, uint16_t rs_port) {
    rs_t *rs;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (rs->rs_ip == rs_ip && rs->rs_port == rs_port) {
            return NAT_LB_EXIST;
        }
    }

    rs = rs_new();
    if (NULL == rs) {
        return NAT_LB_NOMEM;
    }

    rs->rs_ip = rs_ip;
    rs->rs_port = rs_port;
    list_add(&rs->rs_node, &svc->rs_list);
    svc->rs_cnt++;
    return NAT_LB_OK;
}

int rs_del(svc_t *svc, uint32_t rs_ip, uint16_t rs_port) {
    rs_t *rs = NULL;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (rs->rs_ip == rs_ip && rs->rs_port == rs_port) {
            break;
        }
    }

    if (NULL == rs) {
        return NAT_LB_NOT_EXIST;
    }
    list_del(&rs->rs_node);
    rte_free(rs);
    svc->rs_cnt--;

    return NAT_LB_OK;
}

rs_t* rs_find(svc_t *svc, uint32_t rs_ip, uint16_t rs_port) {
    uint32_t hash;
    rs_t *rs = NULL;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (rs->rs_ip == rs_ip && rs->rs_port == rs_port) {
            return rs;
        }
    }

    return NULL;
}

rs_t* rs_schedule(uint32_t vip, uint32_t vport) {
    svc_t *svc;
    rs_t *rs;
    int idx = 0;

    svc = svc_find(vip, vport);
    if (NULL == svc) {
        RTE_LOG(ERR, EAL, "svc not exist.");
        return NULL;
    }

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (idx == svc->next_schedule_rs) {
            break;
        } else {
            idx++;
        }
    }
    svc->next_schedule_rs = svc->next_schedule_rs++;
    svc->next_schedule_rs = svc->next_schedule_rs % svc->rs_cnt;
    return rs;
}

void svc_init(void) {
    int i;

    for (i = 0; i < MAX_SVC_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_svc[i]);
    }
}