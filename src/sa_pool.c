//
// Created by tedqu on 24-9-30.
//

#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include "../include/common.h"
#include "../include/sa_pool.h"
#include "../include/log.h"

#define MAX_SA_POOL_BUCKETS 8

static struct list_head g_sa_pool[MAX_SA_POOL_BUCKETS];

static uint32_t get_snat_hash(uint32_t dst_ip, uint16_t dst_port) {
    return rte_hash_crc_4byte(dst_ip, dst_port) % MAX_SA_POOL_BUCKETS;
}

static sa_t* sa_pool_new(void) {
    snat_addr_t *snat_addr;
    sa_t *sa;
    int i;

    snat_addr = rte_malloc("snat addr", sizeof(snat_addr_t), RTE_CACHE_LINE_SIZE);
    if (NULL == snat_addr) {
        RTE_LOG(ERR, EAL, "No memory, %s", __func__ );
        return NULL;
    }
    memset(snat_addr->port_bit_map, 0, sizeof(snat_addr->port_bit_map));

    sa = rte_malloc("sa pool", sizeof(sa_t), RTE_CACHE_LINE_SIZE);
    if (NULL == sa) {
        RTE_LOG(ERR, EAL, "No memory, %s", __func__ );
        return NULL;
    }
    sa->snat_addr = snat_addr;

    return sa;
}

int snat_addr_add(uint32_t dst_ip, uint16_t dst_port, uint32_t snat_ip) {
    sa_t *sa;
    uint32_t hash;

    hash = get_snat_hash(dst_ip, dst_port);
    list_for_each_entry(sa, &g_sa_pool[hash], sa_node) {
        if (sa->dst_ip == dst_ip && sa->dst_port == dst_port) {
            return NAT_LB_EXIST;
        }
    }

    sa = sa_pool_new();
    if (NULL == sa) {
        return NAT_LB_NOMEM;
    }
    sa->dst_ip = dst_ip;
    sa->dst_port = dst_port;
    sa->snat_addr->snat_ip = snat_ip;
    list_add(&sa->sa_node, &g_sa_pool[hash]);

    return NAT_LB_OK;
}

int snat_addr_del(uint32_t dst_ip, uint16_t dst_port) {
    sa_t *sa;
    uint32_t hash;
    bool found = false;

    hash = get_snat_hash(dst_ip, dst_port);
    list_for_each_entry(sa, &g_sa_pool[hash], sa_node) {
        if (sa->dst_ip == dst_ip && sa->dst_port == dst_port) {
            found = true;
            break;
        }
    }

    if (!found) {
        return NAT_LB_NOT_EXIST;
    }

    list_del(&sa->sa_node);
    rte_free(sa->snat_addr);
    rte_free(sa);
    return NAT_LB_OK;
}

static int snat_port_get(snat_addr_t *snat_addr, uint16_t *snat_port) {
    int port_idx;
    int bit_idx;

    for (port_idx = 0; port_idx < PORT_BIT_MAP_SIZE; port_idx++) {
        if ((snat_addr->port_bit_map[port_idx] ^ 0xFF) != 0) {
            for (bit_idx = 0; bit_idx < 8; bit_idx++) {
                if (((snat_addr->port_bit_map[port_idx]) & (1 << bit_idx)) == 0) {
                    snat_addr->port_bit_map[port_idx] |= (1 << bit_idx);
                    *snat_port = htons((port_idx * 8) + bit_idx + PORT_MIN);
                    RTE_LOG(ERR, LB, "snat port %d\n", *snat_port);
                    return NAT_LB_OK;
                }
            }
        }
    }
    return NAT_LB_NO_SNAT_PORT;
}

int snat_addr_get(uint32_t dst_ip, uint16_t dst_port, uint32_t *snat_ip, uint16_t *snat_port) {
    uint32_t hash;
    sa_t *sa;

    hash = get_snat_hash(dst_ip, dst_port);
    list_for_each_entry(sa, &g_sa_pool[hash], sa_node) {
        if (sa->dst_ip == dst_ip && sa->dst_port == dst_port) {
            *snat_ip = sa->snat_addr->snat_ip;
            return snat_port_get(sa->snat_addr, snat_port);
        }
    }

    return NAT_LB_NOT_EXIST;
}

void sa_pool_init(void) {
    int i;

    for (i = 0; i < MAX_SA_POOL_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_sa_pool[i]);
    }
}