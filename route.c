//
// Created by tedqu on 24-9-9.
//

#define ROUTE_TABLE_BUCKETS 128
#define MAX_ROUTES 4096
#define NUMBER_TBL8 256

#include <rte_lpm.h>
#include <rte_malloc.h>
#include "common.h"
#include "list.h"
#include "route.h"

static uint32_t g_route_entry_id_end;
static struct list_head g_route_table_hash[ROUTE_TABLE_BUCKETS];
static struct rte_lpm* g_route_table_lpm;

static uint32_t get_route_entry_id(void) {
    return g_route_entry_id_end++;
}

static int get_route_entry_hash(uint32_t route_entry_id) {
    return (int)route_entry_id % ROUTE_TABLE_BUCKETS;
}

void route_init(int socket_id) {
    int i;
    char name[64];
    struct rte_lpm_config lpm_cfg;

    for (i = 0; i < ROUTE_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&g_route_table_hash[i]);
    }

    snprintf(name, sizeof (name), "route_table_%d", socket_id);
    lpm_cfg.flags = 0;
    lpm_cfg.max_rules = MAX_ROUTES;
    lpm_cfg.number_tbl8s = NUMBER_TBL8;

    g_route_table_lpm = rte_lpm_create(name, socket_id, &lpm_cfg);
    if (NULL == g_route_table_lpm) {
        rte_exit(EXIT_FAILURE, "Create route table in socket %d failed, %s.",
                 socket_id, rte_strerror(rte_errno));
    }
}

int route_add(uint32_t dst_addr, uint16_t mask, unsigned long mtu, uint32_t gw,
              uint32_t src, struct dev_port *port, uint16_t metric, uint32_t flags) {
    int ret;
    int hash;
    struct route_entry *rt_entry;

    rt_entry = rte_zmalloc("route entry", sizeof(struct route_entry), RTE_CACHE_LINE_SIZE);
    if (NULL == rt_entry) {
        fprintf(stderr, "No memory, %s", __func__ );
        return NAT_LB_NOMEM;
    }

    rt_entry->id = get_route_entry_id();
    rt_entry->dst_addr = dst_addr;
    rt_entry->mask = mask;
    rt_entry->mtu = mtu;
    rt_entry->gw = gw;
    rt_entry->src = src;
    rt_entry->port = port;
    rt_entry->metric = metric;
    rt_entry->flags = flags;

    ret = rte_lpm_add(g_route_table_lpm, rt_entry->dst_addr, rt_entry->mask, rt_entry->id);
    if (ret < 0) {
        rte_free(rt_entry);
        return ret;
    }

    hash = get_route_entry_hash(rt_entry->id);
    list_add(&rt_entry->route_list_node, &g_route_table_hash[hash]);

    return NAT_LB_OK;
}

int route_del(uint32_t dst_addr, uint16_t mask) {
    struct route_entry *rt_entry = NULL;
    uint32_t rt_entry_id;
    int ret, hash;

    ret = rte_lpm_is_rule_present(g_route_table_lpm, dst_addr, mask, &rt_entry_id);
    if (ret == 0) {
        return NAT_LB_NOT_EXIST;
    }
    if (ret < 0) {
        return ret;
    }

    hash = get_route_entry_hash(rt_entry_id);
    list_for_each_entry(rt_entry, &g_route_table_hash[hash], route_list_node) {
        if (rt_entry->id == rt_entry_id) {
            break;
        }
    }
    if (NULL != rt_entry) {
        list_del(&rt_entry->route_list_node);
        rte_free(rt_entry);
        rte_lpm_delete(g_route_table_lpm, dst_addr, mask);
    }

    return NAT_LB_OK;
}

static struct route_entry* route_lookup(uint32_t dst_addr) {
    int ret;
    int hash;
    unsigned int rt_entry_id;
    struct route_entry *rt_entry;

    ret = rte_lpm_lookup(g_route_table_lpm, dst_addr, &rt_entry_id);
    if (ret != 0) {
        return NULL;
    }

    hash = get_route_entry_hash(rt_entry_id);
    list_for_each_entry(rt_entry, &g_route_table_hash[hash], route_list_node) {
        if (rt_entry->id == rt_entry_id) {
            return rt_entry;
        }
    }
    return NULL;
}

/* Client -> NAT-LB -> RS */
struct route_entry* route_ingress_lockup(struct flow4* fl) {
    return route_lookup(fl->dst_addr);
}

/* RS -> NAT-LB -> Client */
struct route_entry* route_egress_lockup(struct  flow4* fl) {
    return route_lookup(fl->dst_addr);
}