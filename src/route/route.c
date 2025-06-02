//
// Created by tedqu on 24-9-9.
//

#define ROUTE_TABLE_BUCKETS 128
#define MAX_ROUTES 4096
#define NUMBER_TBL8 256
#define DEFAULT_MTU 1500

#include <rte_lpm.h>
#include <rte_malloc.h>
#include <stdlib.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/pipeline.h"
#include "route.h"

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;

static uint32_t next_rt_id;
static struct list_head route_table[ROUTE_TABLE_BUCKETS];
static struct rte_lpm* lpm_table;

static uint32_t get_route_entry_id(void) {
    return next_rt_id++;
}

static int get_route_entry_hash(uint32_t route_entry_id) {
    return (int)route_entry_id % ROUTE_TABLE_BUCKETS;
}

int route_add(uint32_t dst_addr, uint16_t mask, unsigned long mtu, uint32_t gw,
              uint32_t src, struct dev_port *port, uint16_t metric, uint32_t flags) {
    int ret;
    int hash;
    struct route_entry *rt_entry;

    rt_entry = rte_zmalloc("route entry", sizeof(struct route_entry), RTE_CACHE_LINE_SIZE);
    if (NULL == rt_entry) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__ );
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

    ret = rte_lpm_add(lpm_table, rt_entry->dst_addr, rt_entry->mask, rt_entry->id);
    if (ret < 0) {
        rte_free(rt_entry);
        return ret;
    }

    hash = get_route_entry_hash(rt_entry->id);
    list_add(&rt_entry->route_list_node, &route_table[hash]);

    return NAT_LB_OK;
}

int route_del(uint32_t dst_addr, uint16_t mask) {
    struct route_entry *rt_entry = NULL;
    uint32_t rt_entry_id;
    int ret, hash;

    ret = rte_lpm_is_rule_present(lpm_table, dst_addr, mask, &rt_entry_id);
    if (ret == 0) {
        return NAT_LB_NOT_EXIST;
    }
    if (ret < 0) {
        return ret;
    }

    hash = get_route_entry_hash(rt_entry_id);
    list_for_each_entry(rt_entry, &route_table[hash], route_list_node) {
        if (rt_entry->id == rt_entry_id) {
            break;
        }
    }
    if (NULL != rt_entry) {
        list_del(&rt_entry->route_list_node);
        rte_free(rt_entry);
        rte_lpm_delete(lpm_table, dst_addr, mask);
    }

    return NAT_LB_OK;
}

static struct route_entry* route_lookup(uint32_t dst_addr) {
    int ret;
    int hash;
    unsigned int rt_entry_id;
    struct route_entry *rt_entry;

    ret = rte_lpm_lookup(lpm_table, dst_addr, &rt_entry_id);
    if (ret != 0) {
        return NULL;
    }

    hash = get_route_entry_hash(rt_entry_id);
    list_for_each_entry(rt_entry, &route_table[hash], route_list_node) {
        if (rt_entry->id == rt_entry_id) {
            return rt_entry;
        }
    }
    return NULL;
}

struct route_entry* route_ingress_lockup(struct flow4* fl) {
    return route_lookup(rte_be_to_cpu_32(fl->dst_addr));
}

struct route_entry* route_egress_lockup(struct  flow4* fl) {
    return route_lookup(rte_be_to_cpu_32(fl->dst_addr));
}

static pipeline_actions route_in(sk_buff_t *skb) {
    struct rt_cache *rt;
    struct per_lcore_ct_ctx *ctx;

    ctx = &per_lcore_ctx;
    rt = ct_ext_data_get(CT_EXT_ROUTE, ctx->ct);
    if (NULL != rt->port) {
        return (rt->flags & RTF_FORWARD) ? PIPELINE_ACTION_FORWARD : PIPELINE_ACTION_LOCAL_IN;
    } else {
        rt->mtu = DEFAULT_MTU;
        rt->gw = 0;
        rt->port = get_port_by_id(skb->rcv_port);
        rt->flags = RTF_FORWARD;
        ctx->ct->ext_flags |= (1 << CT_EXT_ROUTE);
        return PIPELINE_ACTION_FORWARD;
    }
}

struct ct_ext route_ct_ext = {
        .type = CT_EXT_ROUTE,
        .need_sync = false,
        .length = sizeof(struct rt_cache),
        .offset = 0,
        .sync_ext_push_func = NULL,
        .sync_ext_pop_func = NULL,
};

void route_module_init(int socket_id) {
    int i;
    char name[64];
    struct rte_lpm_config lpm_cfg;

    for (i = 0; i < ROUTE_TABLE_BUCKETS; i++) {
        INIT_LIST_HEAD(&route_table[i]);
    }

    snprintf(name, sizeof (name), "route_table_%d", socket_id);
    lpm_cfg.flags = 0;
    lpm_cfg.max_rules = MAX_ROUTES;
    lpm_cfg.number_tbl8s = NUMBER_TBL8;

    lpm_table = rte_lpm_create(name, socket_id, &lpm_cfg);
    if (NULL == lpm_table) {
        rte_exit(EXIT_FAILURE, "%s: create route table in socket %d failed, %s",
                 __func__, socket_id, rte_strerror(rte_errno));
    }

    ct_ext_register(&route_ct_ext);
    pipeline_register("route_in", route_in, PIPELINE_PRIORITY_ROUTE, NULL);
}
