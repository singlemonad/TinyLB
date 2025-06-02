//
// Created by tedqu on 24-9-30.
//

#include <toml.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/conf.h"
#include "svc.h"
#include "sa_pool.h"

#define SNAT_ADDR_MAX_RETRY 100

// 全局snat地址池
struct list_head sa_pool[MAX_LCORE];
static struct conf_item snat_conf_parser;

static snat_ip_t* sa_ip_alloc(void) {
    snat_ip_t *sa;

    sa = rte_malloc("snat_ip pool", sizeof(snat_ip_t), RTE_CACHE_LINE_SIZE);
    if (NULL == sa) {
        RTE_LOG(ERR, EAL, "No memory, %s", __func__ );
        return NULL;
    }
    return sa;
}

static snat_pool_t * sa_pool_alloc(uint32_t ip) {
    snat_pool_t *snat_pool;

    snat_pool = rte_malloc("original_snat addr", sizeof(snat_pool_t), RTE_CACHE_LINE_SIZE);
    if (NULL == snat_pool) {
        RTE_LOG(ERR, EAL, "No memory, %s", __func__ );
        return NULL;
    }
    snat_pool->next_port = PORT_MIN;
    snat_pool->snat_ip = ip;
    return snat_pool;
}

// 添加snat地址
int snat_addr_add(unsigned lcore_id, uint32_t snat_ip) {
    snat_ip_t *sa;

    list_for_each_entry(sa, &sa_pool[lcore_id], sa_node) {
        if (sa->ip == snat_ip) {
            return NAT_LB_EXIST;
        }
    }

    sa = sa_ip_alloc();
    if (NULL == sa) {
        return NAT_LB_NOMEM;
    }

    sa->lcore_id = lcore_id;
    sa->ip = snat_ip;
    list_add(&sa->sa_node, &sa_pool[lcore_id]);
    add_ip_group(IP_TYPE_SNAT, snat_ip);

    return NAT_LB_OK;
}

// 删除snat地址，snat地址是静态配置，不支持删除
int snat_addr_del(unsigned lcore_id, uint32_t snat_ip) {
    snat_ip_t *sa;
    uint32_t hash;
    bool found = false;

    list_for_each_entry(sa, &sa_pool[lcore_id], sa_node) {
        if (sa->ip == snat_ip) {
            found = true;
            break;
        }
    }

    if (!found) {
        return NAT_LB_NOT_EXIST;
    }

    list_del(&sa->sa_node);
    rte_free(sa);
    return NAT_LB_OK;
}

static int snat_port_get(snat_pool_t *snat_addr, uint16_t *snat_port) {

    return NAT_LB_NO_SNAT_PORT;
}

static bool snat_in_use(uint16_t proto, uint32_t rs_ip, uint16_t rs_port, uint32_t snat_ip, uint16_t snat_port) {
    return ct_tuple_in_use(proto, rs_ip, rs_port, snat_ip, snat_port);
}

// 根据lcore获取可用的snat地址
int snat_addr_get(uint16_t proto, uint32_t rs_ip, uint16_t rs_port, struct snat_pool_array* snat_pools, uint32_t *snat_ip, uint16_t *snat_port) {
    int i = 0, idx;
    uint32_t ip;
    uint16_t port;
    for ( ; i < SNAT_ADDR_MAX_RETRY; i++){
        idx = snat_pools->next_idx;
        ip = snat_pools->snat_ips[idx]->snat_ip;
        port = snat_pools->snat_ips[idx]->next_port;

        if (snat_in_use(proto, rs_ip, rs_port, ip, port)) {
            ++snat_pools->snat_ips[idx]->next_port;
            if (snat_pools->snat_ips[idx]->next_port > PORT_MAX) {
                snat_pools->snat_ips[idx]->next_port = PORT_MIN;
                ++snat_pools->next_idx;
                if (snat_pools->next_idx >= snat_pools->cnt) {
                    snat_pools->next_idx = 0;
                }
            }
        } else {
            *snat_ip = ip;
            *snat_port = htons(port);
            // RTE_LOG(INFO, NAT_LB, "%s: snat ip=%s, snat port=%d\n", __func__, be_ip_to_str(*snat_ip), ntohs(*snat_port));

            ++snat_pools->snat_ips[idx]->next_port;
            if (snat_pools->snat_ips[idx]->next_port > PORT_MAX) {
                snat_pools->snat_ips[idx]->next_port = PORT_MIN;
                ++snat_pools->next_idx;
                if (snat_pools->next_idx >= snat_pools->cnt) {
                    snat_pools->next_idx = 0;
                }
            }
            return NAT_LB_OK;
        }
    }
    return NAT_LB_NOT_EXIST;
}

// 根据snat_ip获取对应的lcore
unsigned snat_addr_lcore(uint32_t snat_ip) {
    snat_ip_t *sa;
    int idx;

    for (idx = 0; idx < MAX_SA_POOL_BUCKETS; idx++) {
        list_for_each_entry(sa, &sa_pool[idx], sa_node) {
            if (sa->ip == snat_ip) {
                return idx;
            }
        }
    }
    return MAX_SA_POOL_BUCKETS;
}

static const char* snat_item_name[2] = {
    "lcore_id",
    "snat_ip",
};

static void snat_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t lcore_id = toml_int_in(table, snat_item_name[0]);
    toml_datum_t snat_ip = toml_string_in(table, snat_item_name[1]);
    RTE_LOG(INFO, NAT_LB, "%s: add snat ip, lcore_id=%ld,snat_ip=%s\n", __func__, lcore_id.u.i, snat_ip.u.s);

    int ret;
    uint32_t snat_ip_be = ip_to_int_be(snat_ip.u.s);
    ret = snat_addr_add(lcore_id.u.i, snat_ip_be);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: add snat ip failed\n", __func__);
    }
}

static void init_snat_parser(void) {
    char conf_name[] = "snat";
    bzero(&snat_conf_parser, sizeof(snat_conf_parser));

    memcpy(snat_conf_parser.name, conf_name, strlen(conf_name));
    snat_conf_parser.parse_func = snat_parse_func;
    add_conf_item_parser(&snat_conf_parser);
}

int create_snat_pool_for_rs(rs_t *rs) {
    int lcore_id, cnt;
    struct snat_ip* snat;

    cnt = 0;
    for ( lcore_id = 0; lcore_id < MAX_LCORE; lcore_id++) {
        if (lcore_type_array[lcore_id] == LCORE_TYPE_WORK) {
            list_for_each_entry(snat, &sa_pool[lcore_id], sa_node) {
                rs->snat_ips[lcore_id].snat_ips[cnt] = sa_pool_alloc(snat->ip);
                ++cnt;
            }
            rs->snat_ips[lcore_id].next_idx = 0;
            rs->snat_ips[lcore_id].cnt = cnt;
        }
    }
    return NAT_LB_OK;
}

void sa_pool_init(void) {
    int i;

    init_snat_parser();
    for (i = 0; i < MAX_LCORE; i++) {
        INIT_LIST_HEAD(&sa_pool[i]);
    }
}