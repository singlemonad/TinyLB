//
// Created by tedqu on 24-9-29.
//

#include <toml.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>
#include "../common/util.h"
#include "../common/log.h"
#include "../common/conf.h"
#include "../common/ip_group.h"
#include "../ha/ha.h"
#include "svc.h"
#include "sa_pool.h"

#define SVC_BUCKET_SIZE 64
#define RS_BUCKET_SIZE 8

extern struct rte_rcu_qsbr* rcu_lock;
static struct list_head svc_bucket[SVC_BUCKET_SIZE];
static struct conf_item rs_conf_parser;

static inline uint32_t get_svc_hash(uint8_t proto, uint32_t vip, uint16_t vport) {
    return rte_jhash_2words(proto, vip, vport) % SVC_BUCKET_SIZE;
}

static svc_t* svc_new(void) {
    svc_t* svc = rte_malloc("svc", sizeof(svc_t), RTE_CACHE_LINE_SIZE);
    if (NULL == svc) {
        return NULL;
    }

    INIT_LIST_HEAD(&svc->rs_list);
    return svc;
}

int svc_add(uint8_t proto, uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    hash = get_svc_hash(proto, vip, vport);
    list_for_each_entry(svc, &svc_bucket[hash], svc_node) {
        if (svc->proto == proto && svc->vip == vip && svc->vport == vport) {
            return NAT_LB_EXIST;
        }
    }

    svc = svc_new();
    if (NULL == svc) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__);
        return NAT_LB_NOMEM;
    }
    svc->proto = proto;
    svc->vip = vip;
    svc->vport = vport;
    svc->rs_cnt = 0;
    svc->scheduler = get_scheduler("wrr");
    svc->scheduler->init_service(svc);
    list_add(&svc->svc_node, &svc_bucket[hash]);
    add_ip_group(IP_TYPE_SVC, vip);
    return NAT_LB_OK;
}

int svc_del(uint8_t proto, uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    svc = NULL;
    hash = get_svc_hash(proto, vip, vport);
    list_for_each_entry(svc, &svc_bucket[hash], svc_node) {
        if (svc->proto == proto && svc->vip == vip && svc->vport == vport) {
            break;
        }
    }

    uint64_t rcu_token;
    if (svc != NULL) {
        list_del(&svc->svc_node);

        rcu_token = rte_rcu_qsbr_start(rcu_lock);
        if (rte_rcu_qsbr_check(rcu_lock, rcu_token, true) == 1) {
            RTE_LOG(DEBUG, NAT_LB, "%s: free svc, vip=%s,vport=%d\n", be_ip_to_str(svc->vip), ntohs(svc->vport));
            rte_free(svc);
        } else {
            //
        }
        return NAT_LB_OK;
    }
    return NAT_LB_NOT_EXIST;
}

svc_t* svc_find(uint8_t proto, uint32_t vip, uint32_t vport) {
    uint32_t hash;
    svc_t *svc;

    hash = get_svc_hash(proto, vip, vport);
    list_for_each_entry(svc, &svc_bucket[hash], svc_node) {
        if (svc->proto == proto && svc->vip == vip && svc->vport == vport) {
            return svc;
        }
    }
    return NULL;
}

static inline uint32_t get_rs_hash(uint32_t vip, uint16_t vport) {
    return rte_jhash_1word(vip, vport) % RS_BUCKET_SIZE;
}

static inline rs_t *rs_new(void) {
    return rte_malloc("rs", sizeof(rs_t), RTE_CACHE_LINE_SIZE);
}

int rs_add(svc_t *svc, uint32_t rs_ip, uint16_t rs_port, uint16_t weight) {
    rs_t *rs;

    list_for_each_entry(rs, &svc->rs_list, rs_node) {
        if (rs->rs_ip == rs_ip && rs->rs_port == rs_port) {
            return NAT_LB_EXIST;
        }
    }

    rs = rs_new();
    if (NULL == rs) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n", __func__ );
        return NAT_LB_NOMEM;
    }

    rs->rs_ip = rs_ip;
    rs->rs_port = rs_port;
    rs->weight = weight;
    create_snat_pool_for_rs(rs);
    svc->rs_cnt++;
    list_add(&rs->rs_node, &svc->rs_list);
    svc->scheduler->update_service(svc);
    // add_detect_rs(svc->proto, rs_ip, rs_port);
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

rs_t* rs_schedule(struct svc* svc, struct sk_buff* skb, uint8_t proto, uint32_t vip, uint32_t vport) {
    return svc->scheduler->schedule(svc, skb);
}

static const char* rs_item_name[6] = {
        "vip",
        "vport",
        "proto",
        "pip",
        "pport",
        "weight"
};

static void rs_parse_func(struct conf_item *item, toml_table_t *table) {
    int ret;

    toml_datum_t vip = toml_string_in(table, rs_item_name[0]);
    toml_datum_t vport = toml_int_in(table, rs_item_name[1]);
    toml_datum_t proto = toml_int_in(table, rs_item_name[2]);
    toml_datum_t pip = toml_string_in(table, rs_item_name[3]);
    toml_datum_t pport = toml_int_in(table, rs_item_name[4]);
    toml_datum_t weight = toml_int_in(table, rs_item_name[5]);
    RTE_LOG(INFO, NAT_LB, "%s: add rs, vip=%s,vport=%ld,proto=%ld,pip=%s,pport=%ld,weight=%ld\n", __func__, vip.u.s, vport.u.i, proto.u.i, pip.u.s, pport.u.i, weight.u.i);
    uint32_t vip_be = ip_to_int_be(vip.u.s);
    uint32_t vport_be = htons(vport.u.i);
    svc_t* svc = svc_find(proto.u.i, vip_be, vport_be);
    if (NULL == svc) {
        ret = svc_add(proto.u.i, vip_be, vport_be);
        if (ret != NAT_LB_OK) {
            rte_exit(EXIT_FAILURE, "%s: add svc failed\n", __func__);
        }
        svc = svc_find(proto.u.i, vip_be, vport_be);
    }

    uint32_t pip_be = ip_to_int_be(pip.u.s);
    uint32_t pport_be = htons(pport.u.i);
    ret = rs_add(svc, pip_be, pport_be, weight.u.i);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "%s: add rs failed\n", __func__);
    }
}

static void init_rs_parser(void) {
    char conf_name[] = "rs";
    bzero(&rs_conf_parser, sizeof(rs_conf_parser));

    memcpy(rs_conf_parser.name, conf_name, strlen(conf_name));
    rs_conf_parser.parse_func = rs_parse_func;
    add_conf_item_parser(&rs_conf_parser);
}

void svc_init(void) {
    int i;

    init_rs_parser();

    for (i = 0; i < SVC_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&svc_bucket[i]);
    }
}