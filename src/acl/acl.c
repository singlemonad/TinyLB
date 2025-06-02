//
// Created by tedqu on 24-9-14.
//

#include <toml.h>
#include <rte_malloc.h>
#include "../common/skb.h"
#include "../common/pipeline.h"
#include "../common/conf.h"
#include "../common/log.h"
#include "../common/util.h"
#include "acl.h"

#define MAX_ACL_RULE 512

#define ACL_DEFAULT_CATEGORY_MASK 1
#define ACL_DEFAULT_PRIORITY 1

static struct conf_item acl_conf_parser;

extern __thread struct per_lcore_ct_ctx per_lcore_ctx;
static struct rte_acl_ctx *g_ingress_acl;
static struct rte_acl_ctx *g_egress_acl;

struct rte_acl_field_def ipv4_defs[3] = {
        {
                .type = RTE_ACL_FIELD_TYPE_BITMASK,
                .size = sizeof(uint8_t),
                .field_index = 0,
                .input_index = 0,
                .offset = offsetof(struct ipv4_3tuple, proto)
        },
        {
                .type = RTE_ACL_FIELD_TYPE_MASK,
                .size = sizeof(uint32_t),
                .field_index = 1,
                .input_index = 1,
                .offset = offsetof(struct ipv4_3tuple, ip_src)
        },
        {
                .type = RTE_ACL_FIELD_TYPE_MASK,
                .size = sizeof(uint32_t),
                .field_index = 2,
                .input_index = 2,
                .offset = offsetof(struct ipv4_3tuple, ip_dst)
        }
};

int ingress_acl_rule_add(struct acl_ipv4_rule rule) {
    struct rte_acl_config cfg;
    int ret;

    ret = rte_acl_add_rules(g_ingress_acl, (const struct rte_acl_rule*)&rule, 1);
    if (ret == -ENOMEM) {
        RTE_LOG(ERR, NAT_LB, "%s: no memory\n");
        return ret;
    } else if (ret == -EINVAL) {
        return ret;
    }

    cfg.num_categories = 1;
    cfg.num_fields = RTE_DIM(ipv4_defs);
    memcpy(cfg.defs, ipv4_defs, sizeof(ipv4_defs));

    ret = rte_acl_build(g_ingress_acl, &cfg);
    return ret;
}

int ingress_acl_match(struct ipv4_3tuple *fields) {
    int ret;
    uint32_t result[4];
    const uint8_t *data[1];
    data[0] = (uint8_t*)fields;

    ret = rte_acl_classify(g_ingress_acl, data, result, 1, 4);
    if (ret != 0) {
        return ret;
    }

    if (result[0] == 0) {
        result[0] = ACL_ACCEPT;
    }
    return (int)result[0];
}

static pipeline_actions ingress_acl_in(sk_buff_t *skb) {
    struct per_lcore_ct_ctx *ctx;
    struct rte_ipv4_hdr *iph;
    struct ipv4_3tuple match;
    int acl_action;
    int *acl_ext;

    ctx = &per_lcore_ctx;
    if (ctx->ct->state == CT_NEW) {
        iph = rte_pktmbuf_mtod((struct rte_mbuf *) skb, struct rte_ipv4_hdr*);
        match.proto = iph->next_proto_id;
        match.ip_src = iph->src_addr;
        match.ip_dst = iph->dst_addr;

        acl_action = ingress_acl_match(&match);
        acl_ext = ct_ext_data_get(CT_EXT_ACL_ACTION, ctx->ct);
        *acl_ext = acl_action;
        ctx->ct->ext_flags |= (1 << CT_EXT_ACL_ACTION);
    }

    if (*(int *)ct_ext_data_get(CT_EXT_ACL_ACTION, ctx->ct) == ACL_DROP) {
        return PIPELINE_ACTION_DROP;
    }
    return PIPELINE_ACTION_NEXT;
}

struct ct_ext acl_ct_ext = {
        .type = CT_EXT_ACL_ACTION,
        .need_sync = false,
        .length = sizeof(int),
        .offset = 0,
        .sync_ext_push_func = NULL,
        .sync_ext_pop_func = NULL,
};

static const char* acl_item_name[7] = {
    "direction",
    "proto",
    "src_addr",
    "src_mask",
    "dst_addr",
    "dst_mask",
    "action",
};

static void acl_parse_func(struct conf_item *item, toml_table_t *table) {
    toml_datum_t dir = toml_int_in(table, acl_item_name[0]);
    toml_datum_t proto = toml_int_in(table, acl_item_name[1]);
    toml_datum_t src_addr = toml_string_in(table, acl_item_name[2]);
    toml_datum_t src_mask = toml_int_in(table, acl_item_name[3]);
    toml_datum_t dst_addr = toml_string_in(table, acl_item_name[4]);
    toml_datum_t dst_mask = toml_int_in(table, acl_item_name[5]);
    toml_datum_t action = toml_int_in(table, acl_item_name[6]);
    RTE_LOG(INFO, NAT_LB, "%s: add acl, dir=%ld,proto=%ld,src_addr=%s,src_mask=%ld,dst_addr=%s,dst_port=%ld,action=%ld\n",
            __func__, dir.u.i, proto.u.i, src_addr.u.s, src_mask.u.i, dst_addr.u.s, dst_mask.u.i, action.u.i);

    int ret;
    struct acl_ipv4_rule rule;
    rule.data.userdata = action.u.i;
    rule.data.category_mask = ACL_DEFAULT_CATEGORY_MASK;
    rule.data.priority = ACL_DEFAULT_PRIORITY;
    rule.field[0].value.u8 = (uint8_t)proto.u.i;
    rule.field[0].mask_range.u8 = 0xff;
    rule.field[1].value.u32 = (uint32_t)ip_to_int(src_addr.u.s);
    rule.field[1].mask_range.u32 = (uint32_t)(src_mask.u.i);
    rule.field[2].value.u32 = (uint32_t)ip_to_int(dst_addr.u.s);
    rule.field[2].mask_range.u32 = (uint32_t)(dst_mask.u.i);
    if (dir.u.i == INGRESS) {
        ret = ingress_acl_rule_add(rule);
    } else {
        // TODO support egress
        ret = NAT_LB_OK;
    }

    if (NAT_LB_OK != ret) {
        rte_exit(EXIT_FAILURE, "%s, add ingress acl rule failed, %s.", __func__, rte_strerror(rte_errno));
    }
}

static void init_acl_parser(void) {
    char conf_name[] = "acl";
    bzero(&acl_conf_parser, sizeof(acl_conf_parser));

    memcpy(acl_conf_parser.name, conf_name, strlen(conf_name));
    acl_conf_parser.parse_func = acl_parse_func;
    add_conf_item_parser(&acl_conf_parser);
}

void acl_module_init(void) {
    struct rte_acl_param parm;

    init_acl_parser();

    parm.name = "acl_ingress";
    parm.socket_id = SOCKET_ID_ANY;
    parm.max_rule_num = MAX_ACL_RULE;
    parm.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));

    g_ingress_acl = rte_acl_create(&parm);
    if (NULL == g_ingress_acl) {
        rte_exit(EXIT_FAILURE, "%s: create ingress acl failed, %s", __func__, rte_strerror(rte_errno));
    }

    ct_ext_register(&acl_ct_ext);
    pipeline_register("ingress_acl_in", ingress_acl_in, PIPELINE_PRIORITY_ACL, NULL);
}
