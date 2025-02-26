//
// Created by tedqu on 24-9-14.
//

#include <rte_malloc.h>
#include "../include/acl.h"
#include "../include/skb.h"
#include "../include/pipeline.h"


#define MAX_ACL_RULE 512

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
        fprintf(stderr, "No space.");
        return ret;
    } else if (ret == -EINVAL) {
        fprintf(stderr, "Invalid rule.");
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
    struct per_cpu_ctx *ctx;
    struct rte_ipv4_hdr *iph;
    struct ipv4_3tuple match;
    int acl_action;
    int *acl_ext;

    ctx = get_per_cpu_ctx();
    if (ctx->ct->state == CT_NEW) {
        iph = rte_pktmbuf_mtod((struct rte_mbuf *) skb, struct rte_ipv4_hdr*);
        match.proto = iph->next_proto_id;
        match.ip_src = iph->src_addr;
        match.ip_dst = iph->dst_addr;

        acl_action = ingress_acl_match(&match);
        acl_ext = ct_ext_data_get(CT_EXT_ACL_ACTION, ctx->ct);
        *acl_ext = acl_action;
    }

    if (*(int *)ct_ext_data_get(CT_EXT_ACL_ACTION, ctx->ct) == ACL_DROP) {
        return PIPELINE_ACTION_DROP;
    }
    return PIPELINE_ACTION_NEXT;
}

void acl_module_init(void) {
    struct rte_acl_param parm;

    parm.name = "acl_ingress";
    parm.socket_id = SOCKET_ID_ANY;
    parm.max_rule_num = MAX_ACL_RULE;
    parm.rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs));

    g_ingress_acl = rte_acl_create(&parm);
    if (NULL == g_ingress_acl) {
        rte_exit(EXIT_FAILURE, "Create ingress acl failed, %s", rte_strerror(rte_errno));
    }

    ct_ext_register(CT_EXT_ACL_ACTION, sizeof(int));
    pipeline_register("ingress_acl_in", ingress_acl_in, PIPELINE_PRIORITY_ACL, NULL);
}
