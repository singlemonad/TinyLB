//
// Created by tedqu on 24-9-14.
//

#ifndef NAT_LB_ACL_H
#define NAT_LB_ACL_H

#include <inttypes.h>
#include <rte_acl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ACL_ACCEPT 1
#define ACL_DROP 2

struct acl_ipv4_rule;

struct ipv4_3tuple {
    uint8_t proto;
    uint32_t ip_src;
    uint32_t ip_dst;
};

extern struct rte_acl_field_def ipv4_defs[3];
RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));

void acl_module_init(void);
int ingress_acl_rule_add(struct acl_ipv4_rule rule);
int ingress_acl_match(struct ipv4_3tuple *data);

#endif //NAT_LB_ACL_H
