//
// Created by tedqu on 25-3-5.
//

#include <linux/if_ether.h>
#include <rte_gre.h>
#include "../common/util.h"
#include "../common/skb.h"
#include "../common/log.h"
#include "ipv4.h"
#include "gre.h"

static int gre_rcv(sk_buff_t *skb, struct rte_ipv4_hdr *iph) {
    struct rte_gre_hdr *gre;

    gre = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_gre_hdr*);
    if (!gre->s || ntohs(gre->proto) != ETH_P_IP) {
        RTE_LOG(ERR, NAT_LB, "%s: invalid gre pkt, sequence not set or overlay proto not IPv4\n", __func__ );
        goto drop;
    }

    skb->vpc_id = *(uint32_t *)((unsigned long)gre + sizeof(struct rte_gre_hdr));
    rte_pktmbuf_adj(&skb->mbuf, sizeof(struct rte_gre_hdr) + sizeof(uint32_t));
    return ipv4_rcv(skb);

drop:
    rte_pktmbuf_free(&skb->mbuf);
    return NAT_LB_DROP;
}

static struct l4_handler gre_proto = {
        .rcv = gre_rcv,
};

int uncap_gre(sk_buff_t *skb, struct rte_ipv4_hdr *iph) {
    struct rte_gre_hdr *gre;

    gre = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_gre_hdr*);
    if (!gre->s || ntohs(gre->proto) != ETH_P_IP) {
        RTE_LOG(ERR, NAT_LB, "%s: invalid gre pkt, sequence not set or overlay proto not IPv4\n", __func__ );
        goto drop;
    }

    skb->vpc_id = *(uint32_t *)((unsigned long)gre + sizeof(struct rte_gre_hdr));
    rte_pktmbuf_adj(&skb->mbuf, sizeof(struct rte_gre_hdr) + sizeof(uint32_t));
    return NAT_LB_OK;

drop:
    rte_pktmbuf_free(&skb->mbuf);
    return NAT_LB_DROP;
}

void gre_init(void) {
    inet_register_l4_handler(&gre_proto, IPPROTO_GRE);
}