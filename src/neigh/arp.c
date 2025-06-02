//
// Created by tedqu on 24-9-15.
//

#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_malloc.h>
#include <rte_arp.h>
#include <linux/if_ether.h>
#include "../common/util.h"
#include "arp.h"
#include "neigh.h"
#include "../common/log.h"
#include "../inet/inet.h"

static int arp_rcv(sk_buff_t *skb) {
    int ret = NAT_LB_OK;
    struct rte_arp_hdr *arp = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_arp_hdr*);

    if (arp->arp_opcode != ntohs(RTE_ARP_OP_REPLY)) {
        rte_pktmbuf_free((struct rte_mbuf*)skb);
        return NAT_LB_OK;
    }

    RTE_LOG(DEBUG, NAT_LB, "%s: lcore %d rcv arp pkt\n", __func__, rte_lcore_id());

    uint32_t arp_sip = ntohl(arp->arp_data.arp_sip);
    struct neighbor *neighbor = neighbor_lookup(arp_sip);
    if (NULL != neighbor) {
        neighbor->state = NEIGHBOR_VALID;
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &neighbor->mac);

        struct neigh_mbuf *neigh_mbuf;
        list_for_each_entry(neigh_mbuf, &neighbor->wait_pkt, neigh_mbuf_node) {
            RTE_LOG(DEBUG, NAT_LB, "%s: send wait skb, addr=%p,mbuf.data_len=%d\n", __func__, neigh_mbuf->skb, neigh_mbuf->skb->mbuf.data_len);
            struct dev_port *port = get_port_by_id(skb->mbuf.port);
            neigh_fill_mac(neigh_mbuf->skb, neighbor, port);
            dev_port_xmit(port, neigh_mbuf->skb);
        }

        struct list_head *wait_pkt_head = &neighbor->wait_pkt;
        struct list_head *curr = wait_pkt_head->next;
        while (curr != wait_pkt_head) {
            struct list_head *next = curr->next;
            list_del(curr);
            rte_free(container_of(curr, struct neigh_mbuf, neigh_mbuf_node));
            curr = next;
            RTE_LOG(DEBUG, NAT_LB, "%s: free arp wait pkt\n", __func__);
        }

    } else {
        ret = neighbor_add(arp_sip, &arp->arp_data.arp_sha);
        if (NAT_LB_OK != ret) {
            RTE_LOG(ERR, NAT_LB, "%s: neighbor add failed\n");
        }
    }

    rte_pktmbuf_free((struct rte_mbuf*)skb);
    return ret;
}

int arp_send(struct dev_port *port, uint32_t src_ip, uint32_t dst_ip) {
    sk_buff_t *skb;
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;

    skb = (sk_buff_t*)rte_pktmbuf_alloc(port->mbuf_pool);
    if (NULL == skb) {
        fprintf(stderr, "No memory, %s\n", __func__ );
        return NAT_LB_NOMEM;
    }

    eth = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ether_hdr*);
    arp = (struct rte_arp_hdr*)&eth[1];

    rte_ether_addr_copy(&port->mac, &eth->src_addr);
    memset(&eth->dst_addr, 0xFF, 6);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(struct rte_arp_hdr));
    rte_ether_addr_copy(&port->mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = src_ip;
    memset(&arp->arp_data.arp_tha, 0xFF, 6);
    arp->arp_data.arp_tip = rte_cpu_to_be_32(dst_ip);
    arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode = htons(RTE_ARP_OP_REQUEST);

    skb->mbuf.pkt_len = 60;
    skb->mbuf.data_len = 60;
    skb->mbuf.l2_len = sizeof(struct rte_ether_hdr);
    skb->mbuf.l3_len = sizeof(struct rte_arp_hdr);

    memset(&arp[1], 0, 18);
    dev_port_xmit(port, skb);

    return NAT_LB_OK;
}

static struct l3_handler arp_handler = {
        .rcv= arp_rcv
};

void arp_init(void) {
    inet_register_l3_handler(&arp_handler, ETH_P_ARP);
}