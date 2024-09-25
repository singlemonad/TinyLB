//
// Created by tedqu on 24-9-15.
//

#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_arp.h>
#include "common.h"
#include "dev.h"
#include "l2.h"
#include "arp.h"
#include "neigh.h"

static int arp_rcv(struct rte_mbuf *mbuf, struct dev_port *port) {
    int ret;
    struct rte_arp_hdr *arp;
    uint32_t arp_sip, arp_tip;
    struct rte_ether_addr arp_sha, arp_tha;
    struct neighbor *neighbor;
    struct neigh_mbuf *neigh_mbuf;

    arp = rte_pktmbuf_mtod(mbuf, struct rte_arp_hdr*);
    arp_tip = ntohl(arp->arp_data.arp_tip);
    if (arp->arp_opcode == ntohs(RTE_ARP_OP_REQUEST)) {
        return NAT_LB_OK;
    } else if (arp->arp_opcode == ntohs(RTE_ARP_OP_REPLY)) {
        arp_sip = ntohl(arp->arp_data.arp_sip);
        rte_ether_addr_copy(&arp->arp_data.arp_sha, &arp_sha);

        neighbor = neighbor_lookup(arp_sip);
        if (NULL != neighbor) {
            rte_ether_addr_copy(&arp_sha, &neighbor->mac);
            list_for_each_entry(neigh_mbuf, &neighbor->wait_pkt, neigh_mbuf_node) {
                fprintf(stdout, "xmit wait pkt.\n");
                port_xmit(neigh_mbuf->mbuf, port);
            }
            // TODO free neigh_mbuf
            return NAT_LB_OK;
        }

        ret = neighbor_add(arp_sip, &arp_sha);
        if (NAT_LB_OK != ret) {
            fprintf(stderr, "Neighbor add failed.\n");
        }

        return ret;
    }

    return NAT_LB_OK;
}

int arp_send(struct dev_port *port, uint32_t src_ip, uint32_t dst_ip) {
    struct rte_mbuf *mbuf;
    struct rte_ether_hdr *eth;
    struct rte_arp_hdr *arp;

    mbuf = rte_pktmbuf_alloc(port->mbuf_pool);
    if (NULL == mbuf) {
        fprintf(stderr, "No memory, %s\n", __func__ );
        return NAT_LB_NOMEM;
    }

    eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    arp = (struct rte_arp_hdr*)&eth[1];

    rte_ether_addr_copy(&port->mac, &eth->src_addr);
    memset(&eth->dst_addr, 0xFF, 6);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    memset(arp, 0, sizeof(struct rte_arp_hdr));
    rte_ether_addr_copy(&port->mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = rte_cpu_to_be_32(src_ip);
    memset(&arp->arp_data.arp_tha, 0xFF, 6);
    arp->arp_data.arp_tip = rte_cpu_to_be_32(dst_ip);
    arp->arp_hardware = htons(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode = htons(RTE_ARP_OP_REQUEST);

    mbuf->pkt_len = 60;
    mbuf->data_len = 60;
    mbuf->l2_len = sizeof(struct rte_ether_hdr);
    mbuf->l3_len = sizeof(struct rte_arp_hdr);

    memset(&arp[1], 0, 18);
    port_xmit(mbuf, port);

    return NAT_LB_OK;
}

static struct pkt_type arp_handler = {
        .type = RTE_ETHER_TYPE_ARP,
        .func = arp_rcv
};

void arp_init(void) {
    int ret;

    ret = pkt_type_register(&arp_handler);
    if (NAT_LB_OK != ret) {
        rte_exit(EXIT_FAILURE, "Register ARP handler failed.");
    }
}