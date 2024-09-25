//
// Created by tedqu on 24-9-10.
//

#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include "common.h"

static void show_mac(struct rte_ether_addr *addr) {
    fprintf(stdout,  "%02" PRIx8 " %02" PRIx8 " %02" PRIx8" %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
            RTE_ETHER_ADDR_BYTES(addr));
}

static void show_ip(rte_be32_t addr) {
    fprintf(stdout, "%u.%u.%u.%u", addr & 0xff, (addr >> 8) & 0xff, (addr >> 16) & 0xff, (addr >> 24) & 0xff);
}

static void show_pkt_hdr(struct rte_ether_hdr *eth_hdr, struct rte_ipv4_hdr *ipv4_hdr) {
    fprintf(stdout, "src_mac=");
    show_mac(&eth_hdr->src_addr);

    fprintf(stdout, " dst_mac=");
    show_mac(&eth_hdr->dst_addr);

    fprintf(stdout, " src_ip=");
    show_ip(ipv4_hdr->src_addr);

    fprintf(stdout, " dst_ip=");
    show_ip(ipv4_hdr->dst_addr);

    fprintf(stdout, " ttl=%d", ipv4_hdr->time_to_live);

    fprintf(stdout, " next_proto=%d", ipv4_hdr->next_proto_id);
}

static void show_pkt_metadata(struct rte_mbuf* mbuf) {
    fprintf(stdout, " pkt_len=%d data_len=%d\n", mbuf->pkt_len, mbuf->data_len);
}

static void show_arp_pkt(struct rte_ether_hdr *eth_hdr, struct rte_arp_hdr *arp) {
    fprintf(stdout, "src_mac=");
    show_mac(&eth_hdr->src_addr);

    fprintf(stdout, " dst_mac=");
    show_mac(&eth_hdr->dst_addr);

    fprintf(stdout, " arp_sip=");
    show_ip(arp->arp_data.arp_sip);

    fprintf(stdout, " arp_sha=");
    show_mac(&arp->arp_data.arp_sha);

    fprintf(stdout, " arp_tip=");
    show_ip(arp->arp_data.arp_tip);

    fprintf(stdout, " arp_tha=");
    show_mac(&arp->arp_data.arp_tha);

    fprintf(stdout, " protocol=%d,hlen=%d,plen=%d,hardware=%d,opcode=%d\n",
            arp->arp_protocol, arp->arp_hlen, arp->arp_plen,
            arp->arp_hardware, arp->arp_opcode);
}

void show_pkt(struct rte_mbuf *pkt) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_arp_hdr *arp;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
    if (htons(RTE_ETHER_TYPE_IPV4) == eth_hdr->ether_type) {
        ipv4_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);
        show_pkt_hdr(eth_hdr, ipv4_hdr);
        show_pkt_metadata(pkt);
    } else if (htons(RTE_ETHER_TYPE_ARP) == eth_hdr->ether_type) {
        arp = (struct rte_arp_hdr *)(eth_hdr + 1);
        show_arp_pkt(eth_hdr, arp);
    }
}

uint32_t ip_to_int(char *str) {
    struct in_addr s;

    inet_pton(AF_INET, str, (void *)&s);
    return rte_be_to_cpu_32(s.s_addr);
}