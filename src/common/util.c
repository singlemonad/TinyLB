//
// Created by tedqu on 24-9-10.
//

#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_arp.h>
#include "util.h"

char* protocol_to_str(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_IGMP:
            return "IGMP";
        default:
            return "UNKNOWN";
    }
}

uint32_t ip_to_int(char *addr) {
    struct in_addr s;
    inet_pton(AF_INET, addr, (void *)&s);
    return rte_be_to_cpu_32(s.s_addr);
}

uint32_t ip_to_int_be(char *addr) {
    struct in_addr s;
    inet_pton(AF_INET, addr, (void *)&s);
    return s.s_addr;
}

char* ip_to_str(uint32_t ip) {
    struct in_addr addr = {
            .s_addr = rte_be_to_cpu_32(ip),
    };
    return inet_ntoa(addr);
}

char* be_ip_to_str(uint32_t ip) {
    struct in_addr addr = {
            .s_addr = ip,
    };
    return inet_ntoa(addr);
}

uint32_t be_ip_to_int(char *str) {
    struct in_addr s;
    inet_pton(AF_INET, str, (void *)&s);
    return rte_be_to_cpu_32(s.s_addr);
}

void print_mac(struct rte_ether_addr *addr) {
    fprintf(stdout,  "%02" PRIx8 " %02" PRIx8 " %02" PRIx8" %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
            RTE_ETHER_ADDR_BYTES(addr));
}

void print_ip(rte_be32_t addr) {
    fprintf(stdout, "%s", be_ip_to_str(addr));
}

static void print_pkt_hdr(struct rte_ether_hdr *eth_hdr, struct rte_ipv4_hdr *ipv4_hdr) {
    fprintf(stdout, "src_mac=");
    print_mac(&eth_hdr->src_addr);

    fprintf(stdout, " dst_mac=");
    print_mac(&eth_hdr->dst_addr);

    fprintf(stdout, " src_ip=");
    print_ip(ipv4_hdr->src_addr);

    fprintf(stdout, " dst_ip=");
    print_ip(ipv4_hdr->dst_addr);

    fprintf(stdout, " ttl=%d", ipv4_hdr->time_to_live);

    fprintf(stdout, " next_proto=%d(%s)", ipv4_hdr->next_proto_id, protocol_to_str(ipv4_hdr->next_proto_id));
}

static void print_pkt_metadata(struct rte_mbuf* mbuf) {
    fprintf(stdout, " pkt_len=%d data_len=%d\n", mbuf->pkt_len, mbuf->data_len);
}

static void print_arp_pkt(struct rte_ether_hdr *eth_hdr, struct rte_arp_hdr *arp) {
    fprintf(stdout, "src_mac=");
    print_mac(&eth_hdr->src_addr);

    fprintf(stdout, " dst_mac=");
    print_mac(&eth_hdr->dst_addr);

    fprintf(stdout, " arp_sip=");
    print_ip(arp->arp_data.arp_sip);

    fprintf(stdout, " arp_sha=");
    print_mac(&arp->arp_data.arp_sha);

    fprintf(stdout, " arp_tip=");
    print_ip(arp->arp_data.arp_tip);

    fprintf(stdout, " arp_tha=");
    print_mac(&arp->arp_data.arp_tha);

    fprintf(stdout, " protocol=%d,hlen=%d,plen=%d,hardware=%d,opcode=%d\n",
            arp->arp_protocol, arp->arp_hlen, arp->arp_plen,
            arp->arp_hardware, arp->arp_opcode);
}

void print_pkt(sk_buff_t *pkt) {
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_arp_hdr *arp;

    eth_hdr = rte_pktmbuf_mtod((struct rte_mbuf*)pkt, struct rte_ether_hdr*);
    if (htons(RTE_ETHER_TYPE_IPV4) == eth_hdr->ether_type) {
        ipv4_hdr = (struct rte_ipv4_hdr *) (eth_hdr + 1);
        print_pkt_hdr(eth_hdr, ipv4_hdr);
        print_pkt_metadata((struct rte_mbuf *) pkt);
    } else if (htons(RTE_ETHER_TYPE_ARP) == eth_hdr->ether_type) {
        arp = (struct rte_arp_hdr *)(eth_hdr + 1);
        print_arp_pkt(eth_hdr, arp);
    } else {
        fprintf(stdout, "invalid pkt, ether_type=%d\n", ntohs(eth_hdr->ether_type));
    }
}

static int hex_to_num(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

void hex_str_to_mac(char *dst, char *src) {
    int i = 0;
    while (i < 6) {
        if(' ' == *src || ':'== *src || '"' == *src || '\'' == *src) {
            src++;
            continue;
        }
        *(dst + i) = (hex_to_num(*src) << 4) | hex_to_num(*(src + 1));
        i++;
        src += 2;
    }
}
