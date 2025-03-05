//
// Created by tedqu on 25-3-4.
//

#include "../common/util.h"
#include "nat.h"

static uint16_t gen_ipv4_nat_checksum(uint32_t old_rev_val, uint32_t new_val, uint16_t old_check)
{
    uint32_t check_sum = old_check ^ 0xFFFF;

    check_sum += old_rev_val >> 16;
    check_sum += old_rev_val & 0xFFFF;
    check_sum += new_val >> 16;
    check_sum += new_val & 0xFFFF;

    check_sum = (check_sum & 0xFFFFUL) + (check_sum >> 16);
    check_sum = (check_sum & 0xFFFFUL) + (check_sum >> 16);

    return ~((uint16_t)check_sum);
}

static void rewrite_tcp_dst_port(struct rte_tcp_hdr *tcp, uint16_t new_port, uint32_t old_dst_ip, uint32_t new_dst_ip) {
    uint32_t old_ports = (tcp->src_port << 16) | tcp->dst_port;
    tcp->dst_port = new_port;
    uint32_t new_ports = (tcp->src_port << 16) | tcp->dst_port;
    tcp->cksum = gen_ipv4_nat_checksum(~old_dst_ip, new_dst_ip, tcp->cksum);
    tcp->cksum = gen_ipv4_nat_checksum(~old_ports, new_ports, tcp->cksum);
}

static void rewrite_udp_dst_port(struct rte_udp_hdr *udp, uint16_t new_port, uint32_t old_dst_ip ,uint32_t new_dst_ip) {
    uint32_t old_ports = (udp->src_port << 16) | udp->dst_port;
    udp->dst_port = new_port;
    uint32_t new_ports = (udp->src_port << 16) | udp->dst_port;
    udp->dgram_cksum = gen_ipv4_nat_checksum(~old_dst_ip, new_dst_ip, udp->dgram_cksum);
    udp->dgram_cksum = gen_ipv4_nat_checksum(~old_ports, new_ports, udp->dgram_cksum);
}

int dnat(sk_buff_t *skb, void *arg) {
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    uint32_t old_dst_ip = iph->dst_addr;

    struct dnat_rewrite_data *data = (struct dnat_rewrite_data*)(arg);
    iph->dst_addr = data->dst_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (iph->next_proto_id == IPPROTO_TCP) {
        rewrite_tcp_dst_port((struct rte_tcp_hdr*)&iph[1], data->port, old_dst_ip, iph->dst_addr);
    } else if (iph->next_proto_id == IPPROTO_UDP) {
        rewrite_udp_dst_port((struct rte_udp_hdr*)&iph[1], data->port, old_dst_ip, iph->dst_addr);
    }

    return NAT_LB_OK;
}

static void rewrite_tcp_src_port(struct rte_tcp_hdr *tcp, uint16_t new_port, uint32_t old_src_ip, uint32_t new_src_ip) {
    uint32_t old_ports = (tcp->src_port << 16) | tcp->dst_port;
    tcp->src_port = new_port;
    uint32_t new_ports = (tcp->src_port << 16) | tcp->dst_port;
    tcp->cksum = gen_ipv4_nat_checksum(~old_src_ip, new_src_ip, tcp->cksum);
    tcp->cksum = gen_ipv4_nat_checksum(~old_ports, new_ports, tcp->cksum);
}

static void rewrite_udp_src_port(struct rte_udp_hdr *udp, uint16_t new_port, uint32_t old_src_ip, uint32_t new_src_ip) {
    uint32_t old_ports = (udp->src_port << 16) | udp->dst_port;
    udp->src_port = new_port;
    uint32_t new_ports = (udp->src_port << 16) | udp->dst_port;
    udp->dgram_cksum = gen_ipv4_nat_checksum(~old_src_ip, new_src_ip, udp->dgram_cksum);
    udp->dgram_cksum = gen_ipv4_nat_checksum(~old_ports, new_ports, udp->dgram_cksum);
}

int snat(sk_buff_t *skb, void *arg) {
    struct rte_ipv4_hdr *iph = rte_pktmbuf_mtod((struct rte_mbuf*)skb, struct rte_ipv4_hdr*);
    uint32_t old_sip = iph->src_addr;

    struct snat_rewrite_data *data = (struct snat_rewrite_data*)(arg);
    iph->src_addr = data->src_ip;
    iph->hdr_checksum = 0;
    iph->hdr_checksum = rte_ipv4_cksum(iph);

    if (IPPROTO_TCP == iph->next_proto_id) {
        rewrite_tcp_src_port((struct rte_tcp_hdr*)&iph[1], data->port, old_sip, iph->src_addr);
    } else if (IPPROTO_UDP == iph->next_proto_id) {
        rewrite_udp_src_port((struct rte_udp_hdr*)&iph[1], data->port, old_sip, iph->src_addr);
    }

    return NAT_LB_OK;
}

struct rewrite dnat_rewrite = {
        .rewrite_type = DNAT_REWRITE,
        .ext_type = CT_EXT_DNAT,
        .func = dnat
};

struct rewrite snat_rewrite = {
        .rewrite_type = SNAT_REWRITE,
        .ext_type = CT_EXT_SNAT,
        .func = snat
};