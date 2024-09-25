#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_pdump.h>
#include <rte_malloc.h>
#include "common.h"
#include "dev.h"
#include "lcore.h"
#include "scheduler.h"
#include "route.h"
#include "l2.h"
#include "ipv4_in.h"
#include "neigh.h"
#include "icmp.h"
#include "acl.h"
#include "arp.h"
#include "ct.h"

struct acl_ipv4_rule;

static void configure_lcore(void) {
    struct lcore_queue_conf rx_queue_conf, tx_queue_conf;
    struct lcore_port_conf port_conf, port_conf2;
    struct lcore_conf lcore_conf;

    rx_queue_conf.queue_id = 0;
    rx_queue_conf.len = 0;

    tx_queue_conf.queue_id = 0;
    tx_queue_conf.len = 0;

    port_conf.port_id = 0;
    port_conf.rxq_n = 1;
    port_conf.txq_n = 1;
    port_conf.rxq[0] = rx_queue_conf;
    port_conf.txq[0] = tx_queue_conf;

    port_conf2.port_id = 1;
    port_conf2.rxq_n = 0;
    port_conf2.txq_n = 0;
    port_conf2.rxq[0] = rx_queue_conf;
    port_conf2.txq[0] = tx_queue_conf;

    lcore_conf.lcore_id = 1;
    lcore_conf.type = LCORE_TYPE_FWD_WORKER;
    lcore_conf.ports_n = 2;
    lcore_conf.ports[0] = port_conf;
    lcore_conf.ports[1] = port_conf2;

    add_lcore_configure(lcore_conf);
}

static void configure_port(void) {
    struct port_conf *port_conf;

    port_conf = rte_zmalloc("dev_port conf", sizeof (struct port_conf), RTE_CACHE_LINE_SIZE);
    if (NULL == port_conf) {
        rte_exit(EXIT_FAILURE, "No memory, %s.", __func__ );
    }

    char local_ip[] = "172.16.0.2";
    port_conf->port_id = 0;
    port_conf->rxq_n = 1;
    port_conf->rx_desc_n = 1024;
    port_conf->txq_n = 1;
    port_conf->tx_desc_n = 1024;
    port_conf->mtu = 1500;
    port_conf->local_ip = ip_to_int(local_ip);
    add_port_configure(port_conf);

    char local_ip2[] = "172.16.0.15";
    port_conf = rte_zmalloc("dev_port conf", sizeof (struct port_conf), RTE_CACHE_LINE_SIZE);
    if (NULL == port_conf) {
        rte_exit(EXIT_FAILURE, "No memory, %s.", __func__ );
    }
    port_conf->port_id = 1;
    port_conf->rxq_n = 1;
    port_conf->rx_desc_n = 1024;
    port_conf->txq_n = 1;
    port_conf->tx_desc_n = 1024;
    port_conf->mtu = 1500;
    port_conf->local_ip = ip_to_int(local_ip2);
    add_port_configure(port_conf);
}

static void configure_route(void) {
    char dst_addr[] = "172.16.0.0";
    struct dev_port *port;
    int ret;

    port = get_port_by_id(0);
    ret = route_add(ip_to_int(dst_addr), 16, 1500, 0, 0, port, 0, RTF_LOCAL);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add route failed, %s.", rte_strerror(rte_errno));
    }

    char dst_addr2[] = "169.254.0.0";
    ret = route_add(ip_to_int(dst_addr2), 16, 1500, 0, 0, port, 0, RTF_LOCAL);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add route failed, %s.", rte_strerror(rte_errno));
    }
}

static void configure_neighbor(void) {
    int ret;
    char next_hop[] = "172.16.0.2";
    struct rte_ether_addr mac = {{0x20, 0x90, 0x6f, 0x24, 0x29, 0x0f}};

    ret = neighbor_add(ip_to_int(next_hop), &mac);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add neighbor failed.");
    }

    char next_hop2[] = "172.16.0.15";
    struct rte_ether_addr mac2 = {{0x20, 0x90, 0x6f, 0x4e, 0xe8, 0xd6}};
    ret = neighbor_add(ip_to_int(next_hop2), &mac2);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add neighbor failed.");
    }

    char next_hop3[] = "169.254.128.7";
    struct rte_ether_addr mac3 = {{0xfe, 0xee, 0x80, 0x9f, 0x32, 0x47}};
    ret - neighbor_add(ip_to_int(next_hop3), &mac3);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add neighbor failed.");
    }

    char next_hop4[] = "169.254.128.15";
    ret = neighbor_add(ip_to_int(next_hop4), &mac3);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add neighbor failed.");
    }

    char next_hop5[] = "172.16.0.17";
    ret = neighbor_add(ip_to_int(next_hop5), &mac3);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add neighbor failed.");
    }
}

static void configure_acl(void) {
    struct acl_ipv4_rule rule;
    int ret;

    char ip_src[] = "169.254.0.0";
    rule.data.userdata = ACL_DROP;
    rule.data.category_mask = 1;
    rule.data.priority = 1;
    rule.field[0].value.u8 = IPPROTO_ICMP;
    rule.field[0].mask_range.u8 = 0xff;
    rule.field[1].value.u32 = ip_to_int(ip_src);
    rule.field[1].mask_range.u32 = 16;

    ret = ingress_acl_rule_add(rule);
    if (NAT_LB_OK != ret) {
        rte_exit(EXIT_FAILURE, "Add ingress acl rule failed, %s.", rte_strerror(rte_errno));
    }
}

static void show_stats(void) {
    int ret;
    struct rte_eth_stats stats;

    ret = rte_eth_stats_get(0, &stats);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Eth stats failed, %s.", rte_strerror(rte_errno));
    }
    fprintf(stdout, "Port 0, in_pkt=%lu,out_pkt=%lu,in_error=%lu,out_error=%lu.\n",
            stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors);

    ret = rte_eth_stats_get(1, &stats);
    fprintf(stdout, "Port 1, in_pkt=%lu,out_pkt=%lu,in_error=%lu,out_error=%lu.\n",
            stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Eth stats failed, %s.", rte_strerror(rte_errno));
    }
}

int main(int argc, char *argv[]) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Init eal failed, %s.", rte_strerror(rte_errno));
    }

    ret = rte_pdump_init();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Init pcap failed, %s.", rte_strerror(rte_errno));
    }

    configure_port();
    configure_lcore();

    scheduler_init();
    lcore_init();
    port_init();
    route_init((int)rte_socket_id());
    configure_route();
    l2_init();
    neigh_init();
    // configure_neighbor();
    icmp_init();
    ipv4_in_init();
    acl_init();
    configure_acl();
    arp_init();
    ct_init();
    port_start_all();

    lcore_start(false);

    while (1) {
        rte_delay_us_sleep(10000000);
        show_stats();
    }

    return NAT_LB_OK;

    /* char src_ip[] = "10.0.0.4";
    char dst_ip[] = "172.16.0.2";
    struct route_entry rt_entry = {
            .dst_addr = ip_to_int(dst_ip)
    };
    struct ct_tuple_hash original = {
            .tuple = {
                    .ports.src_port = 56678,
                    .ports.dst_port = 8080,
                    .src_addr = ip_to_int(src_ip),
                    .dst_addr = ip_to_int(dst_ip),
            }
    };
    struct ct_tuple_hash reply = {
            .tuple = {
                    .ports.src_port = 8080,
                    .ports.dst_port = 56678,
                    .src_addr = ip_to_int(dst_ip),
                    .dst_addr = ip_to_int(src_ip),
            }
    };
    struct ct_session ct = {
        .tuple_hash= {
                original,
                reply
        },
        .rt_entry = &rt_entry
    };

    struct list_head ct_table;
    INIT_LIST_HEAD(&ct_table);
    list_add(&ct.tuple_hash[CT_DRI_ORIGINAL].tuple_node, &ct_table);

    struct ct_tuple_hash *curr;
    list_for_each_entry(curr, &ct_table, tuple_node) {
        // struct ct_session *get_ct = container_of(curr, struct ct_session, flows[CT_DRI_ORIGINAL]);
        struct ct_session *get_ct = TUPLE_TO_CT(curr);
        fprintf(stdout, "rt dst_ip=%d\n", get_ct->rt_entry->dst_addr);
    } */
}
