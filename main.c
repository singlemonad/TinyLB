#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_pdump.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include "include/common.h"
#include "include/dev.h"
#include "include/lcore.h"
#include "include/scheduler.h"
#include "include/route.h"
#include "include/ipv4.h"
#include "include/neigh.h"
#include "include/icmp.h"
#include "include/acl.h"
#include "include/arp.h"
#include "include/ct.h"
#include "include/svc.h"
#include "include/sa_pool.h"
#include "include/lb.h"
#include "include/thread.h"

struct acl_ipv4_rule;

static struct rx_thread_cfg rx_thread_cfg1 = {
    .cfg = {
            .thread_id = 0,
    },
    .n_queue = 1,
};

static void configure_lcore(void) {
    rx_thread_cfg1.queues[0].port_id = 0;
    rx_thread_cfg1.queues[0].queue_id = 0;

    struct thread* rx_thread = create_rx_thread(&rx_thread_cfg1);
    lcore_add_thread(1, rx_thread);
}

static void configure_port(void) {
    struct port_conf *port_conf;

    port_conf = (struct port_conf*)rte_zmalloc("dev_port conf", sizeof (struct port_conf), RTE_CACHE_LINE_SIZE);
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
    dev_add_port_configure(port_conf);

    char local_ip2[] = "172.16.0.15";
    port_conf = (struct port_conf*)rte_zmalloc("dev_port conf", sizeof (struct port_conf), RTE_CACHE_LINE_SIZE);
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
    // dev_add_port_configure(port_conf);
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

    char dst_addr3[] = "192.168.0.0";
    ret = route_add(ip_to_int(dst_addr3), 16, 1500, 0, 0, port, 0, RTF_LOCAL);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Add route failed, %s.", rte_strerror(rte_errno));
    }

    char dst_addr4[] = "172.16.0.17";
    ret = route_add(ip_to_int(dst_addr4), 32, 1500, 0, 0, port, 0, RTF_FORWARD);
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

static void configure_svc(void) {
    svc_t *svc;

    char vip[] = "192.168.0.6";
    uint16_t vport = htons(8080);
    if (NAT_LB_OK != svc_add(rte_cpu_to_be_32(ip_to_int(vip)), vport)) {
        rte_exit(EXIT_FAILURE, "Add svc failed");
    }

    svc = svc_find(rte_cpu_to_be_32(ip_to_int(vip)), vport);
    if (NULL == svc) {
        rte_exit(EXIT_FAILURE, "No svc found.");
    }

    char rs_ip[] = "172.16.0.17";
    uint16_t rs_port = htons(80);
    if (NAT_LB_OK != rs_add(svc, rte_cpu_to_be_32(ip_to_int(rs_ip)), rs_port)) {
        rte_exit(EXIT_FAILURE, "Add rs failed");
    }

    // add sa pool for vip
    char snat_ip[] = "172.16.0.2";
    if (NAT_LB_OK != snat_addr_add(rte_cpu_to_be_32(ip_to_int(vip)), vport, rte_cpu_to_be_32(ip_to_int(snat_ip)))) {
        rte_exit(EXIT_FAILURE, "Add snat addr failed");
    }
}

static void show_stats(void) {
    int ret;
    struct rte_eth_stats stats;

    ret = rte_eth_stats_get(0, &stats);
    if (ret != NAT_LB_OK) {
        rte_exit(EXIT_FAILURE, "Eth stats failed, %s.", rte_strerror(rte_errno));
    }
    fprintf(stdout, "Port 0, in_pkt=%lu,out_pkt=%lu,in_error=%lu,out_error=%lu,imissed=%lu.\n",
            stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors, stats.imissed);

    // ret = rte_eth_stats_get(1, &stats);
    // fprintf(stdout, "Port 1, in_pkt=%lu,out_pkt=%lu,in_error=%lu,out_error=%lu.\n",
    //         stats.ipackets, stats.opackets, stats.ierrors, stats.oerrors);
    // if (ret != NAT_LB_OK) {
    //     rte_exit(EXIT_FAILURE, "Eth stats failed, %s.", rte_strerror(rte_errno));
    // }
}

int main(int argc, char *argv[]) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Init eal failed, %s.", rte_strerror(rte_errno));
    }

    rte_timer_subsystem_init();

    ret = rte_pdump_init();
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Init pcap failed, %s.", rte_strerror(rte_errno));
    }

    configure_port();
    configure_lcore();

    dev_port_init();
    route_module_init((int) rte_socket_id());
    configure_route();
    neigh_init();
    icmp_init();
    ipv4_init();
    acl_module_init();
    configure_acl();
    arp_init();
    svc_init();
    ct_module_init();
    lb_module_init();
    sa_pool_init();
    configure_svc();

    int port_amount = 1;
    for (int i = 0; i < port_amount; i++) {
        dev_port_start(i);
    }

    start_lcore(1);

    while (1) {
        rte_delay_us_sleep(10000000);
        show_stats();
    }

    return NAT_LB_OK;

}
