#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_pdump.h>
#include <rte_timer.h>
#include "src/common/lcore.h"
#include "src/common/util.h"
#include "src/neigh/neigh.h"
#include "src/acl/acl.h"
#include "src/lb/lb.h"
#include "src/ctrl/ctrl.h"
#include "src/sync/sync.h"
#include "src/ha/ha.h"
#include "src/inet/inet.h"
#include "src/inet/ipv4.h"
#include "src/common/ip_group.h"
#include "src/common/conf.h"

#define TIMER_RESOLUTION_CYCLES 20000000ULL

uint16_t avail_port_n;

static uint32_t business_ip;
static uint32_t management_ip;
static uint32_t ha_src_port;
static uint16_t sync_src_port;
static uint16_t sync_dst_port;

static void init_module(void) {
    parse_module_init();
    ip_group_module_init();
    dev_port_module_init(avail_port_n);
    inet_module_init();
    neigh_module_init();
    ct_module_init();
    lb_module_init();
    acl_module_init();
    route_module_init((int) rte_socket_id());
    ha_module_init(ha_src_port);
    sync_module_init();
    ctrl_module_init();
    lcore_module_init();
}

static char conf_path[] = "../conf.toml";

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

    rte_timer_subsystem_init();

    avail_port_n = rte_eth_dev_count_avail();
    if (avail_port_n <= 0) {
        rte_exit(EXIT_FAILURE, "No dpdk ports found.\n");
    }

    init_module();

    parse_conf(conf_path);

    dev_port_configure_port(avail_port_n);
    for (int i = 0; i < avail_port_n; i++) {
        dev_port_start(i);
    }

    ipv4_init_static_route();

    unsigned avail_lcore_n = rte_lcore_count();
    if (avail_lcore_n < 2) {
        rte_exit(EXIT_FAILURE, "avail lcore less than 2");
    }

    conf_lcores();
    start_lcores();

    return NAT_LB_OK;
}
