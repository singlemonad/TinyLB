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

// 四个方面
// 一、协议
//  1. TCP状态转换关系、连接复用场景
//  2. MTU、MSS
//  3. ICMP差错控制对连接状态的影响
// 二、性能
//  1. 网卡与PMD驱动优化
//   1）利用网卡的硬件能力卸载一部分计算，比如RSS、CheckSum offload
//   2）调整接受队列和发送队列的大小应对微突发
//   3）调整PMD驱动与硬件交互的批量大小
//   4）...
//  2. 访存优化
//   1）线程本地存储
//   2）cache line对齐
//   3）cache预取
//   4）避免跨numa节点访存
//   5）...
//  3. 无锁编程
//  4. 批量
//  5. 控制面接口性能
//   1）读写分离
//   2）...
// 三、高可用
//  1. 普通网络拓扑
//                                                      route                                                               rs
//                                                                      route       lb
//  client  ->  switch   ->   client default gw   ->    route    ->                         switch    lb default gw         rs
//                                                                      route       lb
//                                                      route                                                               rs
//  2. ip配置
//   1）vip配置在lb lo网卡上，可以响应对vip的arp请求
//   2）client、vip、rs可能位于同一子网也可能位于不同子网
//   3）用于做snat的ip配置在lb lo网卡上
//  3. NAT模式-通信流程
//   1）client、vip、rs位于同一子网
//    a. client发起对vip的arp请求，lb响应该arp请求
//    b. client将目的mac设为lb对应网卡的mac，发送数据包到lb
//    c. lb选择rs，做dnat，发起对rsIp的arp请求
//    d. rs响应arp请求
//    e. lb收到arp响应后，将目的mac为rs的mac，发送数据包到rs
//    f. rs回包时，发起对client的arp请求
//    g. client响应vip的arp请求
//    h. rs将目的mac设为client的mac，发送数据包到client
//    i. client收到源ip为（rsIp，rsPort）的包，丢弃
//   2）client、vip位于同一子网，rs位于另一子网
//    a~b与1）相同
//    c. lb选择rs，做snat
//    d. lb将数据包送到默认网关
//    e. 默认网关及后续路由器通过路由将包送到rs
//    f. rs回包时由于目的ip（clientIp）与rs不在同一子网，送到默认网关
//    g. 默认网关及后续路由器将包送到client
//    h. client收到源ip为（rsIp，rsPort）的包，丢弃
//   综上，NAT模式下，有两个要求
//    1. client与rs不能位于同一子网
//    2. rs的默认网关必须是lb（如果lb可以作为rs的默认网关，那么lb与rs必须在同一子网）
//  4. FULL NAT模式-通信流程
//   1）client、vip、rs位于同一子网
//    a. client发起对vip的arp请求，lb响应该arp请求
//    b. client将目的mac设为lb对应网卡的mac，发送数据包到lb
//    c. lb选择rs，做dnat，lb选择本地ip，做snat
//    d. lb发起对rsIp的arp请求
//    e. rs响应arp请求
//    f. lb将目的mac设为rs的mac，发送数据包到rs
//    g. rs回包时发起对snatIp的arp请求
//    h. lb响应对snatIp的arp请求
//    i. rs将目的mac设为snatIp的mac，发送数据包到lb
//    j. lb做snat、dnat后发起对clientIp的arp请求
//    k. client响应arp
//    l. lb将目的mac设为client的mac，发送数据包到client
//    m. client收到包，完成一次通信
//   2）client、vip、rs分别位于不同子网
//    只要clientIp、vip、snatIp、rsIp都是路由可达的，就可以完成通信
//  2. 大二层网络拓扑
//  从宿主机发起的访问
//      client -> host -> switch -> default gw -> route -> route -> lb -> switch -> default gw -> rs
//  从外网发起的访问
//      client -> tgw ->
//  从IDC发起的访问
//
//   1）和普通网络拓扑的差异
//    a. 大二层下，是两层路由模式，内层路由是由SDN控制器下发的，用于外层封装的源目地址
//    b. 外层封装的源目地址，如果源/目地址指向网关，该地址也是虚拟ip，可以在不同的物理设备间漂移（通过bgp路由宣告完成）
//   2）ip配置
//    a. 网关虚拟ip配置在网关设备的网卡上
//    b. 如果需要做snat，snat地址需要可路由？
//   3）内网访问通信流程
//    a.
//  3. 故障模型
//   1）rs上线，需要保证
//    a. 其他rs的存量连接不受影响
//    b. 新建立的连接可以被均衡到上线的rs上
//   2）rs下线，需要保证
//    a. 其他rs的存量连接不受影响
//    b. client侧可以收到通知后关闭连接
//    c. 新建立的连接不会在选中下线的rs
//   3）网关虚拟ip所在的设备故障，需要保证
//    a. 存量连接不受影响
//    b. 新建连接不受影响
//   4）集群中网关设备上线，需要保证
//    a.
//   5）集群中网关设备下线，需要保证
//   6）跨az容灾
// 四、分片
// 五、限速
// 六、会话同步
// 七、故障检测、Trace

// 分布式限速
/*
 * 分布式限速
 * */

// 同进同出
/*
 * 同进同出
一、为什么要保证同进同出？
1. tcp状态机扭转会影响连接数统计 -- 非致命，可以容忍
2. 没有做snat的场景下，可以根据rsIp+rsPort反查svc信息，完成reply方向的snat -- 非致命，可以绕过
3. 在做了snat的场景下，reply方向需要做dnat，这个依赖origin方向做snat时维护的（clientIp,clientPort）->（snatIP,snatPort）
映射 -- 致命，不可绕过
4. 还有其他致命场景么？
二、同进同出的两个维度
1. 设备维度
同一个连接，origin方向和reply方向的流量需要走到同一台设备
2. worker维度
dpdk一般都是多核的，同一个连接，origin方向和reply方向的流量需要走到同一个worker
三、如何实现同进同出？
1. 设备维度
1）ECMP路由场景下，依赖上游交换机，origin和reply方向，外层源ip不一样，外层目的ip一样，交换机可以根据外层ip来哈希选择物理设备
2）如果设备上的虚拟ip只有唯一路由，天然就能保证
2. worker维度
worker维度需要在五元组粒度实现同进同出，一般有两种思路
1）选择origin和reply方向都保持不变的报文头部字段做哈希
2）将reply方向的报文头部字段与worker关联（snat场景）
3）全局redirect表
具体做法有：
1）需要做snat的场景，可以通过snatIp、snatPort的特征将reply方向的流量转发到对应的worker
2）没有做snat的场景，可以根据（vip,vport,proto）哈希来选择worker
3）
*/

// 会话同步
/**
 * 会话同步
一、需求点
1. 支持集群内上线设备时同步全量会话
2. 支持增量同步
3. 支持会话对账

二、vpcgw会话同步模块分析
1. 线程模型
2. 同步策略
3. 同步协议
1）
2）支持3中扩展结构，ct_sync_meta_t、ct_sync_tgw_t、ct_sync_v6ip_t
a. ct_sync_meta_t包含连接origin和reply方向的v4 5元组信息、连接状态、gre_csum等信息
b. ct_sync_tgw_t包含连接与tgw通信时tsvip等信息
c. ct_sync_v6ip_t包含连接origin和reply方向的v5 5元组信息
4. 流程
1）初始化
a. ct_sync_init初始化会话同步模块
 1. 注册支持的扩展结构
 2. 调用register_sync_svc注册sync处理相关的函数指针
 */

// 容灾
/**
 * VPCGW容灾（集群模式）
一、网络架构模型
1. vpcgw对外提供的访问端点为vpcgw vip，一个vpcgw vip对应到多台vpcgw设备，多台vpcgw设备对外发布vpcgw vip的ECMP路由
由上游交换机哈希选择不同的vpcgw设备
2. 多个vpcgw会组成一个大集群，母机在选择路由时，是在多个vpcgw vip中选择一个，这里有一个隐藏的问题，如果一个vip对应一个集群，
那多个集群间的会话状态是不一致的，这会影响到容灾后的流量
二、网口容灾
三、集群内容灾
1. 通过撤销故障设备的路由宣告可以完成origin和reply方向的流量切换
2. 通过集群内会话同步可以保证存量会话完整性
3. 需要做snat的场景
1）private link场景，需要将内层源ip替换为服务vpc所在的snat网段内的地址，rs侧需要配置路由，将snat网段下一跳指向vpcgw
这里有两个问题
1）client端发起访问时所用的vpcgw vip和rs回包时路由选择的vpcgw vip，不一定是同一个
2）即使是同一个vpcgw vip（通过母机侧自学习可以实现），
通过交换机哈希后，回包可能会发到不同的物理设备，这个时候没有origin方向的会话，怎么处理？
四、集群间容灾
集群间容灾是指，某个vpcgw vip对应的多台vpcgw设备都异常了，需要将vpcgw vip从母机的rtable中删除，删除后，
1. 新增流量不会在走到故障集群
2. 存量流量如果是stick会话，还会走到故障集群；如果不是stick会话，发到新的集群，vpcgw会回rst？
3. 支持集群间的会话同步吗？
*/

/*
 * NATGW容灾（主备模式）
一、网络架构模型
1. natgw对外提供的访问端点为natgw vip

二、网口容灾

三、主备容灾
1. 主备对外宣告不同优先级的路由，正常情况下，访问natgw vip的流量走到主，主异常后撤销路由宣告，访问natgw vip的流量走到备
 * */

/*
 * TGW容灾（集群模式）
一、网口容灾--应对单网口故障

二、集群内容灾--应对单台设备故障
1. origin方向流量需要被发送到集群内其他设备
1）访问eip的外网流量，在转发到tgw前是普通ip包，依赖交换机ECMP路由选择算法
2）访问内网vip的流量，是在母机或其它网关设备上查找控制面路由后确定的，下一跳为tsvip
2. reply方向流量需要被发送到集群内其他设备
1）reply方向是在母机或其它网关设备上查找控制面路由或自学习确定的，下一跳为tsvip
3. 其他设备可以处理故障设备的流量
1）新建流量依赖配置完整性
2）存量流量依赖会话完整性

三、跨AZ容灾--应对单AZ故障
1. tgw集群支持部署在不同的az，比如8台一个集群，4台位于az1、4台位于az2
2. origin方向引流，要求同一条流正常情况下始终转发到同一台设备，一般有如下策略
1）采用大小网段路由，比如对于9.0.0.0/24段，az1为主，宣告16个/28的路由；az2为备宣告/24的路由
大小网段路由的问题是控制面需要做路由拆分，有一定的管理复杂度
2）利用路由协议的其他优先级字段
3）宣告ECMP路由，tgw要求同一条流始终转发到同一台设备，这对上游交换机是有要求的，在跨az情况下，az级的交换机不一定能满足要求
3. reply方向引流，tgw要求同进同出，由于origin和reply方向流量有如下差异
1）外网origin方向为ip包，外层目的ip为eip，是从xgww过来的
2）reply方向为gre包，gre外层目的ip为tsvip，是从xgwl过来的
由于这些差异，reply方向母机或其它网关需要支持每包自学习才有可能支持同进同出
在母机或其它网关支持自学习的情况下，如何宣告tsvip的路由呢？有以下方式
1）多台设备共用同一个tsvip，宣告ECMP路由 -- 交换机不支持按内层头哈希
2）设备用本地tsvip，本地tsvip是其它设备的bak tsvip，本地tsvip所在的设备宣告高优先级路由，bak tsvip所在设备宣告低优先级路由

引流就是将访问设备上的虚拟IP的流量引导到物理设备上，简单来说就是对外宣告一条如下格式的路由，
访问 目的IP（设备上的虚拟IP）的流量的下一跳为 设备物理IP，在宣告路由时，需要考虑如下问题
1）路由器的表项是有限制的，宣告太细粒度的路由打爆路由器
2）路由的宣告和撤销有收敛时间，在收敛时间内，流量的转发可能异常
3）路由至少有目的IP、下一跳两个属性，需要考虑路由管理、冲突等其他问题
宣告路由时，支持如下方式
1）多台设备对相同的虚拟IP段宣告ECMP路由，由交换机根据报文信息选择实际转发到的物理设备，交换机一般有如下特性
a. 根据外层二元组哈希选择
b. 一般不能识别报文内层特征
2）多台设备对相同的虚拟IP端，宣告优先级不同的路由（路由协议支持多种不同的优先级策略）
3）交换机查找路由时支持最长前缀匹配，不同的设备可以宣告同一网段不同大小的路由来实现选路（比如某些设备宣告/24的路由，其他设备宣告将/24拆分为16个/28段的路由）
   这种方式是2）中的一种特例。
 * */

/*
 * CT状态机
 *
一、TCP状态机
TCP尝试在有延迟、不可靠、容量有限的网络上构建可靠传输，
为了构建可靠传输，TCP通过序号、确认号、重传等机制来完成，这就需要在两端维护状态
TCP需要保证在任何网络情况下，维护的状态可以正确的流转和回收
通信两端会维护TCP的状态，TCP状态会根据包流转，在不同的状态对包的响应不同
采取状态机的做法是为了保证TCP的正确性和可靠性（应对各种可能的异常场景），分为如下几点
 1. 可以应对同时建立连接的情况
 2. 不会串流。TCP用<srcIp,srcPort,dstIp,dstPort>四元组标识通信双方，一个TCP连接还有与之相关的
 序号、确认号、窗口等状态。串流是指收到相同四元组的包，但实际上该数据包不属于当前TCP连接。串流的原因是
  1）四元组被复用后，前序连接的报文由于网络延迟或重传被传递到当前连接
 3. 可以在存在丢包和延迟的网络中，正确关闭连接
  1）通过rst直接关闭连接
  2）可以应对最后的fin丢失
  3）在连接的任何状态，网络断开后，可以正确关闭连接
发送端只能预测接收端当前的状态，预测的状态和实际的状态可能不一致，TCP需要两端处理不一致的情况，
举个例子，如果客户端发出syn包，那么预期服务端应该处于listen状态，但实际服务端可能处于任何状态
    行为          客户端预期的服务端状态         服务端实际可能的状态
 客户端发出syn           listen                  listen
                                                未监听端口

二、LB对TCP状态机的修改
LB作为中间设备，无法知道通信两端的实际状态，只能根据已经见过的包来推测连接的状态
推测出连接的状态后，还需要结合rs当前的状态（rs的状态是近实时的）来流转CT的状态
可能引起CT流转的包类型有
 1. SYN
 2. FIN
 3. RST
除了握手的第一个SYN包可以不携带ACK，其他的包都需要携带ACK
LB为了流转CT的状态，根据包的标志将包分为以下类型
 1. SYN，握手的第一个包
 2. SYN+ACK，握手的第二个包
 3. RST，强制关闭连接包
 4. FIN，断连包
 5. ACK，普通包
 6. None，未携带任何标记，无效包
如何设计CT的状态？维护CT的状态有两个目的，
 1. 不同的状态有不同的超时时间，CT超时后，LB维护的连接信息会被删除，后续如果还有该连接的流量会丢包，
 在连接超时时，LB需要显式通知前后端（通过发包的方式），在不同的状态，通知的对象和内容都会有差异
 实际很难做到？因为需要维护双向序号、确认号
 2. 不同的状态，对带有不同标志的包，处理行为不一样 -- 为什么不能直接透传到后端呢？--实际也是透传到后端
 * */

/*
VPCGW实现分析
一、连接管理模块
1. 什么场景下需要重建会话？
1）SYN包且连接状态大于等于ES状态
2. TCP非SYN包找不到会话怎么处理？有三种策略
1）丢包
2）发送RST
3）转发到集群内其他设备（通过组播实现？需要确认实现机制）
3. 如何实现自学习？
1）报文解析模块会将从报文外层头部提取的内容存放在SKB对应的EXT中
2）CT模块从EXT中提取内容，更新到CT中对应的成员
4. 如果首包被ACL/安全组拒绝后，CT处于什么状态？如何处理后续包？
1）如果首包被ACL/安全组拒绝后，CT处于CT_S_NEW状态
2）后续包如果是TCP非SYN包，丢弃；如果是其他包，继续走后续逻辑（和命中CT的情况一致）
5. RS下线、RS不健康、RS权重变为0如何影响存量CT？
1）应该对与RS有关的CT，都发送RST，如果需要这样做，依赖
a. 可以根据RS VIP+VPORT快速找到相关的CT
b. 如果是TCP连接，需要记录确认号与序号
c. 如果是UDP连接，UDP是无连接的，缺乏断链手段--可以通过ICMP来通知客户端？
维护上述信息过于复杂，可以通过删除相关CT+惰性反馈的方式来解决
a. RS下线、不健康、权重变为0时，删除相关CT或将相关CT标记
b. 下次收到ORIGIN的包时，查CT失败，重建CT或响应RST（TCP非SYN包）
二、LB模块
1. LB模块的功能
1）SVC粒度的ACL/安全组
2）RS调度，即选择RS
3）SVC管理，即SVC增删改查
4）RS管理，即RS增删改查
2. SVC类型，SVC类型决定了VPCGW是否需要做SNAT、与上下游网元交互的报文格式及其它一些特性，
SVC分为如下几种
1）V2V（0），CLIENT与RS都位于云上，即VPC内LB，不需要做SNAT
2）V2R（1），CLIENT位于云上，RS位于支撑环境，需要做SNAT，选择支撑IP做SNAT？
3）R2V（2），CLIENT位于支撑环境，RS位于云上
4）V2V_SNAT（3），PRIVATE LINK？
3. RS类型
1）LOCAL_VPC（0），RS位于云上，并且与VIP位于同于RS
2）UNDERLAY（1），RS位于支撑环境
3）PL_VPC（2），RS在另一个VPC，与VIP所在的VPC不同
4. PRIVATE LINK类型
1）VPC2VPC（0），普通VPC TO VPC PRIVATE LINK，选择服务VPC内预留的SNAT网段
2）V2IDC（1），服务VIP与RS位于支撑环境或IDC，SNAT时选择SVC粒度的SNAT地址 
4. STICKY SVC RS选择算法
1）只支持根据源IP做STICKY
2）STICKY会话保存在PER WORKER的STICKY会话表中，同时也会保存在全局表中
3）查找时，先查找PER WORKER的STICKY会话表，未查找则继续在全局STICKY会话表中查找，查找全局表会加锁
4）如果在全局表中查到，会将其复制到本地会话表
5）创建的时候，会同时插入全局表和本地表
5. REPLY方向检查
1）LB选择RS后，对于不做SNAT的场景，会检查REPLY方向连接是否能建立，如果不能，向源端发送RST
6. SNAT地址管理
1. 为什么需要做SNAT？
如果后端RS不支持自学习保证源进源出，或者RS与CLIENT位于异构网络，异构网络分如下场景，
1）PRIVATE LINK场景，CLIENT与RS位于不同VPC
2）V2R场景，RS位于支撑网络
3）R2V场景（原JNSGW场景），CLIENT位于支撑网络，RS位于云上VPC
4）RS位于IDC场景，下游网关为专线
VPCGW需要对发往RS的包做SNAT，保证RS的回包可以走到VPCGW（依赖在RS侧配置路由，将SNAT地址段的路由指向VPCGW）
针对上述场景，SNAT所用的地址段也不一样，
1）PRIVATE LINK场景，需要在RS所在的VPC预留网段做SNAT，还需要配置路由将SNAT段指向VPCGW吗？取决于后端是否支持自学习？
2）V2R场景，RS位于支撑网络，依赖于后端的能力，如果后端不支持自学习，需要做集群粒度的SNAT
3）R2V场景，用固定网段做SNAT？
4）RS位于IDC场景需要SVC粒度的SNAT IP，因为PVGW无状态且不支持网段路由
2. SNAT地址管理
1）在创建RS时，如果RS需要做SNAT，会初始化RS中用于做SNAT的IP列表，并且吧RS对应的SNAT结构插入每CPU的表中
2）每个WORKER对应的PROT范围不重叠，分配PROT时，从WORKER本地端口范围中分配
3）分配SNAT、PORT时，从上次分配的位置往下开始找，如果没有被使用（CT查找为空），则分配；否则递增PORT，最多循环100次
这种分配算法，如何应对PORT回收的情况呢？--现在没有回收，通过检查是否有CT来确认PORT是否可用
7. 级联场景
8. TOA
9. 调度算法
1）WRR，加权随机
2）WLC，最小连接数
3）SIP，源IP哈希
10. SVC删除、RS
1）删除SVC、RS时，会将对象标记为已删除，什么时候实际删除呢？
通过引用计数的方式，SVC会被RS引用，RS会被会话引用，当会话删除时，会递减RS的引用计数，
如果引用计数为0，会释放RS，SVC同理
2）删除SVC、RS时，不会处理相关的连接，而是采取惰性处理的方式，
当下次有包命中会话时，如果SVC或RS已删除，对于非TCP会话，直接删除会话；
对于TCP会话，如果没有开启RST模式，直接删除会话；如果开启了RST模式，对双向发送RST，
并且将会话状态设置为CLOSE，等待会话超时后删除
三、ACL、安全组模块
四、路由模块
五、控制面接口优化
1. 批量
2. 读写分离
3. 共享内存
六、分流，即如何在WORKER间划分流量
1. 目标，在WORKER间划分流量需要达到如下目标
1）同一条流，正反向需要划分到同一个WORKER
2）不同流在WORKER间需要尽量均衡
2. 方式，在WORKER间划分流量是计算密集的，有两种方式
1）利用网卡的硬件分流能力（rte_flow）。利用硬件划分可以提高性能，但是可能有如下问题
a. 硬件的容量和划分方式不一定能满足需求，特别是对于reply方向的流量，如果需要根据端口或其它特征划分，容量可能不够
b. 如果需要在WORKER数量异构的设备间同步会话，可能需要感知硬件分流的具体算法（算法和网卡相关，是易变的）
2）采用PIPELINE模式，软件分流，软件分流会降低性能
3. 流量分类
4. 划分方式
*/

/*
软硬件协同设计-以VPCGW为例

*/

/*
P4
一、核心功能及其实现
1. mirror
1）转发流程中对mirror的处理
a. tm中会已mirror id为索引维护一张mirror表
b. 对于转发到tm的包，在ingress/egress中可以设置mirror id
c. tm对设置了mirror id的包，tm根据mirror id查找mirror表来决定转发目的，转发目的可以是port、cpu
d. pre(packet replication engine)负责复制和转发包
2. tm的packet tx_buffer
1）组织形式
a. tm的packet buffer被分为几个pool，如果一个pool满了，发往该pool的packet会被丢弃
2）如何控制packet所属的buffer
a. 可以通过ingress_cos字段来指定packet所属的buffer
b. deflect_on_drop字段可以指定当pool满了时的备选pool
3. packet replication engine
1）pre如何复制packet？
a. pre会创建一个描述符，描述符的内容指向在packet buffer中的包
2）组播配置的组织形式
a. 第一级代表一组需要负责的目的网络
b. 第二级代表一组端口或lag
c. 如果是目的为ecmp或lag，通过哈希选择其中的一个目的
4. queue admission control
1）分类方式
a. tm将包方入队列时有流控机制，流控是根据包的优先级有队列当前的状态决定的
b. 包有3个优先级，最高为green、yellow次之、red最低，可以通过packet_color指定包的优先级
c. 队列有3个长度阈值，分别为green、yellow、red，green最高、yellow次之、red最低
2）分类算法
a. 如果队列当前长度小于red，全部放行
b. 如果队列当前长度大于red小于yellow，放行yellow和green包，丢弃red包
c. 如果队列当前长度大于yellow小于green，放行green包，丢弃red、yellow包
d. 如果队列当前长度大于green，全部丢弃
3）控制面感知拥塞状态
a. 可以通过enq_congest_stat和deq_congest_stat获取队列拥塞状态
4）队列配置
a. 100G端口有32个队列
5）包调度器
a. 包调度器决定了什么时候出队哪个包
b. 支持多种不同的调度算法从队列中出包，比如优先级调度、带权重的优先级调度...

二、疑问
1. pipeline折叠后，如何指定从egress出去的包应该走到哪个ingress port？
可能是默认行为，配置为loop back模式的port，会将包重新送到对应的ingress

三、GWLB相关问题分析
1. 抓包实现
1）抓包点在哪里？
a. PIPELINE_A INGRESS
b. PIPELINE_A EGRESS
2）抓包的匹配条件
a. 外层3层协议号、4层协议号、4层源目地址、内存3层协议号、4层协议号、4层源目地址
3）抓取的包的目的地
a. 通过指定MIRROR_ID上送到CPU

四、TOFINO扩展
1. Action Profile

*/

/*
eBPF
一、基础知识
1. 开发步骤
     1）使用C语言开发一个eBPF程序
     2）使用LLVM把eBPF程序编成BPF字节码
     3）通过bpf系统调用，把BPF字节码提交给内核
     4）内核验证并运行BPF字节码，并把相应的状态保存到BPF映射中
     5）用户通过BPF映射查询BPF字节码的运行状态

2. BCC
    1）BCC是BPF编译器集合，包含了用于构建BPF程序的编成框架和库，并提供了大量可以直接使用的工具
    2）使用BCC，可以通过Python与eBPF的各种事件和数据进行交互
    3）BCC使用起来，不太好构建远程编译环境，优先使用Linux原生系统调用来实现加载和MAP

3. eBPF程序分类
    1）分类查询方式
        a. linux/bpf.h头文件中enum bpf_prog_type定义了支持的所有eBPF程序类型
        b. 可以通过命令bpftool feature probe | grep program_type查看
    2）跟踪类eBPF程序
        a. 跟踪类eBPF程序用于从系统中提取信息
        b. 跟踪类eBPF程序大致分为如下几种
            KPROBE
            TRACEPOINT
            PERF_EVENT
            RAW_TRACEPOINT
            RAW_TRACEPOINT_WRITABLE
            TRACING
        c. 跟踪类eBPF程序函数原型如何确定？
    3）网络类eBPF程序
        a. 网络类eBPF程序用于对网络数据包进行过滤处理
        b. 网络类eBPF程序大致分为如下几种
            XDP
                模式：通用、原生、卸载
                函数原型：入参为xdp_buff
                返回值：XDP_DROP、XDP_PASS、XDP_TX、XDP_REDIRECT、XDB_ABORT
                挂载方式：ip link set dev $devName $mode(xdpgeneric、xdpdrv、xdpoffload) object $xdbObject.o
                卸载方式：iplink set $devName $mode(xdpgeneric、xdpdrv、xdpoffload) off
            TC
                子类型：BPF_PROG_TYPE_SCHED_CLS、BPF_PROG_TYPE_SCHED_ACT
                接收方向处理位置：网卡接收之后（GRO之后），协议栈处理之前
                发送方向处理位置：协议栈处理之后，发送到网卡队列之前
                函数原型：入参为sk_buff
                挂载方式：
                卸载方式：
            套接字程序
            cgroup程序
    4）其他类eBPF程序

4. eBPF程序辅助函数
    1）不同类型的eBPF程序可以调用的辅助函数是不一样的
    2）bpftool feature probe命令可以查看不同类型的eBPF程序可以调用的辅助函数
    3）辅助函数的原型在linux/bpf.h头文件中查看或者通过man bpf-helpers命令查看

5. bpf系统调用

6. bpf映射
    1）bpf映射用于提供大块的键值存储，可以被用户态程序访问
    2）一个bpf程序最多可以创建64个bpf映射
    3）bpf映射可以在多个用户态和内核态bpf程序间共享
    4）bpf映射只能由用户态程序创建
    5）bpf映射有类型，支持的类型可以通过linux/bpf.h头文件中的bpf_map_type查看或通过命令bpftool feature probe | grep map_type查看
    6）bpf映射在用户态程序退出（即关闭fd）时删除，如果需要常驻，需要通过BPF_OBJ_PIN将映射挂载到/sys/fs/bpf中
    7）bpftool map可以查看所有的映射，bpftool map dump name $map_name命令可以查看bpf映射的内容

7. bpf类型格式（BTF）
    1）不同的内核版本中内核数据结构的定义可能有差异
    2）bpf程序需要引入内核头文件来获取内核数据结构的定义
    3）内核编译时如果开启了CONFIG_DEBUG_INFO_BTF，会将内核数据结构的定义自动内嵌在内核二进制文件vmlinux中，可以通过命令
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h将内核数据结构的定义导入到vmlinux.h中，eBPF程序引用vmlinux.h即可
    4）eBPF CO-RE项目通过如下方式实现eBPF程序的可移植性
        a. 通过对BPF代码中的访问偏移量进行重写，解决了不同内核版本中数据结构偏移量不同的问题；
        b. 在libbpf中预定义不同内核版本中的数据结构的修改，解决了不同内核中数据结构不兼容的问题。

二、bpf映射

三、跟踪类eBPF程序
1. 内核函数与跟踪点查找
    1）/sys/kernel/debug/tracing目录下有所有支持跟踪的内核函数与跟踪点
2. 性能事件跟踪点查找
    1）perf list [hw|sw|cache|tracepoint|pmu|sdt|metric|metricgroup]
3. 利用bpftrace查找
    1）bpftrace -l查询内核插桩和跟踪点
    2）bpftrace -lv查询内核查找和跟踪点的入参与出参
4. 如何根据场景选择合适的内核插桩与跟踪点？
    1）优先选择跟踪点（tracepoint），跟踪点比较稳定
    2）需要对内核代码有一定的了解
5. 内核插桩与跟踪点函数原型确定
    1）入参
    2）出参
6. 利用bpftrace实现跟踪
7. 利用BCC实现跟踪
8. 利用libbpf实现跟踪

四、网络类eBPF程序

*/