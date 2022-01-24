#include <signal.h>
#include <stdbool.h>
#include <getopt.h>

#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

#include "pon.h"

#define APP "volt"

#define ALLOCID_SIZE    3       // number of alloc_ids
#define DELTA   5
#define DBRU_SIZE   5
#define BWMAP_LEN  8
#define BWMAP_SIZE  (ALLOCID_SIZE*BWMAP_LEN+2)
#define TIMESTAMP_SIZE 20
#define ONU_ID 1
#define BUFLEN 512

const int DBRU_STATIC[] =  {15, 20, 90, 20, 30, 40, 50, 10, 25, 32, 90, 20, 30, 40};
const int BWMAP_STATIC[] = {97, 70, 88, 60, 10, 50, 55, 23, 16, 20, 10, 50, 55, 23}; 

uint16_t ETH_TYPE_DBRU = 0x1235;
uint16_t ETH_TYPE_BWMAP = 0x5678;
uint32_t VOLT_LOG_LEVEL = RTE_LOG_DEBUG;

/* the server side */
static struct rte_ether_addr onu_ether_addr = {{0x00, 0x04, 0x0a, 0x00, 0x00, 0x00}};
//static struct rte_ether_addr onu_ether_addr = {{0x0c, 0xc4, 0x7a, 0x9d, 0x78, 0xaa}};

/* the client side */
static struct rte_ether_addr olt_ether_addr = {{0x00, 0x00, 0x00, 0x1a, 0x00, 0x01}};
//static struct rte_ether_addr olt_ether_addr = {{0x00, 0x00, 0x0b, 0x00, 0x00, 0x0c}};

//static uint16_t cfg_udp_srv = 9930;
//static uint16_t cfg_udp_cli = 9960;

// Upstream
struct dbru_header
{
    // ethernet header comes first: 14 bytes = 112 bits
    uint16_t volt_pre_header;   // alignment data: 16 + 112 = 128 bits
    // begin vOLT dummy data
    uint64_t dummy_stuff1;
    uint64_t dummy_stuff2;

    uint64_t dummy_stuff3;
    uint64_t dummy_stuff4;

    uint64_t dummy_stuff5;
    uint64_t dummy_stuff6;

    uint64_t dummy_stuff7;
    uint64_t dummy_stuff8; 

    uint64_t dummy_stuff9;
    uint64_t dummy_stuff10; 

    uint64_t dummy_stuff11;
    uint64_t dummy_stuff12; 

    uint64_t dummy_stuff13;
    uint64_t dummy_stuff14;

    uint64_t dummy_stuff15;
    // end vOLT dummy data
    uint8_t  padding:2;
    uint16_t onu_id:10;
    uint8_t  counter:4;
    uint32_t buff_occ:24;
    uint32_t allign:24;     // align to 64 bits 
    // hardware timestamp
    uint32_t ts_counter;
    uint32_t ts_begin_low;
    uint32_t ts_begin_high;
    uint32_t ts_end_low;
    uint32_t ts_end_high;
} __attribute__((packed));


struct bwmap_header {
    uint16_t count;
    uint16_t alloc_id:14;       // ITU-T recommendations is 14 bits (10 bit ONU ID + 4 bits TCONT ID)
    char     dbru:1;           // ITU-T recommendations is 1 bit
    char     ploamu:1;         // ITU-T recommendations is 1 bit
    uint16_t start_time;     // ITU-T recommendations is 16 bits
    uint16_t grant_size;     // ITU-T recommendations is 16 bits
    uint16_t extra_padding;  // padding to bring up to 64 bits alignment (from pack_bwmap())
    uint32_t ts_counter;
    uint32_t ts_begin_low;
    uint32_t ts_begin_high;
    uint32_t ts_end_low;
    uint32_t ts_end_high;
} __attribute__((packed));

int xhash(unsigned int onu_id, unsigned int counter){
    return ((onu_id & 0x3FF) << 4) | (counter & 0x0F);
}


#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 128
// #define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define PKT_MBUF_DATA_SIZE (RTE_ETHER_MAX_JUMBO_FRAME_LEN + RTE_PKTMBUF_HEADROOM)
#define MAX_JUMBO_PKT_LEN  9216

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

int RTE_LOGTYPE_VOLT;

struct rte_mempool *volt_pktmbuf_pool = NULL;

static volatile bool force_quit;

/* enabled port */
static uint16_t portid = 0;
/* number of packets */
static uint64_t nb_pkts = 1000;
/* server mode */
static bool server_mode = true;

uint16_t global_count = 0;


static struct rte_eth_dev_tx_buffer *tx_buffer;

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .max_rx_pkt_len = MAX_JUMBO_PKT_LEN,
        .split_hdr_size = 0,
        .offloads = DEV_RX_OFFLOAD_JUMBO_FRAME,
    },
    .txmode = {
        .mq_mode = ETH_MQ_TX_NONE,
        .offloads = DEV_TX_OFFLOAD_MULTI_SEGS,
    },
};

/* Per-port statistics struct */
struct volt_port_statistics
{
    uint64_t tx;
    uint64_t rx;
    uint64_t *rtt;
    uint64_t dropped;
} __rte_cache_aligned;
struct volt_port_statistics port_statistics;

static inline void
initlize_port_statistics(void)
{
    port_statistics.tx = 0;
    port_statistics.rx = 0;
    port_statistics.rtt = malloc(sizeof(uint64_t) * nb_pkts);
    port_statistics.dropped = 0;
}

static inline void
destroy_port_statistics(void)
{
    free(port_statistics.rtt);
}

static inline void
print_port_statistics(void)
{
    uint64_t i, min_rtt, max_rtt, sum_rtt, avg_rtt;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "====== vOLT statistics =====\n");
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "tx %" PRIu64 " sent packets\n", port_statistics.tx);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "rx %" PRIu64 " received packets\n", port_statistics.rx);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "dopped %" PRIu64 " packets\n", port_statistics.dropped);

    min_rtt = 999999999;
    max_rtt = 0;
    sum_rtt = 0;
    avg_rtt = 0;
    for (i = 0; i < nb_pkts; i++)
    {
        sum_rtt += port_statistics.rtt[i];
        if (port_statistics.rtt[i] < min_rtt)
            min_rtt = port_statistics.rtt[i];
        if (port_statistics.rtt[i] > max_rtt)
            max_rtt = port_statistics.rtt[i];
    }
    avg_rtt = sum_rtt / nb_pkts;
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "min rtt: %" PRIu64 " us\n", min_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "max rtt: %" PRIu64 " us\n", max_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "average rtt: %" PRIu64 " us\n", avg_rtt);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "=================================\n");
}

static const char short_options[] =
    "p:" /* portmask */
    "n:" /* number of packets */
    "s"  /* server mode */
    "c"  /* client mode */
    ;


static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM)
    {
        rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "\n\nSignal %d received, preparing to exit...\n", signum);
        force_quit = true;
    }
}

/* display usage */
static void
volt_usage(const char *prgname)
{
    printf("%s [EAL options] --"
           "\t-p PORTID: port to configure\n"
           "\t\t\t\t\t-n PACKETS: number of packets\n"
           "\t\t\t\t\t-s: enable server mode (default)\n",
           prgname);
}

/* Parse the argument given in the command line of the application */
static int
volt_parse_args(int argc, char **argv)
{
    int opt, ret;
    char *prgname = argv[0];

    while ((opt = getopt(argc, argv, short_options)) != EOF)
    {
        switch (opt)
        {
        /* port id */
        case 'p':
            portid = (uint16_t)strtol(optarg, NULL, 10);
            break;

        case 'n':
            nb_pkts = (uint64_t)strtoull(optarg, NULL, 10);
            break;

        case 's':
            server_mode = true;
            break;

        case 'c':
            server_mode = false;
            break;

        default:
            volt_usage(prgname);
            return -1;
        }
    }

    if (optind >= 0)
        argv[optind - 1] = prgname;

    ret = optind - 1;
    optind = 1; /* reset getopt lib */
    return ret;
}

/* construct dbru packet */
static struct rte_mbuf *
construct_dbru_packet(void)
{
    size_t pkt_size;
    struct rte_mbuf *pkt;
    struct rte_ether_hdr *eth_hdr;
    struct dbru_header *dbru_hdr;

    pkt = rte_pktmbuf_alloc(volt_pktmbuf_pool);
    if (!pkt)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_VOLT, "fail to alloc mbuf for packet\n");

    pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct dbru_header);


    /* Initialize Ethernet header. */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    rte_ether_addr_copy(&onu_ether_addr, &eth_hdr->d_addr);
    rte_ether_addr_copy(&olt_ether_addr, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_PON_US_FIRST);

    /* Initialize DBRu packet (just after the Ethernet header) */
    dbru_hdr = (struct dbru_header *)(eth_hdr + 1);
    uint8_t counter = 0;
    dbru_hdr->padding = 0x0;
    dbru_hdr->onu_id = ONU_ID; 
    dbru_hdr->counter = ++counter;
    dbru_hdr->buff_occ = rte_cpu_to_be_16(DBRU_STATIC[counter]);

    pkt->data_len = pkt_size;
    pkt->pkt_len = pkt_size;
    pkt->next = NULL;

    return pkt;
}


/* construct dbru packet */
static struct rte_mbuf *
construct_bwmap_packet(void)
{
    size_t pkt_size;
    struct rte_mbuf *pkt;
    struct rte_ether_hdr *eth_hdr;
    struct bwmap_header *bwmap_hdr;

    pkt = rte_pktmbuf_alloc(volt_pktmbuf_pool);
    if (!pkt)
        rte_log(RTE_LOG_ERR, RTE_LOGTYPE_VOLT, "fail to alloc mbuf for packet\n");

    pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct bwmap_header);


    /* Initialize Ethernet header. */
    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    rte_ether_addr_copy(&onu_ether_addr, &eth_hdr->d_addr);
    rte_ether_addr_copy(&olt_ether_addr, &eth_hdr->s_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETH_TYPE_BWMAP);

    /* Initialize BWMAP packet (just after the Ethernet header) */
    bwmap_hdr = (struct bwmap_header *)(eth_hdr + 1);
    bwmap_hdr->count = rte_cpu_to_be_16(1);
    bwmap_hdr->alloc_id = xhash(ONU_ID, 1);
    bwmap_hdr->ploamu = rte_cpu_to_be_16(0);
    bwmap_hdr->start_time = rte_cpu_to_be_16(17);
    bwmap_hdr->grant_size = rte_cpu_to_be_16(97);


    pkt->data_len = pkt_size;
    pkt->pkt_len = pkt_size;
    pkt->next = NULL;

    return pkt;
}

/* main volt loop */
static void
volt_main_loop(void)
{
    unsigned lcore_id;
    unsigned i, nb_rx, nb_tx;
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    struct rte_mbuf *m = NULL;
    struct rte_mbuf *s = NULL;
    struct rte_ether_hdr *eth_hdr;
    struct dbru_header *dbru_hdr;
    struct bwmap_header *bwmap_hdr;
    uint16_t eth_type;

    lcore_id = rte_lcore_id();

    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "entering vOLT loop on lcore %u\n", lcore_id);
    rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "waiting for upstream packets\n");

    /* wait for a query */
    while (!force_quit)
    {
        nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);
        if (nb_rx)
        {
            for (i = 0; i < nb_rx; i++)
            {

                m = pkts_burst[i];

                eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
                eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
                if (eth_type == RTE_ETHER_TYPE_PON_US_FIRST)
                {
                    if (rte_is_same_ether_addr(&eth_hdr->d_addr, &onu_ether_addr))
                    {
                        dbru_hdr = (struct dbru_header *)(rte_pktmbuf_mtod(m, char *) + sizeof(struct rte_ether_hdr));

                        port_statistics.rx += 1;
                        /* response */
                        rte_ether_addr_copy(&onu_ether_addr, &eth_hdr->s_addr);
                        rte_ether_addr_copy(&olt_ether_addr, &eth_hdr->d_addr);

                        nb_tx = rte_eth_tx_burst(portid, 0, &m, 1);
                        if (nb_tx)
                            port_statistics.tx += nb_tx;

                        global_count += 1;

                        // send the bwmap packet
                        if (global_count > 2) {
                            global_count = 0;
                            //rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "ts_begin_low: %u \n", rte_be_to_cpu_32(dbru_hdr->ts_begin_low));
                            rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "ts_begin_high: %u \n", dbru_hdr->ts_begin_high);
                            rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "ts_counter: %u \n", dbru_hdr->ts_counter);
        
                            s = construct_bwmap_packet();
                            if (s == NULL)
                                rte_log(RTE_LOG_ERR, RTE_LOGTYPE_VOLT, "construct packet failed\n");

                            eth_hdr = rte_pktmbuf_mtod(s, struct rte_ether_hdr *);
                            bwmap_hdr = (struct bwmap_header *)(rte_pktmbuf_mtod(s, char *) + sizeof(struct rte_ether_hdr));
                            
                            rte_ether_addr_copy(&onu_ether_addr, &eth_hdr->s_addr);
                            rte_ether_addr_copy(&olt_ether_addr, &eth_hdr->d_addr);
                            rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VOLT, "Sending a BWMAP packet w/ start time: %u \n", rte_be_to_cpu_16(bwmap_hdr->start_time));
                            nb_tx = rte_eth_tx_burst(portid, 0, &s, 1);

                        }
                    }
                }
            }
        }
    }
}


static int
volt_launch_one_lcore(__attribute__((unused)) void *dummy)
{
    volt_main_loop();
    return 0;
}

int main(int argc, char **argv)
{
    int ret;
    uint16_t nb_ports;
    unsigned int nb_mbufs;
    unsigned int nb_lcores;
    unsigned int lcore_id;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    /* init log */
    RTE_LOGTYPE_VOLT = rte_log_register(APP);
    ret = rte_log_set_level(RTE_LOGTYPE_VOLT, VOLT_LOG_LEVEL);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Set log level to %u failed\n", RTE_LOGTYPE_VOLT);
    
    nb_lcores = rte_lcore_count();
    if (nb_lcores < 2)
        rte_exit(EXIT_FAILURE, "Number of CPU cores should be no less than 2.");

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports, bye...\n");

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_VOLT, "%u port(s) available\n", nb_ports);

    /* parse application arguments (after the EAL ones) */
    ret = volt_parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid volt arguments\n");
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_VOLT, "Enabled port: %u\n", portid);
    if (portid > nb_ports - 1)
        rte_exit(EXIT_FAILURE, "Invalid port id %u, port id should be in range [0, %u]\n", portid, nb_ports - 1);

    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    nb_mbufs = RTE_MAX((unsigned int)(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE)), 8192U);
    volt_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
                                                    MEMPOOL_CACHE_SIZE, 0, PKT_MBUF_DATA_SIZE,
                                                    rte_socket_id());
    if (volt_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_VOLT, "Initializing port %u...\n", portid);
    fflush(stdout);

    /* init port */
    rte_eth_dev_info_get(portid, &dev_info);
    if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
        local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
                 ret, portid);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
                                           &nb_txd);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot adjust number of descriptors: err=%d, port=%u\n",
                 ret, portid);

    /* init one RX queue */
    fflush(stdout);
    rxq_conf = dev_info.default_rxconf;

    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                                 rte_eth_dev_socket_id(portid),
                                 &rxq_conf,
                                 volt_pktmbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                 ret, portid);

    /* init one TX queue on each port */
    fflush(stdout);
    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                 rte_eth_dev_socket_id(portid),
                                 &txq_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                 ret, portid);

    /* Initialize TX buffers */
    tx_buffer = rte_zmalloc_socket("tx_buffer",
                                   RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
                                   rte_eth_dev_socket_id(portid));
    if (tx_buffer == NULL)
        rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
                 portid);

    rte_eth_tx_buffer_init(tx_buffer, MAX_PKT_BURST);

    ret = rte_eth_tx_buffer_set_err_callback(tx_buffer,
                                             rte_eth_tx_buffer_count_callback,
                                             &port_statistics.dropped);
    if (ret < 0)
        rte_exit(EXIT_FAILURE,
                 "Cannot set error callback for tx buffer on port %u\n",
                 portid);

    /* Start device */
    ret = rte_eth_dev_start(portid);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
                 ret, portid);

    /* initialize port stats */
    initlize_port_statistics();

    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_VOLT, "Initilize port %u done.\n", portid);

    lcore_id = rte_get_next_lcore(0, true, false);

    ret = 0;
    rte_eal_remote_launch(volt_launch_one_lcore, NULL, lcore_id);

    if (rte_eal_wait_lcore(lcore_id) < 0)
    {
        ret = -1;
    }

    rte_eth_dev_stop(portid);
    rte_eth_dev_close(portid);
    destroy_port_statistics();
    rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_VOLT, "Bye!\n");

    return 0;
}
