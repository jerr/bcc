#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpretrans    Trace or count TCP retransmits and TLPs.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpretrans [-c] [-h] [-l]
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Feb-2016   Brendan Gregg   Created this.
# 03-Nov-2017   Matthias Tafelmeier Extended this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
from time import sleep

# arguments
examples = """examples:
    ./tcpretrans           # trace TCP retransmits
    ./tcpretrans -l        # include TLP attempts
"""
parser = argparse.ArgumentParser(
    description="Trace TCP retransmits",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-l", "--lossprobe", action="store_true",
    help="include tail loss probe attempts")
parser.add_argument("-c", "--count", action="store_true",
    help="count occurred retransmits per flow")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define RETRANSMIT  1
#define TLP         2

// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
    u32 snd_wnd;    /* The window we expect to receive	*/
    u64	rx_b;	    /* The total number of data bytes received acked (bytes_received) */
	u64	tx_b;       /* The total number of data bytes sent acked (bytes_acked) */
    u32	dsack_dups;	/* The total number of DSACK blocks received */
    u32	snd_una;	/* First byte we want an ack for*/
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	u32	last_oow_ack_time;  /* timestamp of last out-of-window ACK */
    
    u32	snd_wl1;	/* Sequence for window update		*/
	u32	max_window;	/* Maximal window ever seen from peer	*/
	u32	mss_cache;	/* Cached effective mss, not including SACKS */
	u32	window_clamp;	/* Maximal window to advertise		*/
	u32	rcv_ssthresh;	/* Current window clamp			*/

    u32	snd_ssthresh;	/* Slow start size threshold		*/
 	u32	snd_cwnd;	/* Sending congestion window		*/
	u32	snd_cwnd_cnt;	/* Linear increase counter		*/
	u32	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */
	u32	snd_cwnd_used;
	u32	snd_cwnd_stamp;
	u32	prior_cwnd;	/* cwnd right before starting loss recovery */
	u32	prr_delivered;	/* Number of newly delivered packets to
				 * receiver in Recovery. */
	u32	prr_out;	/* Total number of pkts sent during Recovery. */
	u32	delivered;	/* Total data packets delivered incl. rexmits */
	u32	lost;		/* Total data packets lost incl. rexmits */
	u32	app_limited;	/* limited until "delivered" reaches this val */
	u64	first_tx_mstamp;  /* start of window send phase */
	u64	delivered_mstamp; /* time we reached "delivered" */
	u32	rate_delivered;    /* saved rate sample: packets delivered */
	u32	rate_interval_us;  /* saved rate sample: time elapsed */

 	u32	rcv_wnd;	/* Current receiver window		*/
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */
	u32	notsent_lowat;	/* TCP_NOTSENT_LOWAT */
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */
	u32	lost_out;	/* Lost packets			*/
	u32	sacked_out;	/* SACK'd packets			*/
	u32	fackets_out;	/* FACK'd packets			*/
    
    u32	srtt_us;	/* smoothed round trip time << 3 in usecs */
	u32	mdev_us;	/* medium deviation			*/
	u32	mdev_max_us;	/* maximal mdev for the last rtt period	*/
	u32	rttvar_us;	/* smoothed mdev_max			*/
	u32	rtt_seq;	/* sequence number to update rttvar	*/
    u32	packets_out;	/* Packets which are "in flight"	*/
	u32	retrans_out;	/* Retransmitted packets out		*/
	u32	max_packets_out;  /* max packets_out in last window */
	u32	max_packets_seq;  /* right edge of max_packets_out flight */
    u32	reordering;	/* Packet reordering metric.		*/

    u32 rcv_rtt_est; /* Receiver side RTT estimation */
	u32 rcvq_space; /* Receiver queue space */


};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 type;
};
BPF_PERF_OUTPUT(ipv6_events);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_count, struct ipv4_flow_key_t);

struct ipv6_flow_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_count, struct ipv6_flow_key_t);

static int trace_event(struct pt_regs *ctx, struct sock *skp, int type)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;
   
    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
    }
    // else drop

    return 0;
}

int trace_retransmit(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, RETRANSMIT);
    return 0;
}

int trace_tlp(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk, TLP);
    return 0;
}
"""

struct_init = { 'ipv4':
        { 'count' :
            """
               struct ipv4_flow_key_t flow_key = {};
               flow_key.saddr = skp->__sk_common.skc_rcv_saddr;
               flow_key.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               flow_key.lport = lport;
               flow_key.dport = ntohs(dport);""",
        'trace' :
               """
               struct ipv4_data_t data4 = {};
               // get throughput stats. see tcp_get_info().
               struct tcp_sock *tp = (struct tcp_sock *)skp;

               data4.snd_wnd = tp->snd_wnd;
               data4.rx_b = tp->bytes_received;
               data4.tx_b = tp->bytes_acked;
               // data4.dsack_dups = tp->dsack_dups;
               data4.snd_una = tp->snd_una;
               data4.snd_sml = tp->snd_sml;
               data4.rcv_tstamp = tp->rcv_tstamp;
               data4.lsndtime = tp->lsndtime;
               data4.last_oow_ack_time = tp->last_oow_ack_time;

               data4.snd_wl1 = tp->snd_wl1;
	           data4.snd_wnd = tp->snd_wnd;
	           data4.max_window = tp->max_window;
	           data4.mss_cache = tp->mss_cache;
	           data4.window_clamp = tp->window_clamp;
	           data4.rcv_ssthresh = tp->rcv_ssthresh;

               data4.snd_ssthresh = tp->snd_ssthresh;
               data4.snd_cwnd = tp->snd_cwnd;
               data4.snd_cwnd_cnt = tp->snd_cwnd_cnt;
               data4.snd_cwnd_clamp = tp->snd_cwnd_clamp;
               data4.snd_cwnd_used = tp->snd_cwnd_used;
               data4.snd_cwnd_stamp = tp->snd_cwnd_stamp;

               data4.prior_cwnd = tp->prior_cwnd;
               data4.prr_delivered = tp->prr_delivered;
               data4.prr_out = tp->prr_out;
               data4.delivered = tp->delivered;
               data4.lost= tp->lost;
               data4.app_limited = tp->app_limited;
               data4.first_tx_mstamp = tp->first_tx_mstamp;
               data4.delivered_mstamp = tp->delivered_mstamp;
               data4.rate_delivered = tp->rate_delivered;
               data4.rate_interval_us = tp->rate_interval_us;

               data4.rcv_wnd = tp->rcv_wnd;
               data4.write_seq = tp->write_seq;
               data4.notsent_lowat = tp->notsent_lowat;
               data4.pushed_seq = tp->pushed_seq;
               data4.lost_out = tp->lost_out;
               data4.sacked_out = tp->sacked_out;
               data4.fackets_out = tp->fackets_out;
            

               data4.srtt_us = tp->srtt_us;
               data4.mdev_us = tp->mdev_us;
               data4.mdev_max_us = tp->mdev_max_us;
               data4.rttvar_us = tp->rttvar_us;
               data4.rtt_seq = tp->rtt_seq;
               data4.packets_out = tp->packets_out;
               data4.retrans_out = tp->retrans_out;
               data4.max_packets_out = tp->max_packets_out; 
               data4.max_packets_seq = tp->max_packets_seq;
               data4.reordering = tp->reordering;

               data4.rcv_rtt_est = tp->rcv_rtt_est.rtt_us;
               data4.rcvq_space = tp->rcvq_space.space;

               data4.pid = pid;
               data4.ip = 4;
               data4.type = type;
               data4.saddr = skp->__sk_common.skc_rcv_saddr;
               data4.daddr = skp->__sk_common.skc_daddr;
               // lport is host order
               data4.lport = lport;
               data4.dport = ntohs(dport);
               data4.state = state; """
               },
        'ipv6':
        { 'count' :
            """
                    struct ipv6_flow_key_t flow_key = {};
                    bpf_probe_read(&flow_key.saddr, sizeof(flow_key.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read(&flow_key.daddr, sizeof(flow_key.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    flow_key.lport = lport;
                    flow_key.dport = ntohs(dport);""",
          'trace' : """
                    struct ipv6_data_t data6 = {};
                    data6.pid = pid;
                    data6.ip = 6;
                    data6.type = type;
                    bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    data6.lport = lport;
                    data6.dport = ntohs(dport);
                    data6.state = state;"""
                }
        }

count_core_base = """
        COUNT_STRUCT.increment(flow_key);
"""

if args.count:
    bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['count'])
    bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['count'])
    bpf_text = bpf_text.replace("IPV4_CORE", count_core_base.replace("COUNT_STRUCT", 'ipv4_count'))
    bpf_text = bpf_text.replace("IPV6_CORE", count_core_base.replace("COUNT_STRUCT", 'ipv6_count'))
else:
    bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['trace'])
    bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['trace'])
    bpf_text = bpf_text.replace("IPV4_CORE", "ipv4_events.perf_submit(ctx, &data4, sizeof(data4));")
    bpf_text = bpf_text.replace("IPV6_CORE", "ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# event data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong),
        ("snd_wnd", ct.c_uint),
        ("tx_b", ct.c_ulonglong),
        ("rx_b", ct.c_ulonglong),
        ("dsack_dups", ct.c_uint),
        ("snd_una", ct.c_uint),
        ("snd_sml", ct.c_uint),
        ("rcv_tstamp", ct.c_uint),
        ("lsndtime", ct.c_uint),
        ("last_oow_ack_time", ct.c_uint),
        ("snd_wl1", ct.c_uint),
	    ("snd_wnd", ct.c_uint),
	    ("max_window", ct.c_uint),
	    ("mss_cache", ct.c_uint),
	    ("window_clamp", ct.c_uint),
	    ("rcv_ssthresh", ct.c_uint),
        ("snd_ssthresh", ct.c_uint),
        ("snd_cwnd", ct.c_uint),
        ("snd_cwnd_cnt", ct.c_uint),
        ("snd_cwnd_clamp", ct.c_uint),
        ("snd_cwnd_used", ct.c_uint),
        ("snd_cwnd_stamp", ct.c_uint),

        ("prior_cwnd", ct.c_uint),
        ("prr_delivered", ct.c_uint),
        ("prr_out", ct.c_uint),
        ("delivered", ct.c_uint),
        ("lost", ct.c_uint),
        ("app_limited", ct.c_uint),
        ("first_tx_mstamp", ct.c_ulonglong),
        ("delivered_mstamp", ct.c_ulonglong),
        ("rate_delivered", ct.c_uint),
        ("rate_interval_us", ct.c_uint),
        ("rcv_wnd", ct.c_uint),
        ("write_seq", ct.c_uint),
        ("notsent_lowat", ct.c_uint),
        ("pushed_seq", ct.c_uint),
        ("lost_out", ct.c_uint),
        ("sacked_out", ct.c_uint),
        ("fackets_out", ct.c_uint),
        ("srtt_us", ct.c_uint),
        ("mdev_us", ct.c_uint),
        ("mdev_max_us", ct.c_uint),
        ("rttvar_us", ct.c_uint),
        ("rtt_seq", ct.c_uint),
        ("packets_out", ct.c_uint),
        ("retrans_out", ct.c_uint),
        ("max_packets_out", ct.c_uint),
        ("max_packets_seq", ct.c_uint),
        ("reordering", ct.c_uint),
        ("rcv_rtt_est", ct.c_uint),
        ("rcvq_space", ct.c_uint)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("type", ct.c_ulonglong)
    ]

# from bpf_text:
type = {}
type[1] = 'R'
type[2] = 'L'

# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = 'ESTABLISHED'
tcpstate[2] = 'SYN_SENT'
tcpstate[3] = 'SYN_RECV'
tcpstate[4] = 'FIN_WAIT1'
tcpstate[5] = 'FIN_WAIT2'
tcpstate[6] = 'TIME_WAIT'
tcpstate[7] = 'CLOSE'
tcpstate[8] = 'CLOSE_WAIT'
tcpstate[9] = 'LAST_ACK'
tcpstate[10] = 'LISTEN'
tcpstate[11] = 'CLOSING'
tcpstate[12] = 'NEW_SYN_RECV'

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    print("%-8s %-6d %-2d %-20s %1s> %-20s %-12s %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d  %-10d %-10d %-10d  %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d  %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d %-10d  %-10d %-10d %-10d %-10d %-10d %-10d" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.lport),
        type[event.type],
        "%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
        tcpstate[event.state],
        event.snd_wnd,
        event.tx_b,
        event.rx_b,
        event.dsack_dups,
        event.snd_una,
        event.snd_sml,
        event.rcv_tstamp,
        event.lsndtime,
        event.last_oow_ack_time,
        event.snd_wl1,
	    event.snd_wnd,
	    event.max_window,
	    event.mss_cache,
	    event.window_clamp,
	    event.rcv_ssthresh,
        event.snd_ssthresh,
        event.snd_cwnd,
        event.snd_cwnd_cnt,
        event.snd_cwnd_clamp,
        event.snd_cwnd_used,
        event.snd_cwnd_stamp,
         event.prior_cwnd,
         event.prr_delivered,
         event.prr_out,
         event.delivered,
         event.lost,
         event.app_limited,
         event.first_tx_mstamp,
         event.delivered_mstamp,
         event.rate_delivered,
         event.rate_interval_us,
         event.rcv_wnd,
         event.write_seq,
         event.notsent_lowat,
         event.pushed_seq,
         event.lost_out,
         event.sacked_out,
         event.fackets_out,
         event.srtt_us,
         event.mdev_us,
         event.mdev_max_us,
         event.rttvar_us,
         event.rtt_seq,
         event.packets_out,
         event.retrans_out,
         event.max_packets_out, 
         event.max_packets_seq,
         event.reordering,
         event.rcv_rtt_est,
         event.rcvq_space))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    print("%-8s %-6d %-2d %-20s %1s> %-20s %-12s" % (
        strftime("%H:%M:%S"), event.pid, event.ip,
        "%s:%d" % (inet_ntop(AF_INET6, event.saddr), event.lport),
        type[event.type],
        "%s:%d" % (inet_ntop(AF_INET6, event.daddr), event.dport),
        tcpstate[event.state]))

def depict_cnt(counts_tab, l3prot='ipv4'):
    for k, v in sorted(counts_tab.items(), key=lambda counts: counts[1].value):
        depict_key = ""
        ep_fmt = "[%s]#%d"
        if l3prot == 'ipv4':
            depict_key = "%-20s <-> %-20s" % (ep_fmt % (inet_ntop(AF_INET, pack('I', k.saddr)), k.lport),
                                              ep_fmt % (inet_ntop(AF_INET, pack('I', k.daddr)), k.dport))
        else:
            depict_key = "%-20s <-> %-20s" % (ep_fmt % (inet_ntop(AF_INET6, k.saddr), k.lport),
                                              ep_fmt % (inet_ntop(AF_INET6, k.daddr), k.dport))

        print ("%s %10d" % (depict_key, v.value))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")
if args.lossprobe:
    b.attach_kprobe(event="tcp_send_loss_probe", fn_name="trace_tlp")

print("Tracing retransmits ... Hit Ctrl-C to end")
if args.count:
    try:
        while 1:
            sleep(99999999)
    except BaseException:
        pass

    # header
    print("\n%-25s %-25s %-10s" % (
        "LADDR:LPORT", "RADDR:RPORT", "RETRANSMITS"))
    depict_cnt(b.get_table("ipv4_count"))
    depict_cnt(b.get_table("ipv6_count"), l3prot='ipv6')
# read events
else:
    # header
    print("%-8s %-6s %-2s %-20s %1s> %-20s %-12s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s" % ("TIME", "PID", "IP",
        "LADDR:LPORT", "T", "RADDR:RPORT", "STATE", "snd_wnd", "tx_b", "rx_b", "dsack_dups", "snd_una", "snd_sml", "rcv_tstamp", "lsndtime" , "last_oow_ack_time"))

    b["ipv4_events"].open_perf_buffer(print_ipv4_event)
    b["ipv6_events"].open_perf_buffer(print_ipv6_event)
    while 1:
        b.perf_buffer_poll()
