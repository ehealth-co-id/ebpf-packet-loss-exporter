//go:build ignore

#include <linux/in.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_ZONE_ENTRIES 64

struct counter_key {
	__u32 ifindex;
	__u8  dst_zone_id;
	__u8  pad[3];
};

struct flow_seq_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u32 seq;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ZONE_ENTRIES);
	__uint(key_size, sizeof(__u32) + sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(map_flags, BPF_F_NO_PREALLOC);
} zone_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__uint(key_size, sizeof(struct flow_seq_key));
	__uint(value_size, sizeof(__u8));
} seen_seq SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(struct counter_key));
	__uint(value_size, sizeof(__u64));
} tcp_segments SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__uint(key_size, sizeof(struct counter_key));
	__uint(value_size, sizeof(__u64));
} tcp_retrans SEC(".maps");

static __always_inline int parse_ipv4(void *data, void *data_end, struct iphdr **iph)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	*iph = (void *)(eth + 1);
	if ((void *)(*iph + 1) > data_end)
		return -1;

	return 0;
}

static __always_inline void bump_counter(void *map, const struct counter_key *key, __u64 delta)
{
	__u64 init = 0;
	__u64 *val = bpf_map_lookup_elem(map, key);
	if (!val) {
		bpf_map_update_elem(map, key, &init, BPF_NOEXIST);
		val = bpf_map_lookup_elem(map, key);
	}
	if (val)
		__sync_fetch_and_add(val, delta);
}

SEC("tc")
int path_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 lpm_key[2];
	__u8 *zone_id;
	struct counter_key ckey = {};
	struct flow_seq_key fkey = {};
	__u8 one = 1;
	__u64 *existing;

	if (parse_ipv4(data, data_end, &iph) < 0)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	tcph = (void *)iph + (iph->ihl * 4);
	if ((void *)(tcph + 1) > data_end)
		return TC_ACT_OK;

	__u16 tcp_hdr_len = tcph->doff * 4;
	if (tcp_hdr_len < sizeof(*tcph))
		return TC_ACT_OK;

	__u16 ip_total = bpf_ntohs(iph->tot_len);
	__u32 ip_hdr_len = iph->ihl * 4;
	if (ip_total < ip_hdr_len + tcp_hdr_len)
		return TC_ACT_OK;

	__u32 payload_len = ip_total - ip_hdr_len - tcp_hdr_len;
	if (payload_len == 0)
		return TC_ACT_OK;

	lpm_key[0] = 32;
	lpm_key[1] = iph->daddr;
	zone_id = bpf_map_lookup_elem(&zone_lpm, lpm_key);
	if (!zone_id)
		return TC_ACT_OK;

	ckey.ifindex = skb->ifindex;
	ckey.dst_zone_id = *zone_id;

	fkey.saddr = iph->saddr;
	fkey.daddr = iph->daddr;
	fkey.sport = tcph->source;
	fkey.dport = tcph->dest;
	fkey.seq = tcph->seq;

	existing = bpf_map_lookup_elem(&seen_seq, &fkey);
	if (existing) {
		bump_counter(&tcp_retrans, &ckey, 1);
		return TC_ACT_OK;
	}

	bpf_map_update_elem(&seen_seq, &fkey, &one, BPF_ANY);
	bump_counter(&tcp_segments, &ckey, 1);
	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
