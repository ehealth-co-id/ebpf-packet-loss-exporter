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
#define FLOW_IDLE_NS     300000000000ULL /* 5 minutes */
#define BLOOM_WORDS      32768
#define BLOOM_BITS       (BLOOM_WORDS * 64)
#define BLOOM_BITMASK    (BLOOM_BITS - 1)
#define BLOOM_HASHES     3
#define BLOOM_EPOCH_NS   1500000000ULL /* 1.5 seconds */

struct bloom_word {
	__u64 gen;
	__u64 bits;
};

struct bloom_epoch_state {
	__u64 gen;
	__u64 start_ns;
};

struct counter_key {
	__u32 ifindex;
	__u8  dst_zone_id;
	__u8  pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ZONE_ENTRIES);
	__uint(key_size, sizeof(__u32) + sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(map_flags, BPF_F_NO_PREALLOC);
} zone_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_ZONE_ENTRIES);
	__uint(key_size, sizeof(__u32) + sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(map_flags, BPF_F_NO_PREALLOC);
} src_zone_lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2 * BLOOM_WORDS);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bloom_word));
} bloom_bits SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bloom_epoch_state));
} bloom_epoch SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
} debug_tcp_payload SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
} debug_tcp_zoned SEC(".maps");

static __always_inline void debug_inc(void *map)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(map, &k);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int parse_ipv4(struct __sk_buff *skb, void *data, void *data_end,
				      struct iphdr **iph)
{
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IP)) {
		*iph = (void *)(eth + 1);
		if ((void *)(*iph + 1) > data_end)
			return -1;
		return 0;
	}

	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		*iph = data;
		if ((void *)(*iph + 1) > data_end)
			return -1;
		return 0;
	}

	return -1;
}

static __always_inline void bump_counter(void *map, const struct counter_key *key, __u64 delta)
{
	__u64 *val = bpf_map_lookup_elem(map, key);

	if (!val) {
		__u64 zero = 0;

		bpf_map_update_elem(map, key, &zero, BPF_NOEXIST);
		val = bpf_map_lookup_elem(map, key);
	}
	if (val)
		__sync_fetch_and_add(val, delta);
}

static __always_inline __u32 bloom_hash(__u32 saddr, __u32 daddr, __u16 sport,
					__u16 dport, __u32 seq, __u32 seed)
{
	__u32 h = seed;

	h ^= saddr;
	h ^= daddr + 0x9e3779b9 + (h << 6) + (h >> 2);
	h ^= ((__u32)sport << 16) | dport;
	h ^= seq + 0x9e3779b9 + (h << 6) + (h >> 2);
	return h;
}

static __always_inline __u32 bloom_bit_index(__u32 saddr, __u32 daddr, __u16 sport,
					     __u16 dport, __u32 seq, __u32 seed)
{
	return bloom_hash(saddr, daddr, sport, dport, seq, seed) & BLOOM_BITMASK;
}

static __always_inline int bloom_test_bit_gen(__u32 bit, __u64 gen)
{
	__u32 word = bit >> 6;
	__u64 mask = 1ULL << (bit & 63);
	__u32 idx = (gen & 1) * BLOOM_WORDS + word;
	struct bloom_word *w = bpf_map_lookup_elem(&bloom_bits, &idx);

	if (!w || w->gen != gen)
		return 0;
	return (w->bits & mask) != 0;
}

static __always_inline void bloom_set_bit_gen(__u32 bit, __u64 gen)
{
	__u32 word = bit >> 6;
	__u64 mask = 1ULL << (bit & 63);
	__u32 idx = (gen & 1) * BLOOM_WORDS + word;
	struct bloom_word *w = bpf_map_lookup_elem(&bloom_bits, &idx);

	if (!w)
		return;

	if (w->gen != gen) {
		w->gen = gen;
		w->bits = 0;
	}
	w->bits |= mask;
}

static __always_inline void bloom_maybe_roll_epoch(__u64 now)
{
	__u32 k = 0;
	struct bloom_epoch_state *epoch = bpf_map_lookup_elem(&bloom_epoch, &k);

	if (!epoch) {
		struct bloom_epoch_state init = {
			.gen = 0,
			.start_ns = now,
		};

		bpf_map_update_elem(&bloom_epoch, &k, &init, BPF_ANY);
		return;
	}

	if (now > epoch->start_ns && now - epoch->start_ns > BLOOM_EPOCH_NS) {
		epoch->gen++;
		epoch->start_ns = now;
	}
}

static __always_inline int bloom_test_and_set(__u32 saddr, __u32 daddr, __u16 sport,
					      __u16 dport, __u32 seq)
{
	__u32 k = 0;
	struct bloom_epoch_state *epoch = bpf_map_lookup_elem(&bloom_epoch, &k);
	__u64 cur_gen;
	__u64 prev_gen;
	__u32 bit0, bit1, bit2;
	int seen0, seen1, seen2;

	if (!epoch)
		return 0;

	cur_gen = epoch->gen;
	prev_gen = cur_gen - 1;

	bit0 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0x12345678);
	bit1 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0x9e3779b9);
	bit2 = bloom_bit_index(saddr, daddr, sport, dport, seq, 0xdeadbeef);

	seen0 = bloom_test_bit_gen(bit0, cur_gen) || bloom_test_bit_gen(bit0, prev_gen);
	seen1 = bloom_test_bit_gen(bit1, cur_gen) || bloom_test_bit_gen(bit1, prev_gen);
	seen2 = bloom_test_bit_gen(bit2, cur_gen) || bloom_test_bit_gen(bit2, prev_gen);

	bloom_set_bit_gen(bit0, cur_gen);
	bloom_set_bit_gen(bit1, cur_gen);
	bloom_set_bit_gen(bit2, cur_gen);

	return seen0 && seen1 && seen2;
}

SEC("tc")
int path_egress(struct __sk_buff *skb)
{
	void *data;
	void *data_end;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 lpm_key[2];
	__u8 *zone_id;
	__u8 *src_zone;
	struct counter_key ckey = {};
	__u64 now;
	__u32 seq;
	__u32 seq_key;
	__u8 fin;
	__u8 syn;
	__u8 rst;

	if (bpf_skb_pull_data(skb, 0) < 0)
		return TC_ACT_OK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;

	if (parse_ipv4(skb, data, data_end, &iph) < 0)
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

	fin = tcph->fin;
	syn = tcph->syn;
	rst = tcph->rst;

	if (payload_len == 0 && !syn && !fin && !rst)
		return TC_ACT_OK;

	debug_inc(&debug_tcp_payload);

	lpm_key[0] = 32;
	lpm_key[1] = iph->saddr;
	src_zone = bpf_map_lookup_elem(&src_zone_lpm, lpm_key);
	if (!src_zone)
		return TC_ACT_OK;

	lpm_key[1] = iph->daddr;
	zone_id = bpf_map_lookup_elem(&zone_lpm, lpm_key);
	if (!zone_id)
		return TC_ACT_OK;

	debug_inc(&debug_tcp_zoned);

	ckey.ifindex = skb->ifindex;
	ckey.dst_zone_id = *zone_id;

	now = bpf_ktime_get_ns();
	bloom_maybe_roll_epoch(now);

	seq = bpf_ntohl(tcph->seq);
	bump_counter(&tcp_segments, &ckey, 1);

	if (payload_len > 0) {
		seq_key = seq >> 4;
		if (bloom_test_and_set(iph->saddr, iph->daddr, tcph->source,
				       tcph->dest, seq_key))
			bump_counter(&tcp_retrans, &ckey, 1);
		return TC_ACT_OK;
	}

	if (syn && !tcph->ack) {
		if (bloom_test_and_set(iph->saddr, iph->daddr, tcph->source,
				       tcph->dest, seq))
			bump_counter(&tcp_retrans, &ckey, 1);
	}

	return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
