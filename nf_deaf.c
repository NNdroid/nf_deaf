#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/fs.h>      /* 6.12: simple_read_from_buffer 需要此头文件 */
#include <linux/mm.h>      /* 6.12: page/virt/vmalloc 转换需要此头文件 */
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/dst.h>

#define MARK_MAGIC	GENMASK(31, 16)
#define MARK_WR_ACKSEQ	BIT(15)
#define MARK_WR_SEQ	BIT(14)
#define MARK_WR_CHKSUM	BIT(13)
#define MARK_REPEAT	GENMASK(12, 10)
#define MARK_DELAY	GENMASK(9, 5)
#define MARK_TTL	GENMASK(4, 0)

#define NF_DEAF_TCP_DOFF	10
#define NF_DEAF_BUF_SIZE	SZ_2K
/* 修正了字符串定义，避免编译器警告 */
#define NF_DEAF_BUF_DEFAULT	"GET / HTTP/1.1\r\nHost: www.speedtest.cn\r\nUser-Agent: Mozilla/5.0\r\nAccept: /\r\nConnection: close\r\n\r\n"

struct nf_deaf_skb_cb {
	union {
		struct inet_skb_parm _4;
		struct inet6_skb_parm _6;
	};
	struct net *net;
	struct sock *sk;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
/* 确保 CB 结构大小安全 */
#define NF_DEAF_SKB_CB(skb) ((struct nf_deaf_skb_cb *)(skb)->cb)

struct nf_deaf_timer {
	struct list_head list;
	struct timer_list timer;
	int size;
};

static DEFINE_PER_CPU(struct nf_deaf_timer, skb_tx_timer);
static char __read_mostly buf[NF_DEAF_BUF_SIZE] __aligned(NF_DEAF_BUF_SIZE) = NF_DEAF_BUF_DEFAULT;
static unsigned int __read_mostly buf_size = sizeof(NF_DEAF_BUF_DEFAULT) - 1;
static struct page * __read_mostly buf_page;
static struct dentry *dir;

#ifdef CONFIG_DEBUG_FS
static ssize_t
nf_deaf_buf_read(struct file *file, char __user *to, size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_inode;
	ssize_t ret;

	inode_lock_shared(inode);
	ret = simple_read_from_buffer(to, count, ppos, buf, READ_ONCE(buf_size));
	inode_unlock_shared(inode);
	return ret;
}

static ssize_t
nf_deaf_buf_write(struct file *file, const char __user *from, size_t count, loff_t *ppos)
{
	struct inode *inode = file->f_inode;
	ssize_t ret;

	inode_lock(inode);
	ret = simple_write_to_buffer(buf, NF_DEAF_BUF_SIZE, ppos, from, count);
	if (ret < 0)
		goto out;

	WRITE_ONCE(buf_size, *ppos);
	inode->i_size = *ppos;
out:
	inode_unlock(inode);
	return ret;
}

static const struct file_operations nf_deaf_fops = {
	.owner	= THIS_MODULE,
	.read	= nf_deaf_buf_read,
	.write	= nf_deaf_buf_write,
	.llseek	= default_llseek,
};
#endif

/* 前置声明 */
static unsigned int
nf_deaf_postrouting_hook4(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state);
static unsigned int
nf_deaf_postrouting_hook6(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state);

static void
nf_deaf_tcp_init(struct tcphdr *th, const struct tcphdr *oth,
		 bool corrupt_seq, bool corrupt_ackseq)
{
	__be16 *data;

	th->source = oth->source;
	th->dest = oth->dest;
	th->seq = oth->seq ^ htonl((u32)corrupt_seq << 31);
	th->ack_seq = oth->ack_seq ^ htonl((u32)corrupt_ackseq << 31);
	th->res1 = 0;
	th->doff = NF_DEAF_TCP_DOFF;
	
	/* 6.12 兼容性修改：直接操作 TCP 标记字节，避免宏定义冲突 */
	((u8 *)th)[13] = ((u8 *)oth)[13];
	
	th->check = 0;
	th->urg_ptr = 0;

	data = (void *)th + sizeof(*th);
	data[0] = htons(0x1312);
	data[9] = 0;
}

static struct sk_buff *
nf_deaf_alloc_and_init_skb(const struct sk_buff *oskb, unsigned int l3hdrsize, unsigned int payloadsize)
{
	struct dst_entry *dst;
	struct sk_buff *skb;

	skb = alloc_skb(LL_MAX_HEADER + l3hdrsize + NF_DEAF_TCP_DOFF * 4, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, LL_MAX_HEADER);
	__skb_put(skb, l3hdrsize + NF_DEAF_TCP_DOFF * 4);
	
	/* 6.12: dev 字段赋值 */
	if (oskb->dev)
		skb->dev = oskb->dev;
		
	skb_copy_queue_mapping(skb, oskb);
	
	/* 6.12: 安全获取 dst */
	dst = skb_dst(oskb);
	if (dst) {
		dst_hold(dst);
		skb_dst_set(skb, dst);
	}

	skb_reset_network_header(skb);
	skb_set_transport_header(skb, l3hdrsize);
	
	if (likely(buf_page)) {
		skb_fill_page_desc(skb, 0, buf_page, offset_in_page(buf), payloadsize);
		get_page(buf_page);
	}

	skb->len += payloadsize;
	skb->data_len = payloadsize;

	return skb;
}

static int
nf_deaf_send_generated_skb(struct sk_buff *skb,
			   const struct nf_hook_state *state, u32 repeat)
{
	int i;

	for (i = 0; i < repeat; i++) {
		struct sk_buff *nskb;

		nskb = skb_clone(skb, GFP_ATOMIC);
		if (unlikely(!nskb))
			break;

		if (unlikely(state->okfn(state->net, state->sk, nskb)))
			break;
	}

	return state->okfn(state->net, state->sk, skb);
}

static void
nf_deaf_timer_resched(struct timer_list *timer, unsigned long tick)
{
	timer->expires = tick + jiffies;
	add_timer(timer);
}

static unsigned int
nf_deaf_enqueue_skb(struct sk_buff *skb, const struct nf_hook_state *state,
		    unsigned long delay)
{
	struct nf_deaf_timer *percpu_timer = this_cpu_ptr(&skb_tx_timer);
	struct timer_list *timer = &percpu_timer->timer;
	struct list_head *list = &percpu_timer->list;

	if (unlikely(list_empty(list)))
		nf_deaf_timer_resched(timer, delay);
	else if (unlikely(percpu_timer->size >= 1000))
		return NF_DROP;

	skb->skb_mstamp_ns = get_jiffies_64() + delay;
	
	/* 编译时检查 CB 大小 */
	BUILD_BUG_ON(sizeof(struct nf_deaf_skb_cb) > sizeof(skb->cb));
	
	NF_DEAF_SKB_CB(skb)->net = state->net;
	NF_DEAF_SKB_CB(skb)->sk = state->sk;
	NF_DEAF_SKB_CB(skb)->okfn = state->okfn;
	
	list_add_tail(&skb->list, list);
	percpu_timer->size++;
	return NF_STOLEN;
}

/* * 6.12 关键修复: 
 * 移除了所有对 net->nf.hooks_... 的访问逻辑。
 * 直接调用保存的 okfn 即可将包交给 Netfilter 链中的"下一个"处理者。
 */
static void
nf_deaf_send_queued_skb(struct sk_buff *skb)
{
	struct net *net = NF_DEAF_SKB_CB(skb)->net;
	struct sock *sk = NF_DEAF_SKB_CB(skb)->sk;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *) = NF_DEAF_SKB_CB(skb)->okfn;

	/* * 直接调用 okfn。在 Netfilter 架构中，okfn 实际上是 nf_hook_slow 
	 * 传递进来的延续函数，调用它意味着"当前 hook 处理完毕，继续后续流程"。
	 * 这正是我们需要的行为，无需手动遍历 hook 链表。
	 */
	okfn(net, sk, skb);
}

static void
nf_deaf_dequeue_skb(struct timer_list *timer)
{
	struct nf_deaf_timer *percpu_timer = from_timer(percpu_timer, timer, timer);
	struct list_head *list = &percpu_timer->list;
	struct sk_buff *skb, *tmp;
	u64 now;

	now = get_jiffies_64();
	list_for_each_entry_safe(skb, tmp, list, list) {
		if (time_after64(skb->skb_mstamp_ns, now)) {
			nf_deaf_timer_resched(timer, skb->skb_mstamp_ns - now);
			break;
		}

		skb->skb_mstamp_ns = 0;
		skb_list_del_init(skb);
		percpu_timer->size--;
		nf_deaf_send_queued_skb(skb);
	}
}

static int
nf_deaf_xmit4(const struct sk_buff *oskb, const struct iphdr *oiph,
	      const struct tcphdr *oth, const struct nf_hook_state *state)
{
	bool corrupt_checksum, corrupt_seq, corrupt_ackseq;
	unsigned int tmp_buf_size = READ_ONCE(buf_size);
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *th;
	u32 repeat;
	u8 ttl;

	skb = nf_deaf_alloc_and_init_skb(oskb, sizeof(*iph), tmp_buf_size);
	if (unlikely(!skb))
		return -ENOMEM;

	corrupt_checksum = oskb->mark & MARK_WR_CHKSUM;
	corrupt_seq = oskb->mark & MARK_WR_SEQ;
	corrupt_ackseq = oskb->mark & MARK_WR_ACKSEQ;
	ttl = FIELD_GET(MARK_TTL, oskb->mark);
	repeat = FIELD_GET(MARK_REPEAT, oskb->mark);
	
	skb->protocol = htons(ETH_P_IP);

	iph = ip_hdr(skb);
	*iph = *oiph;
	iph->check = 0;
	iph->ihl = 5;
	iph->tot_len = htons(sizeof(*iph) + NF_DEAF_TCP_DOFF * 4 + tmp_buf_size);
	iph->ttl = ttl ?: iph->ttl;
	iph->check = ip_fast_csum(iph, iph->ihl);

	th = (void *)iph + sizeof(*iph);
	nf_deaf_tcp_init(th, oth, corrupt_seq, corrupt_ackseq);

	th->check = tcp_v4_check(NF_DEAF_TCP_DOFF * 4 + tmp_buf_size, iph->saddr, iph->daddr,
				 csum_partial(th, NF_DEAF_TCP_DOFF * 4 + tmp_buf_size, 0));
	th->check += corrupt_checksum;

	return nf_deaf_send_generated_skb(skb, state, repeat);
}

static int
nf_deaf_xmit6(const struct sk_buff *oskb, const struct ipv6hdr *oip6h,
	      const struct tcphdr *oth, const struct nf_hook_state *state)
{
	bool corrupt_checksum, corrupt_seq, corrupt_ackseq;
	unsigned int tmp_buf_size = READ_ONCE(buf_size);
	struct sk_buff *skb;
	struct ipv6hdr *ip6h;
	struct tcphdr *th;
	u32 repeat;
	u8 ttl;

	skb = nf_deaf_alloc_and_init_skb(oskb, sizeof(*ip6h), tmp_buf_size);
	if (unlikely(!skb))
		return -ENOMEM;

	corrupt_checksum = oskb->mark & MARK_WR_CHKSUM;
	corrupt_seq = oskb->mark & MARK_WR_SEQ;
	corrupt_ackseq = oskb->mark & MARK_WR_ACKSEQ;
	ttl = FIELD_GET(MARK_TTL, oskb->mark);
	repeat = FIELD_GET(MARK_REPEAT, oskb->mark);
	skb->protocol = htons(ETH_P_IPV6);

	ip6h = ipv6_hdr(skb);
	*ip6h = *oip6h;
	ip6h->payload_len = htons(NF_DEAF_TCP_DOFF * 4 + tmp_buf_size);
	ip6h->hop_limit = ttl ?: ip6h->hop_limit;

	th = (void *)ip6h + sizeof(*ip6h);
	nf_deaf_tcp_init(th, oth, corrupt_seq, corrupt_ackseq);
	th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr, NF_DEAF_TCP_DOFF * 4 + tmp_buf_size,
				    IPPROTO_TCP, csum_partial(th, NF_DEAF_TCP_DOFF * 4 + tmp_buf_size,
							      0));
	th->check += corrupt_checksum;

	return nf_deaf_send_generated_skb(skb, state, repeat);
}

static unsigned int
nf_deaf_postrouting_hook4(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	u32 delay;

	if (likely(FIELD_GET(MARK_MAGIC, skb->mark) != 0xdeaf))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (unlikely(iph->protocol != IPPROTO_TCP))
		return NF_ACCEPT;

	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return NF_ACCEPT;

	if (unlikely(!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*th))))
		return NF_DROP;

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	if (unlikely(nf_deaf_xmit4(skb, iph, th, state)))
		return NF_DROP;

	delay = FIELD_GET(MARK_DELAY, skb->mark);
	if (unlikely(!delay))
		return NF_ACCEPT;

	return nf_deaf_enqueue_skb(skb, state, delay);
}

static unsigned int
nf_deaf_postrouting_hook6(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *th;
	u32 delay;

	if (likely(FIELD_GET(MARK_MAGIC, skb->mark) != 0xdeaf))
		return NF_ACCEPT;

	ip6h = ipv6_hdr(skb);
	if (unlikely(ip6h->nexthdr != NEXTHDR_TCP))
		return NF_ACCEPT;

	if (unlikely(!pskb_may_pull(skb, skb_transport_offset(skb) + sizeof(*th))))
		return NF_DROP;

	ip6h = ipv6_hdr(skb);
	th = tcp_hdr(skb);

	if (unlikely(nf_deaf_xmit6(skb, ip6h, th, state)))
		return NF_DROP;

	delay = FIELD_GET(MARK_DELAY, skb->mark);
	if (unlikely(!delay))
		return NF_ACCEPT;

	return nf_deaf_enqueue_skb(skb, state, delay);
}

static struct nf_hook_ops nf_deaf_postrouting_hooks[] = {
	{
		.hook		= nf_deaf_postrouting_hook4,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
	{
		.hook		= nf_deaf_postrouting_hook6,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_POST_ROUTING,
		.priority	= NF_IP6_PRI_LAST - 1,
	},
};

static int __init nf_deaf_init(void)
{
	struct dentry __maybe_unused *file;
	int ret, i;

	if (is_vmalloc_or_module_addr(buf))
		buf_page = vmalloc_to_page(buf);
	else
		buf_page = virt_to_page(buf);

#ifdef CONFIG_DEBUG_FS
	dir = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	file = debugfs_create_file("buf", 0644, dir, NULL, &nf_deaf_fops);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto out_debugfs;
	} else {
		file->d_inode->i_size = sizeof(NF_DEAF_BUF_DEFAULT) - 1;
	}
#endif

	for_each_possible_cpu(i) {
		struct nf_deaf_timer *percpu_timer = per_cpu_ptr(&skb_tx_timer, i);

		INIT_LIST_HEAD(&percpu_timer->list);
		timer_setup(&percpu_timer->timer, nf_deaf_dequeue_skb, TIMER_PINNED);
	}

	ret = nf_register_net_hooks(&init_net, nf_deaf_postrouting_hooks, ARRAY_SIZE(nf_deaf_postrouting_hooks));
	if (ret)
		goto out_debugfs;

	return 0;

out_debugfs:
#ifdef CONFIG_DEBUG_FS
	debugfs_remove(dir);
#endif
	return ret;
}
module_init(nf_deaf_init);

static void __exit nf_deaf_exit(void)
{
	int i;

#ifdef CONFIG_DEBUG_FS
	debugfs_remove(dir);
#endif
	nf_unregister_net_hooks(&init_net, nf_deaf_postrouting_hooks, ARRAY_SIZE(nf_deaf_postrouting_hooks));

	for_each_possible_cpu(i) {
		struct nf_deaf_timer *percpu_timer = per_cpu_ptr(&skb_tx_timer, i);
		struct sk_buff *skb, *tmp;

		del_timer_sync(&percpu_timer->timer);

		list_for_each_entry_safe(skb, tmp, &percpu_timer->list, list)
			kfree_skb(skb);
	}
}
module_exit(nf_deaf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");
MODULE_DESCRIPTION("NF DEAF Module for Kernel 6.12");
