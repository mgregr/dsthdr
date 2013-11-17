#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
 
static short int nhdrs = 0;
module_param(nhdrs, short, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(nhdrs, "Number of extension headers that will be added, default is 0");
MODULE_LICENSE("GPL v2");

#define DST_OPTS_HLEN 8 	// length of dst option header without any options

struct ipv6_dst_opt_hdr_padn {
	__u8	nexthdr;
	__u8	hdrlen;
//padN option
	__u8	pad_type;
	__u8	pad_len;
	__u32	padding;
};

static struct nf_hook_ops nfho;   //net filter hook option struct

void insert_dst_hdr (struct sk_buff *skb, int offset) 
{
	struct ipv6_dst_opt_hdr_padn *hdr;
	hdr = (struct ipv6_dst_opt_hdr_padn *) (skb->data + offset);
	hdr->nexthdr = NEXTHDR_DEST;
	hdr->hdrlen = 0;
	hdr->pad_type = 1;
	hdr->pad_len = 4;
	hdr->padding = 0;
		
}

unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	
	struct ipv6hdr *ipv6;
	unsigned int y = 0;
	struct ipv6_dst_opt_hdr_padn *last_hdr;
	__u8	transport_hdr;

  if (nhdrs == 0) {
		return NF_ACCEPT;
	}
	
  ipv6 = ipv6_hdr(skb);
	if (ipv6 == NULL) {
		printk(KERN_INFO "fail to find ipv6 header\n");
		return NF_ACCEPT;
	} else {
		if (ipv6->nexthdr != NEXTHDR_TCP) {
			return NF_ACCEPT;
		}
//		printk (KERN_INFO "%pI6c -> %pI6c, header %d, headroom %d", &ipv6->saddr, &ipv6->daddr, ipv6->nexthdr, skb_headroom(skb));
		if (skb_headroom(skb) < nhdrs * DST_OPTS_HLEN + ETH_HLEN) {	// check if headroom is big enough
			if (pskb_expand_head(skb, SKB_DATA_ALIGN(nhdrs * DST_OPTS_HLEN + ETH_HLEN) - skb_headroom(skb), 0, GFP_ATOMIC) != 0) { //expand the headroom
				printk (KERN_INFO "Cannot reallocate headroom");
				return NF_DROP;
			}
		}
//		printk(KERN_INFO "new headroom %d", skb_headroom(skb));
		skb_push(skb, nhdrs * DST_OPTS_HLEN);
		memmove(skb->data, ipv6, sizeof(struct ipv6hdr));
		skb_reset_network_header(skb);
		ipv6 = ipv6_hdr(skb);
		memset(skb->data + sizeof(struct ipv6hdr), 0, nhdrs * DST_OPTS_HLEN);
		transport_hdr = ipv6->nexthdr;
		ipv6->nexthdr = NEXTHDR_DEST;
		for (y = 0; y < nhdrs; y++) {
			insert_dst_hdr(skb, sizeof(struct ipv6hdr) + y * DST_OPTS_HLEN);
		}
		last_hdr = (struct ipv6_dst_opt_hdr_padn *) (skb->data + sizeof(struct ipv6hdr) + ((nhdrs - 1) * DST_OPTS_HLEN));
		last_hdr->nexthdr = transport_hdr;
		ipv6->payload_len = htons(ntohs(ipv6->payload_len) + nhdrs * DST_OPTS_HLEN);
	}

  return NF_ACCEPT;
}
 
int init_module()
{
        nfho.hook = hook_func;
        nfho.hooknum = NF_INET_LOCAL_OUT;
        nfho.pf = NFPROTO_IPV6;
        nfho.priority = NF_IP_PRI_FIRST;
 
        nf_register_hook(&nfho);

        printk(KERN_INFO "Dsthdr module: number of headers %d\n", nhdrs); 
        return 0;
}
 
void cleanup_module()
{
        nf_unregister_hook(&nfho);     
}
