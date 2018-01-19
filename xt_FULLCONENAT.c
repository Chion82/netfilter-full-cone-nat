#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ipv6.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>

#define MAX_PORTS 65536

struct natmapping {
	__be32 int_addr;
  uint16_t int_port;
};

static struct natmapping mappings[MAX_PORTS];

static int is_mapping_active(const struct natmapping* mapping)
{
	return mapping->int_addr != 0;
}

static __be32 get_device_ip(const struct net_device* dev) {
	struct in_device* in_dev;
  struct in_ifaddr* if_info;

  in_dev = dev->ip_ptr;
  if (in_dev == NULL) {
    return 0;
  }
  if_info = in_dev->ifa_list;
	if (if_info) {
		return if_info->ifa_local;
	} else {
		return 0;
	}
}

static void tg_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static unsigned int fullconenat_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct nf_nat_ipv4_multi_range_compat *mr;
  const struct nf_nat_ipv4_range *range;

  struct nf_conn *ct;
  enum ip_conntrack_info ctinfo;
  struct nf_conntrack_tuple *ct_tuple, *ct_tuple_origin;

  struct natmapping* mapping;
  unsigned int ret;
  struct nf_nat_range newrange;

  __be32 new_ip, ip;
  uint16_t port, original_port;
  uint8_t protonum;

  mr = par->targinfo;
  range = &mr->range[0];

  mapping = NULL;
  ret = XT_CONTINUE;

  ct = nf_ct_get(skb, &ctinfo);

  memset(&newrange.min_addr, 0, sizeof(newrange.min_addr));
  memset(&newrange.max_addr, 0, sizeof(newrange.max_addr));
  newrange.flags       = mr->range[0].flags | NF_NAT_RANGE_MAP_IPS;
  newrange.min_proto   = mr->range[0].min;
  newrange.max_proto   = mr->range[0].max;

	if (xt_hooknum(par) == NF_INET_PRE_ROUTING) {
		//inbound packets
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
		
    protonum = (ct_tuple->dst).protonum;
    if (protonum != IPPROTO_UDP) {
      return ret;
    }
    ip = (ct_tuple->src).u3.ip;
    port = be16_to_cpu((ct_tuple->dst).u.udp.port);

    mapping = &mappings[port];
    if (is_mapping_active(mapping)) {
      printk("DNAT: src_ip=%pI4; dst_port=%d; map_to=%pI4:%d \n", &ip, port, &(mapping->int_addr), mapping->int_port);

      newrange.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
      newrange.min_addr.ip = mapping->int_addr;
      newrange.max_addr.ip = mapping->int_addr;
      newrange.min_proto.udp.port = cpu_to_be16(mapping->int_port);
      newrange.max_proto = newrange.min_proto;
      return nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));
    }

	} else if (xt_hooknum(par) == NF_INET_POST_ROUTING) {
		//outbound packets
    new_ip = get_device_ip(skb->dev);
		newrange.min_addr.ip = new_ip;
    newrange.max_addr.ip = new_ip;
    ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));

    ct_tuple_origin = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);
    
    protonum = (ct_tuple->dst).protonum;
    if (protonum != IPPROTO_UDP) {
      return ret;
    }

    ip = (ct_tuple_origin->src).u3.ip;
    original_port = be16_to_cpu((ct_tuple_origin->src).u.udp.port);
    port = be16_to_cpu((ct_tuple->dst).u.udp.port);

    printk("SNAT: src_ip=%pI4; src_port=%d; mapped_src_port=%d; \n", &ip, original_port, port);
    
    mapping = &mappings[port];
    mapping->int_addr = ip;
    mapping->int_port = original_port;
	}

  return ret;
}

static int tg4_check(const struct xt_tgchk_param *par)
{
	// const struct nf_nat_ipv4_multi_range_compat *mr = par->targinfo;

	return nf_ct_netns_get(par->net, par->family);
}

static struct xt_target tg_reg[] __read_mostly = {
	{
		.name       = "FULLCONENAT",
		.family     = NFPROTO_IPV4,
		.revision   = 0,
		.target     = fullconenat_tg4,
		.targetsize = sizeof(struct nf_nat_ipv4_multi_range_compat),
		.table      = "nat",
		.hooks      = (1 << NF_INET_PRE_ROUTING) |
		              (1 << NF_INET_POST_ROUTING) |
		              (1 << NF_INET_LOCAL_OUT) |
		              (1 << NF_INET_LOCAL_IN),
		.checkentry = tg4_check,
		.destroy    = tg_destroy,
		.me         = THIS_MODULE,
	},
};

static int __init tg_init(void)
{
  int i;
  
	printk("xt_FULLCONENAT init");
	for (i=0; i<MAX_PORTS; i++) {
		mappings[i].int_addr = 0;
		mappings[i].int_port = 0;
	}
	return xt_register_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

static void tg_exit(void)
{
	printk("xt_FULLCONENAT exit");
	xt_unregister_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

module_init(tg_init);
module_exit(tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: implementation of UDP-only full cone NAT");
MODULE_AUTHOR("Chion Tang <tech@chionlab.moe>");
MODULE_ALIAS("ipt_fullconenat");
