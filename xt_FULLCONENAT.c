#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

struct natmapping {
  struct natmapping *next;
  uint16_t port;
  __be32 int_addr;  /* internal source ip address */
  uint16_t int_port; /* internal source port */
  struct nf_conntrack_tuple original_tuple;
};

static DEFINE_SPINLOCK(fullconenat_lock);

static struct natmapping* mappings_head;

static struct natmapping* get_mapping(const uint16_t port) {
  struct natmapping *p_current, *prev, *new;
  p_current = mappings_head;
  if (p_current == NULL) {
    return NULL;
  }
  prev = NULL;
  while (p_current) {
    if (p_current->port == port) {
      return p_current;
    }
    prev = p_current;
    p_current = p_current->next;
  }
  new = kmalloc(sizeof(struct natmapping), GFP_ATOMIC);
  if (new == NULL) {
    return NULL;
  }
  new->port = port;
  new->next = NULL;
  new->int_addr = 0;
  new->int_port = 0;
  memset(&new->original_tuple, 0, sizeof(struct nf_conntrack_tuple));

  prev->next = new;
  return new;
}

static void init_mappings(void) {
  mappings_head = kmalloc(sizeof(struct natmapping), GFP_ATOMIC);
  if (mappings_head != NULL) {
    mappings_head->next = NULL;
    mappings_head->port = 0;
    mappings_head->int_addr = 0;
    mappings_head->int_port = 0;
    memset(&mappings_head->original_tuple, 0, sizeof(struct nf_conntrack_tuple));
  } else {
    printk("xt_FULLCONENAT: mappings allocation failed. This may be caused by insufficient memory.");
  }
}

static void destroy_mappings(void) {
  static struct natmapping *p_current, *next;
  p_current = mappings_head;
  while (p_current) {
    next = p_current->next;
    kfree(p_current);
    p_current = next;
  }
}

static int is_mapping_active(const struct natmapping* mapping, const struct nf_conn *ct)
{
  const struct nf_conntrack_zone *zone;
  struct net *net;
  struct nf_conntrack_tuple_hash *original_tuple_hash;

  if (mapping->port == 0 || mapping->int_addr == 0 || mapping->int_port == 0) {
    return 0;
  }

  /* get corresponding conntrack from the saved tuple */
  net = nf_ct_net(ct);
  zone = nf_ct_zone(ct);
  if (net == NULL || zone == NULL) {
    return 0;
  }
  original_tuple_hash = nf_conntrack_find_get(net, zone, &mapping->original_tuple);

  if (original_tuple_hash) {
    /* if the corresponding conntrack is found, consider the mapping is active */
    return 1;
  } else {
    return 0;
  }
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
    /* inbound packets */
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

    protonum = (ct_tuple->dst).protonum;
    if (protonum != IPPROTO_UDP) {
      return ret;
    }
    ip = (ct_tuple->src).u3.ip;
    port = be16_to_cpu((ct_tuple->dst).u.udp.port);

    spin_lock(&fullconenat_lock);

    /* find an active mapping based on the inbound port */
    mapping = get_mapping(port);
    if (mapping == NULL) {
      spin_unlock(&fullconenat_lock);
      return ret;
    }
    if (is_mapping_active(mapping, ct)) {
      newrange.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
      newrange.min_addr.ip = mapping->int_addr;
      newrange.max_addr.ip = mapping->int_addr;
      newrange.min_proto.udp.port = cpu_to_be16(mapping->int_port);
      newrange.max_proto = newrange.min_proto;

      ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));
    }
    spin_unlock(&fullconenat_lock);
    return ret;


  } else if (xt_hooknum(par) == NF_INET_POST_ROUTING) {
    /* outbound packets */
    new_ip = get_device_ip(skb->dev);
    newrange.min_addr.ip = new_ip;
    newrange.max_addr.ip = new_ip;
    ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));

    ct_tuple_origin = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    /* the reply tuple contains the mapped port. */
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);
    
    protonum = (ct_tuple->dst).protonum;
    if (protonum != IPPROTO_UDP) {
      return ret;
    }

    ip = (ct_tuple_origin->src).u3.ip;
    original_port = be16_to_cpu((ct_tuple_origin->src).u.udp.port);
    port = be16_to_cpu((ct_tuple->dst).u.udp.port);

    
    spin_lock(&fullconenat_lock);

    /* store the mapping information to our mapping table */
    mapping = get_mapping(port);
    if (mapping == NULL) {
      spin_unlock(&fullconenat_lock);
      return ret;
    }
    mapping->int_addr = ip;
    mapping->int_port = original_port;
    /* save the original source tuple */
    memcpy(&mapping->original_tuple, ct_tuple_origin, sizeof(struct nf_conntrack_tuple));
    
    spin_unlock(&fullconenat_lock);


    return ret;
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
  init_mappings();

  return xt_register_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

static void tg_exit(void)
{
  destroy_mappings();

  xt_unregister_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

module_init(tg_init);
module_exit(tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: implementation of RFC3489 full cone NAT");
MODULE_AUTHOR("Chion Tang <tech@chionlab.moe>");
MODULE_ALIAS("ipt_FULLCONENAT");
