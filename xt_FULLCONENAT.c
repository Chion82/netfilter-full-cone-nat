#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/hashtable.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>

struct natmapping {
  uint16_t port;
  __be32 int_addr;  /* internal source ip address */
  uint16_t int_port; /* internal source port */
  struct nf_conntrack_tuple original_tuple;

  struct hlist_node node;
};

static struct nf_ct_event_notifier ct_event_notifier;
static int ct_event_notifier_registered __read_mostly = 0;
static struct net *ct_event_net = NULL;

static DEFINE_HASHTABLE(mapping_table, 10);

static DEFINE_SPINLOCK(fullconenat_lock);

static struct natmapping* get_mapping(const uint16_t port, const int create_new) {
  struct natmapping *p_current, *p_new;

  hash_for_each_possible(mapping_table, p_current, node, port) {
    if (p_current->port == port) {
      return p_current;
    }
  }

  if (!create_new) {
    return NULL;
  }

  p_new = kmalloc(sizeof(struct natmapping), GFP_ATOMIC);
  if (p_new == NULL) {
    return NULL;
  }
  p_new->port = port;
  p_new->int_addr = 0;
  p_new->int_port = 0;
  memset(&p_new->original_tuple, 0, sizeof(struct nf_conntrack_tuple));

  hash_add(mapping_table, &p_new->node, port);

  return p_new;
}

static struct natmapping* get_mapping_by_original_src(const __be32 src_ip, const uint16_t src_port) {
  struct natmapping *p_current;
  int i;
  hash_for_each(mapping_table, i, p_current, node) {
    if (p_current->int_addr == src_ip && p_current->int_port == src_port) {
      return p_current;
    }
  }
  return NULL;
}

static void destroy_mappings(void) {
  struct natmapping *p_current;
  struct hlist_node *tmp;
  int i;

  spin_lock(&fullconenat_lock);

  hash_for_each_safe(mapping_table, i, tmp, p_current, node) {
    hash_del(&p_current->node);
    kfree(p_current);
  }

  spin_unlock(&fullconenat_lock);
}

/* Check if a mapping is valid.
Possibly delete and free an invalid mapping. 
*mapping should not be used anymore after check_mapping() returns 0. */
static int check_mapping(struct natmapping* mapping, const struct nf_conn *ct)
{
  const struct nf_conntrack_zone *zone;
  struct net *net;
  struct nf_conntrack_tuple_hash *original_tuple_hash;

  if (mapping == NULL) {
    return 0;
  }

  if (mapping->port == 0 || mapping->int_addr == 0 || mapping->int_port == 0) {
    goto del_mapping;
  }

  /* get corresponding conntrack from the saved tuple */
  net = nf_ct_net(ct);
  zone = nf_ct_zone(ct);
  if (net == NULL || zone == NULL) {
    goto del_mapping;
  }
  original_tuple_hash = nf_conntrack_find_get(net, zone, &mapping->original_tuple);

  if (original_tuple_hash) {
    /* if the corresponding conntrack is found, consider the mapping is active */
    return 1;
  } else {
    goto del_mapping;
  }

del_mapping:
  hash_del(&mapping->node);
  kfree(mapping);
  return 0;
}

// conntrack destroy event callback
static int ct_event_cb(unsigned int events, struct nf_ct_event *item) {
  struct nf_conn *ct;
  struct nf_conntrack_tuple *ct_tuple, *ct_tuple_origin;
  struct natmapping *mapping;
  uint8_t protonum;
  uint16_t port;

  ct = item->ct;
  if (ct == NULL || !(events & (1 << IPCT_DESTROY))) {
    return 0;
  }

  ct_tuple = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);
  ct_tuple_origin = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);

  protonum = (ct_tuple->dst).protonum;
  if (protonum != IPPROTO_UDP) {
    return 0;
  }

  port = be16_to_cpu((ct_tuple->dst).u.udp.port);

  spin_lock(&fullconenat_lock);

  mapping = get_mapping(port, 0);
  if (mapping == NULL
    || !nf_ct_tuple_equal(&mapping->original_tuple, ct_tuple_origin)) {
    spin_unlock(&fullconenat_lock);
    return 0;
  }

  hash_del(&mapping->node);
  kfree(mapping);

  spin_unlock(&fullconenat_lock);

  return 0;
}

static void check_register_ct_event_cb(struct net *net) {
  spin_lock(&fullconenat_lock);
  if (!ct_event_notifier_registered) {
    ct_event_notifier.fcn = ct_event_cb;
    nf_conntrack_register_notifier(net, &ct_event_notifier);
    ct_event_notifier_registered = 1;
    ct_event_net = net;
  }
  spin_unlock(&fullconenat_lock);
}

static void check_unregister_ct_event_cb(void) {
  spin_lock(&fullconenat_lock);
  if (ct_event_notifier_registered && ct_event_net != NULL) {
    nf_conntrack_unregister_notifier(ct_event_net, &ct_event_notifier);
    ct_event_notifier_registered = 0;
  }
  spin_unlock(&fullconenat_lock);
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

static void fullconenat_tg_destroy(const struct xt_tgdtor_param *par)
{
  nf_ct_netns_put(par->net, par->family);
}

static uint16_t find_appropriate_port(const uint16_t original_port, const struct nf_nat_ipv4_range *range, struct nf_conn *ct) {
  uint16_t min, start, selected, range_size, i;
  struct natmapping* mapping = NULL;

  if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
    min = be16_to_cpu((range->min).udp.port);
    range_size = be16_to_cpu((range->max).udp.port) - min + 1;
  } else {
    /* minimum port is 1024. same behavior as default linux NAT. */
    min = 1024;
    range_size = 65535 - min + 1;
  }

  if ((range->flags & NF_NAT_RANGE_PROTO_RANDOM)
    || (range->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)) {
    /* for now we do the same thing for both --random and --random-fully */

    /* select a random starting point */
    start = (uint16_t)(prandom_u32() % (u32)range_size);
  } else {

    if ((original_port >= min && original_port <= min + range_size - 1)
      || !(range->flags & NF_NAT_RANGE_PROTO_SPECIFIED)) {
      /* 1. try to preserve the port if it's available */
      mapping = get_mapping(original_port, 0);
      if (mapping == NULL || !(check_mapping(mapping, ct))) {
        return original_port;
      }
    }

    /* otherwise, we start from zero */
    start = 0;
  }

  for (i = 0; i < range_size; i++) {
    /* 2. try to find an available port */
    selected = min + ((start + i) % range_size);
    mapping = get_mapping(selected, 0);
    if (mapping == NULL || !(check_mapping(mapping, ct))) {
      return selected;
    }
  }

  /* 3. at least we tried. rewrite a privous mapping. */
  return min + start;
}

static unsigned int fullconenat_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
  const struct nf_nat_ipv4_multi_range_compat *mr;
  const struct nf_nat_ipv4_range *range;

  struct nf_conn *ct;
  enum ip_conntrack_info ctinfo;
  struct nf_conntrack_tuple *ct_tuple, *ct_tuple_origin;

  struct natmapping *mapping, *src_mapping;
  unsigned int ret;
  struct nf_nat_range newrange;

  __be32 new_ip, ip;
  uint16_t port, original_port, want_port;
  uint8_t protonum;

  ip = 0;
  original_port = 0;

  check_register_ct_event_cb(xt_net(par));

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
    mapping = get_mapping(port, 0);
    if (mapping == NULL) {
      spin_unlock(&fullconenat_lock);
      return ret;
    }
    if (check_mapping(mapping, ct)) {
      newrange.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
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
    spin_lock(&fullconenat_lock);

    ct_tuple_origin = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    protonum = (ct_tuple_origin->dst).protonum;

    if (protonum == IPPROTO_UDP) {
      ip = (ct_tuple_origin->src).u3.ip;
      original_port = be16_to_cpu((ct_tuple_origin->src).u.udp.port);

      src_mapping = get_mapping_by_original_src(ip, original_port);
      if (src_mapping != NULL && check_mapping(src_mapping, ct)) {

        /* outbound nat: if a previously established mapping is active,
        we will reuse that mapping. */

        newrange.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
        newrange.min_proto.udp.port = cpu_to_be16(src_mapping->port);
        newrange.max_proto = newrange.min_proto;

      } else {
        want_port = find_appropriate_port(original_port, range, ct);

        newrange.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
        newrange.min_proto.udp.port = cpu_to_be16(want_port);
        newrange.max_proto = newrange.min_proto;

      }
    }

    new_ip = get_device_ip(skb->dev);
    newrange.min_addr.ip = new_ip;
    newrange.max_addr.ip = new_ip;

    ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));

    if (protonum != IPPROTO_UDP || ret != NF_ACCEPT) {
      spin_unlock(&fullconenat_lock);
      return ret;
    }

    /* the reply tuple contains the mapped port. */
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);

    port = be16_to_cpu((ct_tuple->dst).u.udp.port);

    /* store the mapping information to our mapping table */
    mapping = get_mapping(port, 1);
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

static int fullconenat_tg_check(const struct xt_tgchk_param *par)
{

  return nf_ct_netns_get(par->net, par->family);
}

static struct xt_target tg_reg[] __read_mostly = {
 {
  .name       = "FULLCONENAT",
  .family     = NFPROTO_IPV4,
  .revision   = 0,
  .target     = fullconenat_tg,
  .targetsize = sizeof(struct nf_nat_ipv4_multi_range_compat),
  .table      = "nat",
  .hooks      = (1 << NF_INET_PRE_ROUTING) |
                (1 << NF_INET_POST_ROUTING),
  .checkentry = fullconenat_tg_check,
  .destroy    = fullconenat_tg_destroy,
  .me         = THIS_MODULE,
 },
};

static int __init fullconenat_tg_init(void)
{
  return xt_register_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

static void fullconenat_tg_exit(void)
{
  check_unregister_ct_event_cb();
  xt_unregister_targets(tg_reg, ARRAY_SIZE(tg_reg));

  destroy_mappings();
}

module_init(fullconenat_tg_init);
module_exit(fullconenat_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: implementation of RFC3489 full cone NAT");
MODULE_AUTHOR("Chion Tang <tech@chionlab.moe>");
MODULE_ALIAS("ipt_FULLCONENAT");
