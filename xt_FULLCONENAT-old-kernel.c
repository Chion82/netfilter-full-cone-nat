#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

#define xt_hooknum(par) (par->hooknum)

struct natmapping {
  uint16_t port;
  __be32 int_addr;  /* internal source ip address */
  uint16_t int_port; /* internal source port */
  struct nf_conntrack_tuple original_tuple;

  struct hlist_node node;
};

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

static void clear_inactive_mappings(const struct nf_conn *ct) {
  struct natmapping *p_current;
  struct hlist_node *tmp;
  int i;

  spin_lock(&fullconenat_lock);

  hash_for_each_safe(mapping_table, i, tmp, p_current, node) {
    if (!is_mapping_active(p_current, ct)) {
      hash_del(&p_current->node);
      kfree(p_current);
    }
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
  uint16_t port, original_port;
  uint8_t protonum;

  mr = par->targinfo;
  range = &mr->range[0];

  mapping = NULL;
  ret = XT_CONTINUE;

  ct = nf_ct_get(skb, &ctinfo);

  clear_inactive_mappings(ct);

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
    spin_lock(&fullconenat_lock);

    ct_tuple_origin = &(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple);
    protonum = (ct_tuple_origin->dst).protonum;

    if (protonum == IPPROTO_UDP) {
      ip = (ct_tuple_origin->src).u3.ip;
      original_port = be16_to_cpu((ct_tuple_origin->src).u.udp.port);

      src_mapping = get_mapping_by_original_src(ip, original_port);
      if (src_mapping != NULL && is_mapping_active(src_mapping, ct)) {

        /* outbound nat: if a previously established mapping is active,
        we will reuse that mapping. */

        newrange.flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
        newrange.min_proto.udp.port = cpu_to_be16(src_mapping->port);
        newrange.max_proto = newrange.min_proto;

      } else if (!(newrange.flags & NF_NAT_RANGE_PROTO_RANDOM)
        && !(newrange.flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)) {

        /* if multiple LAN hosts are using the same source port
        and any PROTO_RANDOM is not specified,
        we force a random port allocation to avoid collision. */

        src_mapping = get_mapping(original_port, 0);
        if (src_mapping != NULL
          && is_mapping_active(src_mapping, ct)) {
          newrange.flags |= NF_NAT_RANGE_PROTO_RANDOM;
        }
      }
    }

    new_ip = get_device_ip(skb->dev);
    newrange.min_addr.ip = new_ip;
    newrange.max_addr.ip = new_ip;

    ret = nf_nat_setup_info(ct, &newrange, HOOK2MANIP(xt_hooknum(par)));

    /* the reply tuple contains the mapped port. */
    ct_tuple = &(ct->tuplehash[IP_CT_DIR_REPLY].tuple);
    
    if (protonum != IPPROTO_UDP) {
      spin_unlock(&fullconenat_lock);
      return ret;
    }

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

  return 0;
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

static int __init tg_init(void)
{
  return xt_register_targets(tg_reg, ARRAY_SIZE(tg_reg));
}

static void tg_exit(void)
{
  xt_unregister_targets(tg_reg, ARRAY_SIZE(tg_reg));

  destroy_mappings();
}

module_init(tg_init);
module_exit(tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: implementation of RFC3489 full cone NAT");
MODULE_AUTHOR("Chion Tang <tech@chionlab.moe>");
MODULE_ALIAS("ipt_FULLCONENAT");
