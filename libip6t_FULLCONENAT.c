#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <xtables.h>
#include <limits.h> /* INT_MAX in ip_tables.h */
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/nf_nat.h>

#ifndef NF_NAT_RANGE_PROTO_RANDOM_FULLY
#define NF_NAT_RANGE_PROTO_RANDOM_FULLY (1 << 4)
#endif

enum {
	O_TO_PORTS = 0,
	O_RANDOM,
	O_RANDOM_FULLY,
	O_TO_SRC,
	O_PERSISTENT,
};

static void FULLCONENAT_help(void)
{
	printf(
"FULLCONENAT target options:\n"
" --to-source [<ipaddr>[-<ipaddr>]] [--persistent]\n"
"				Address to map source to.\n"
" --to-ports <port>[-<port>]\n"
"				Port (range) to map to.\n"
" --random\n"
"				Randomize source port.\n"
" --random-fully\n"
"				Fully randomize source port.\n");
}

static const struct xt_option_entry FULLCONENAT_opts[] = {
	{.name = "to-ports", .id = O_TO_PORTS, .type = XTTYPE_STRING},
	{.name = "random", .id = O_RANDOM, .type = XTTYPE_NONE},
	{.name = "random-fully", .id = O_RANDOM_FULLY, .type = XTTYPE_NONE},
	{.name = "to-source", .id = O_TO_SRC, .type = XTTYPE_STRING},
	{.name = "persistent", .id = O_PERSISTENT, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static void parse_to(const char *orig_arg, struct nf_nat_range *r)
{
	char *arg, *dash, *error;
	const struct in6_addr *ip;

	arg = strdup(orig_arg);
	if (arg == NULL)
		xtables_error(RESOURCE_PROBLEM, "strdup");

	r->flags |= NF_NAT_RANGE_MAP_IPS;
	dash = strchr(arg, '-');

	if (dash)
		*dash = '\0';

	ip = xtables_numeric_to_ip6addr(arg);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
			   arg);
	r->min_addr.in6 = *ip;
	if (dash) {
		ip = xtables_numeric_to_ip6addr(dash+1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM, "Bad IP address \"%s\"\n",
				   dash+1);
		r->max_addr.in6 = *ip;
	} else
		r->max_addr = r->min_addr;

	free(arg);
}

/* Parses ports */
static void
parse_ports(const char *arg, struct nf_nat_range *r)
{
	char *end;
	unsigned int port, maxport;

	r->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;

	if (!xtables_strtoui(arg, &end, &port, 0, UINT16_MAX))
		xtables_param_act(XTF_BAD_VALUE, "FULLCONENAT", "--to-ports", arg);

	switch (*end) {
	case '\0':
		r->min_proto.tcp.port
			= r->max_proto.tcp.port
			= htons(port);
		return;
	case '-':
		if (!xtables_strtoui(end + 1, NULL, &maxport, 0, UINT16_MAX))
			break;

		if (maxport < port)
			break;

		r->min_proto.tcp.port = htons(port);
		r->max_proto.tcp.port = htons(maxport);
		return;
	default:
		break;
	}
	xtables_param_act(XTF_BAD_VALUE, "FULLCONENAT", "--to-ports", arg);
}

static void FULLCONENAT_parse(struct xt_option_call *cb)
{
	const struct ip6t_entry *entry = cb->xt_entry;
	struct nf_nat_range *r = cb->data;
	int portok;

	if (entry->ipv6.proto == IPPROTO_TCP
	    || entry->ipv6.proto == IPPROTO_UDP
	    || entry->ipv6.proto == IPPROTO_SCTP
	    || entry->ipv6.proto == IPPROTO_DCCP
	    || entry->ipv6.proto == IPPROTO_ICMP)
		portok = 1;
	else
		portok = 0;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_PORTS:
		if (!portok)
			xtables_error(PARAMETER_PROBLEM,
				   "Need TCP, UDP, SCTP or DCCP with port specification");
		parse_ports(cb->arg, r);
		break;
	case O_TO_SRC:
		parse_to(cb->arg, r);
		break;
	case O_RANDOM_FULLY:
		r->flags |=  NF_NAT_RANGE_PROTO_RANDOM_FULLY;
		break;
	case O_RANDOM:
		r->flags |=  NF_NAT_RANGE_PROTO_RANDOM;
		break;
	case O_PERSISTENT:
		r->flags |=  NF_NAT_RANGE_PERSISTENT;
		break;
	}
}

static void
FULLCONENAT_print(const void *ip, const struct xt_entry_target *target,
                 int numeric)
{
	const struct nf_nat_range *r = (const void *)target->data;

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		printf(" to:%s", xtables_ip6addr_to_numeric(&r->min_addr.in6));
		if (memcmp(&r->min_addr, &r->max_addr, sizeof(r->min_addr)))
			printf("-%s", xtables_ip6addr_to_numeric(&r->max_addr.in6));
	}

	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(" masq ports: ");
		printf("%hu", ntohs(r->min_proto.tcp.port));
		if (r->max_proto.tcp.port != r->min_proto.tcp.port)
			printf("-%hu", ntohs(r->max_proto.tcp.port));
		if (r->flags & NF_NAT_RANGE_PERSISTENT)
			printf(" persistent");
	}

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" random");

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		printf(" random-fully");
}

static void
FULLCONENAT_save(const void *ip, const struct xt_entry_target *target)
{
	const struct nf_nat_range *r = (const void *)target->data;

	if (r->flags & NF_NAT_RANGE_MAP_IPS) {
		printf(" --to-source %s", xtables_ip6addr_to_numeric(&r->min_addr.in6));
		if (memcmp(&r->min_addr, &r->max_addr, sizeof(r->min_addr)))
			printf("-%s", xtables_ip6addr_to_numeric(&r->max_addr.in6));
		if (r->flags & NF_NAT_RANGE_PERSISTENT)
			printf(" --persistent");
	}

	if (r->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(" --to-ports %hu", ntohs(r->min_proto.tcp.port));
		if (r->max_proto.tcp.port != r->min_proto.tcp.port)
			printf("-%hu", ntohs(r->max_proto.tcp.port));
	}

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" --random");

	if (r->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		printf(" --random-fully");
}

static struct xtables_target fullconenat_tg_reg = {
	.name		= "FULLCONENAT",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_IPV6,
	.size		= XT_ALIGN(sizeof(struct nf_nat_range)),
	.userspacesize	= XT_ALIGN(sizeof(struct nf_nat_range)),
	.help		= FULLCONENAT_help,
	.x6_parse	= FULLCONENAT_parse,
	.print		= FULLCONENAT_print,
	.save		= FULLCONENAT_save,
	.x6_options	= FULLCONENAT_opts,
};

void _init(void)
{
	xtables_register_target(&fullconenat_tg_reg);
}
