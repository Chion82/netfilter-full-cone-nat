
Implementation of full cone SNAT.

Assuming eth0 is external interface:
```
iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT #same as MASQUERADE  
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT  #automatically restore NAT for inbound packets
```
Currently only UDP traffic is supported for full-cone NAT. For other protos FULLCONENAT is equivalent to MASQUERADE.

Build
======
Prerequisites: 
* kernel source  
* iptables source (git://git.netfilter.org/iptables.git) 

Kernel Module
-------------
1. Copy xt_FULLCONENAT.c to `kernel-source/net/netfilter/xt_FULLCONENAT.c`   
2. Append following line to `kernel-source/net/netfilter/Makefile`:

```
obj-$(CONFIG_NETFILTER_XT_TARGET_FULLCONENAT) += xt_FULLCONENAT.o
```

3. Insert following section to `kernel-source/net/ipv4/netfilter/Kconfig` right after `config IP_NF_TARGET_NETMAP` section:

```
config IP_NF_TARGET_FULLCONENAT
  tristate "FULLCONENAT target support"
  depends on NETFILTER_ADVANCED
  select NETFILTER_XT_TARGET_FULLCONENAT
  ---help---
  This is a backwards-compat option for the user's convenience
  (e.g. when running oldconfig). It selects
  CONFIG_NETFILTER_XT_TARGET_FULLCONENAT.

```

4. Insert following section to `kernel-source/net/netfilter/Kconfig` right after `config NETFILTER_XT_TARGET_NETMAP` section:

```
config NETFILTER_XT_TARGET_FULLCONENAT
  tristate '"FULLCONENAT" target support'
  depends on NF_NAT
  ---help---
  Full Cone NAT

  To compile it as a module, choose M here. If unsure, say N.

```

5. `cd` into the kernel source directory and prepare a working kernel config. This can be done by exporting from your current system:

```
zcat /proc/config.gz > .config
```

6. Run `make menuconfig` and select:
    Networking support -> Network options -> Network packet filtering framework (Netfilter) -> IP: Netfilter Configuration -> <M> FULLCONENAT target support

7. Prepare for building: `make prepare`

8. Run `make` to build the kernel source. Alternatively, run `make modules SUBDIRS=net/netfilter` to build only the netfilter modules.

9. Run `make modules_install` to install all built modules. Alternatively, manually load the xt_FULLCONENAT module by `insmod net/netfilter/xt_FULLCONENAT.ko`.

IPtables extension
------------------

1. Copy libipt_FULLCONENAT.c and libipt_FULLCONENAT.t to `iptables-source/extensions`.

2. Under the iptables source directory, `./configure`, `make` and `make install`

Usage
=====

Assuming eth0 is external interface:

Basic Usage:

```
iptables -t nat -A POSTROUTING -o eth0 -j FULLCONENAT
iptables -t nat -A PREROUTING -i eth0 -j FULLCONENAT
```

Random port range:

```
iptables -t nat -A POSTROUTING -o eth0 ! -p udp -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth0 -p udp -j FULLCONENAT --to-ports 40000-60000 --random-fully

iptables -t nat -A PREROUTING -i eth0 -p udp -m multiport --dports 40000:60000 -j FULLCONENAT
```
