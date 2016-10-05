// Kernel module to detect the following TCP based reconnaissance packets that can be generated
// using ‘nmap’ and log them to the kernel log '/var/log/kern.log'
//
// 1. SYN packet
// 2. FIN packet
// 3. NULL packet
// 4. XMAS packet
// 5. ACK packet

/*
* Author: Harish Fulara (2014143)
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

//structure holding set of hook function options
static struct nf_hook_ops nfho;

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	//structure to hold IP header
	struct iphdr * ip_hdr;
	//structure to hold TCP header
	struct tcphdr * tcp_hdr;
	//structure to hold socket buffer
	struct sk_buff * socket_buffer;

	socket_buffer = skb;

	//if socket buffer is null, just accept it and return
	if(!socket_buffer) {
		return NF_ACCEPT;
	}

	//getting the IP header of the incoming packet
	ip_hdr = (struct iphdr *)skb_network_header(socket_buffer);

	//if IP header is null, just accept it and return
	if(!ip_hdr) {
		return NF_ACCEPT;
	}

	//if the incoming packet is a TCP packet, do the required processing
	if(ip_hdr->protocol == IPPROTO_TCP) {
		//getting the TCP header of the incoming packet
		tcp_hdr = (struct tcphdr *)((__u32 *)ip_hdr+ ip_hdr->ihl);
		
		//check if NULL packet is received
		//no flag is set in a NULL packet
		if(!tcp_hdr->syn && !tcp_hdr->fin && !tcp_hdr->psh && !tcp_hdr->urg && !tcp_hdr->ack && !tcp_hdr->rst && !tcp_hdr->ece && !tcp_hdr->cwr) {
			printk(KERN_INFO "NULL Packet from ");
			printk("%pI4", &ip_hdr->saddr);
			printk(" having ID %u\n", ip_hdr->id);
		}
		//check if XMAS packet is received
		//FIN, PSH and URG flags are set in an XMAS packet
		else if(!tcp_hdr->syn && tcp_hdr->fin && tcp_hdr->psh && tcp_hdr->urg && !tcp_hdr->ack && !tcp_hdr->rst && !tcp_hdr->ece && !tcp_hdr->cwr) {
			printk(KERN_INFO "XMAS Packet from ");
			printk("%pI4", &ip_hdr->saddr);
			printk(" having ID %u\n", ip_hdr->id);
		}
		//check if SYN packet is received
		//only SYN flag is set in a SYN packet
		else if(tcp_hdr->syn && !tcp_hdr->fin && !tcp_hdr->psh && !tcp_hdr->urg && !tcp_hdr->ack && !tcp_hdr->rst && !tcp_hdr->ece && !tcp_hdr->cwr) {
			printk(KERN_INFO "SYN Packet from ");
			printk("%pI4", &ip_hdr->saddr);
			printk(" having ID %u\n", ip_hdr->id);
		}
		//check if FIN packet is received
		//only FIN flag is set in a FIN packet
		else if(!tcp_hdr->syn && tcp_hdr->fin && !tcp_hdr->psh && !tcp_hdr->urg && !tcp_hdr->ack && !tcp_hdr->rst && !tcp_hdr->ece && !tcp_hdr->cwr) {
			printk(KERN_INFO "FIN Packet from ");
			printk("%pI4", &ip_hdr->saddr);
			printk(" having ID %u\n", ip_hdr->id);
		}
		//check if ACK packet is received
		//only ACK flag is set in an ACK packet
		else if(!tcp_hdr->syn && !tcp_hdr->fin && !tcp_hdr->psh && !tcp_hdr->urg && tcp_hdr->ack && !tcp_hdr->rst && !tcp_hdr->ece && !tcp_hdr->cwr) {
			printk(KERN_INFO "ACK Packet from ");
			printk("%pI4", &ip_hdr->saddr);
			printk(" having ID %u\n", ip_hdr->id);
		}
	}

	// accept the incoming packet
	return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module() {
	//function to call when conditions below met
	nfho.hook = hook_func;
	//called right after packet recieved, first hook in Netfilter
	nfho.hooknum = NF_INET_PRE_ROUTING;
	//IPV4 packets
	nfho.pf = PF_INET;
	//set to highest priority over all other hook functions
	nfho.priority = NF_IP_PRI_FIRST;
	//register hook
	nf_register_hook(&nfho);

	//return 0 for success
	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module() {
	//cleanup – unregister hook
	nf_unregister_hook(&nfho);
}