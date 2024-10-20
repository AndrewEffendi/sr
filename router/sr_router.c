/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* Function declaration */ 
static void handle_packet_forwarding(struct sr_instance *sr, uint8_t *pkt, unsigned int len,
                                      struct sr_rt *route, sr_ethernet_hdr_t *eth_hdr,
                                      sr_ip_hdr_t *ip_hdr, char *interface);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  if (!check_eth_len(packet, len)) {
        printf("Packet invalid.\n");
        return;
    }

    switch (ethertype(packet)) {
        case ethertype_arp:
            print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
            printf("Received ARP packet.\n");
            handle_arp(sr, packet, interface, len);
            break;

        case ethertype_ip:
            print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
            printf("Received IP packet.\n");
            handle_ip(sr, packet, len, interface);
            break;

        default:
            printf("Unknown packet received. Dropping.\n");
            break;
    }

}/* end sr_ForwardPacket */

/* ----------------------------------------------- */

/*--------------------------------------------------------------------- 
 * checkers: Return 1 if valid, 0 if not.
 *---------------------------------------------------------------------*/
/* Common checksum validation function */
int validate_checksum(uint8_t *packet, unsigned int offset, unsigned int length, uint16_t old_cksm) {
  uint16_t new_cksm = cksum(packet + offset, length);
  return (old_cksm == new_cksm);
}

/* check eth length*/
int check_eth_len(uint8_t *packet, unsigned int len) {
  return (len >= sizeof(sr_ethernet_hdr_t));
}

/* check IP packet length and checksum*/
int check_ip_len_cs(uint8_t *pkt, unsigned int len) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  uint16_t old_cksm = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;

  int valid = validate_checksum(pkt, sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t), old_cksm);
  ip_hdr->ip_sum = old_cksm;

  return valid;
}

/* check ICMP packet length and checksum*/
int check_icmp_len_cs(uint8_t *pkt, int len) {
  if (len < sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return 0;
  }

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  uint16_t old_cksm = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  int valid = validate_checksum(pkt, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t), old_cksm);
  icmp_hdr->icmp_sum = old_cksm;

  return valid;
}

/*--------------------------------------------------------------------- 
 * Helper function to prepare Ethernet and IP header
 *---------------------------------------------------------------------*/
/* Helper function to prepare Ethernet header */
void eth_header(sr_ethernet_hdr_t *eth_hdr, struct sr_if *interface, uint8_t *dest_mac) {
  memcpy(eth_hdr->ether_shost, interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_dhost, dest_mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_ip);
}

/* Helper function to prepare IP header */
void ip_header(sr_ip_hdr_t *ip_hdr, uint32_t src_ip, uint32_t dst_ip, uint16_t len, uint8_t ttl, uint8_t protocol) {
  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_len = htons(len);
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_off = htons(IP_DF);
  ip_hdr->ip_ttl = ttl;
  ip_hdr->ip_p = protocol;
  ip_hdr->ip_src = src_ip;
  ip_hdr->ip_dst = dst_ip;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

/* ----------------------------------------------- */

/*---------------------------------------------------------------------
 * Method: handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len)
 * Scope:  Global
 *
 * This method processes incoming ARP packets received on a specified
 * interface. It sends replies for ARP requests, updates the ARP cache
 * for ARP replies, and drops packets that are unrecognized or lack a 
 * matching interface.
 *---------------------------------------------------------------------*/
void handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    /* Get the interface associated with the incoming ARP request's target IP */
    struct sr_if *my_if = sr_get_interface_by_IP(sr, arp_hdr->ar_tip);

    if (my_if) {
        if (htons(arp_hdr->ar_op) == arp_op_request) {
            /*ARP Request*/
            uint8_t *ret_pkt = malloc(len);
            memcpy(ret_pkt, pkt, len);

            /* Get the interface for the incoming ARP request */
            struct sr_if *in_if = sr_get_interface(sr, interface);

            sr_ethernet_hdr_t *ret_eth_hdr = (sr_ethernet_hdr_t *)(ret_pkt);
            sr_arp_hdr_t *ret_arp_hdr = (sr_arp_hdr_t *)(ret_pkt + sizeof(sr_ethernet_hdr_t));

            memcpy(ret_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
            memcpy(ret_eth_hdr->ether_shost, in_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            ret_eth_hdr->ether_type = ntohs(ethertype_arp);

            ret_arp_hdr->ar_op = ntohs(arp_op_reply);
            memcpy(ret_arp_hdr->ar_sha, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
            ret_arp_hdr->ar_sip = my_if->ip;
            memcpy(ret_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);
            ret_arp_hdr->ar_tip = arp_hdr->ar_sip;

            sr_send_packet(sr, ret_pkt, len, interface);
            free(ret_pkt);

        } else if (htons(arp_hdr->ar_op) == arp_op_reply) {
            /*ARP Reply*/
            struct sr_arpreq *req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

            if (req) {
                struct sr_packet *iterator = req->packets;

                while (iterator) {
                    sr_ethernet_hdr_t *w_eth = (sr_ethernet_hdr_t *)(iterator->buf);
                    memcpy(w_eth->ether_dhost, arp_hdr->ar_sha, sizeof(uint8_t) * ETHER_ADDR_LEN);

                    sr_send_packet(sr, iterator->buf, iterator->len, iterator->iface);
                    iterator = iterator->next;
                }
                sr_arpreq_destroy(&sr->cache, req);
            }
        } else {
            printf("Unrecognized ARP OP Code.\n");
            return;
        }
    } else {
        printf("No matching interface found.\n");
    }
}

/*---------------------------------------------------------------------
 * Method: handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface)
 * Scope:  Global
 *
 * This method processes incoming IP packets received on a specified
 * interface. It checks the packet's validity, replies to ICMP echo
 * requests, sends ICMP errors for TCP/UDP packets, forwards packets
 * destined for other interfaces, and drops unsupported packets or those
 * with no matching interface.
 *---------------------------------------------------------------------*/
void handle_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  
    if (!check_ip_len_cs(pkt, len)) {
        printf("Packet is not valid.\n");
        return;
    }

    struct sr_if *my_int = sr_get_interface_by_IP(sr, ip_hdr->ip_dst);
    /* Check if the incoming packet is destined for this interface */
    if (my_int) {
        if (ip_hdr->ip_p == 1) {
            printf("Received ICMP packet.\n");

            /* ICMP */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type != 8 || !check_icmp_len_cs(pkt, len)) {
                /* Unsupported type*/
                return ;
            }
            /*Send ICMP echo reply*/
            send_icmp_echo_reply(sr, pkt, interface, len);
        } else if (ip_hdr->ip_p == 0x0006 || ip_hdr->ip_p == 0x0011) {
            /* TCP/UDP */
            /* send error code 3, type 3*/
            send_icmp_error(3, 3, sr, pkt, interface);
            return;
        } else {
            /* Unsupported Protocol */
            printf("Received unsupported protocol, dropping.\n");
            return ;
        }
    } else {
        /* forward */
        forward_ip(sr, pkt, len, interface);
    }
}

/*---------------------------------------------------------------------
 * Method: forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface)
 * Scope:  Global
 *
 * This method processes an IP packet by validating it, decrementing the 
 * TTL, and sending an ICMP time exceeded message if the TTL reaches 
 * zero. It then finds the longest prefix match for the destination 
 * address to forward the packet. If a match is found, it checks the 
 * ARP cache to send the packet or queues it if no match is found. 
 * If no longest prefix match is found, it sends an ICMP Network 
 * Unreachable message.
 *---------------------------------------------------------------------*/
void forward_ip(struct sr_instance *sr, uint8_t *pkt, unsigned int len, char *interface) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    /* Validate the IP packet */
    if (!check_ip_len_cs(pkt, len)) {
        /* invalid packet */
        return;
    }

    /* Decrement TTL and check */
    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0) {
        send_icmp_error(11, 0, sr, pkt, interface);
        return; /* Exit if TTL expired */
    }

    /* Recalculate IP checksum */
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Find longest prefix match */
    struct sr_rt *route = longest_prefix_match(sr, ip_hdr->ip_dst);
    if (route) {
        handle_packet_forwarding(sr, pkt, len, route, eth_hdr, ip_hdr, interface);
    } else {
        /*LPM not found, send error type 3 code 0*/
        send_icmp_error(3, 0, sr, pkt, interface);
    }
}

/*---------------------------------------------------------------------
 * Method: static handle_packet_forwarding(struct sr_instance *sr, uint8_t *pkt, unsigned int len,
 *                                         struct sr_rt *route, sr_ethernet_hdr_t *eth_hdr,
 *                                         sr_ip_hdr_t *ip_hdr, char *interface)
 * Scope:  Local
 *
 * This method handles packet forwarding by checking the ARP cache for 
 * the next-hop MAC address. If found, it configures the Ethernet frame 
 * and forwards the packet. If not found, it queues the packet for 
 * ARP resolution and initiates an ARP request. The source MAC address 
 * is set based on the interface associated with the route.
 *---------------------------------------------------------------------*/
static void handle_packet_forwarding(struct sr_instance *sr, uint8_t *pkt, unsigned int len,
                                      struct sr_rt *route, sr_ethernet_hdr_t *eth_hdr,
                                      sr_ip_hdr_t *ip_hdr, char *interface) {
    struct sr_if *my_if = sr_get_interface(sr, route->interface);
    sr_print_if(my_if);

    /* Set the source MAC address */
    memcpy(eth_hdr->ether_shost, my_if->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
    
    /* Check ARP cache for the next-hop MAC address */
    struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    if (arp_entry) {
        /* If MAC address is found, configure Ethernet frame and forward packet */
        memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
        sr_send_packet(sr, pkt, len, my_if->name);
    } else {
        /* If no MAC address is found, queue packet for ARP */
        print_hdr_eth(pkt);
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, pkt, len, my_if->name);
        handle_arp_request(sr, req);
    }
}


/*--------------------------------------------------------------------- 
 * Method: longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr)
 * Scope:  Global
 *
 * This method searches the routing table for the longest prefix match 
 * corresponding to the given destination address. It iterates through 
 * each entry in the routing table and compares the destination address 
 * with the masked address of each route. If a match is found, the 
 * function updates the longest match found so far. The longest prefix 
 * match is returned, or NULL if no match is found.
 *---------------------------------------------------------------------*/
struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_rt *walker = 0;

  /* REQUIRES */
  assert(sr);
  assert(dest_addr);

  walker = sr->routing_table;
  struct sr_rt *longest = 0;
  uint32_t len = 0;
  while (walker) {
    if ((walker->dest.s_addr & walker->mask.s_addr) == (dest_addr & walker->mask.s_addr)) {
      if ((walker->mask.s_addr & dest_addr) > len) {
        len = walker->mask.s_addr & dest_addr;
        longest = walker;
      }
    }
    walker = walker->next;
  }
  return longest;
}

/*--------------------------------------------------------------------- 
 * Method: lookup_and_send_packet(struct sr_instance *sr, uint32_t dst_ip, 
 *                                  uint8_t *pkt, unsigned int len, 
 *                                  char *interface)
 * Scope:  Global
 *
 * This method performs an ARP cache lookup for the specified destination 
 * IP address. If an ARP entry is found, it updates the destination MAC 
 * address in the Ethernet header of the packet and sends the packet. 
 * If no ARP entry is available, it queues the packet for later delivery 
 * and initiates an ARP request.
 *---------------------------------------------------------------------*/
void lookup_and_send_packet(struct sr_instance *sr, uint32_t dst_ip, uint8_t *pkt, unsigned int len, char *interface) {
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, dst_ip);
  if (entry) {
    memcpy(((sr_ethernet_hdr_t *)pkt)->ether_dhost, entry->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
    sr_send_packet(sr, pkt, len, interface);
    free(entry);
  } else {
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, dst_ip, pkt, len, interface);
    handle_arp_request(sr, req);
  }
}

/*--------------------------------------------------------------------- 
 * Method: send_icmp_echo_reply(struct sr_instance *sr, uint8_t *pkt, 
 *                                char *interface, int len)
 * Scope:  Global
 *
 * This method constructs and sends an ICMP Type 0 (echo reply) packet. 
 * It swaps the source and destination IP addresses in the IP header, 
 * prepares the necessary Ethernet, IP, and ICMP headers, and calculates 
 * the ICMP checksum. Finally, it either sends the packet or queues it 
 * for delivery based on the ARP cache lookup.
 *---------------------------------------------------------------------*/
void send_icmp_echo_reply(struct sr_instance *sr, uint8_t *pkt, char *interface, int len) {
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(pkt + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
  struct sr_if *my_int = sr_get_interface(sr, interface);

  /* Swap IP addresses */
  uint32_t temp_ip = ip_hdr->ip_dst;
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = temp_ip;

  /* Prepare headers */
  eth_header(eth_hdr, my_int, eth_hdr->ether_shost);
  ip_header(ip_hdr, ip_hdr->ip_src, ip_hdr->ip_dst, ntohs(ip_hdr->ip_len), 64, ip_protocol_icmp);

  /* Prepare ICMP header */
  icmp_hdr->icmp_type = 0;
  icmp_hdr->icmp_code = 0;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(ip_hdr->ip_len) - sizeof(sr_ip_hdr_t));

  print_hdr_eth(pkt);
  print_hdr_ip(pkt + sizeof(sr_ethernet_hdr_t));
  print_hdr_icmp(pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* look up arp cache and send packet */
  lookup_and_send_packet(sr, ip_hdr->ip_dst, pkt, len, interface);
}

/*--------------------------------------------------------------------- 
 * Method: send_icmp_error(int type, int code, struct sr_instance *sr, 
 *                          uint8_t *orig_pkt, char *interface)
 * Scope:  Global
 *
 * Constructs and sends an ICMP Type 3 (Destination Unreachable) error 
 * message. It prepares the necessary Ethernet, IP, and ICMP headers 
 * based on the original packet and sends the constructed error packet 
 * back to the source. The type and code parameters specify the reason 
 * for the error. The original packet data is included in the ICMP 
 * message for reference.
 *---------------------------------------------------------------------*/
void send_icmp_error(int type, int code, struct sr_instance *sr, uint8_t *orig_pkt, char *interface) {
  unsigned int plen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t);
  uint8_t *ret_pkt = malloc(plen);
  
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(ret_pkt);
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ret_pkt + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(ret_pkt + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));

  struct sr_if *in_if = sr_get_interface(sr, interface);

  /* Set up headers */
  eth_header(eth_hdr, in_if, ((sr_ethernet_hdr_t *)orig_pkt)->ether_shost);
  ip_header(ip_hdr, (code == 3) ? ((sr_ip_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t)))->ip_dst : in_if->ip, 
                    ((sr_ip_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t)))->ip_src, 
                    sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), 64, ip_protocol_icmp);

  /* Prepare ICMP Type 3 header */
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->next_mtu = 0;
  icmp_hdr->unused = 0;
  memcpy(icmp_hdr->data, orig_pkt + sizeof(sr_ethernet_hdr_t), sizeof(uint8_t) * ICMP_DATA_SIZE);
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  /* look up arp cache and send packet */
  lookup_and_send_packet(sr, ip_hdr->ip_dst, ret_pkt, plen, interface);

  free(ret_pkt);
}