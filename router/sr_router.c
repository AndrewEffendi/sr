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

  if (check_eth_len(packet, len)) {

    if (ethertype(packet) == ethertype_arp) {
      print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));
      printf("Received ARP packet.\n");
      handle_arp(sr, packet, interface, len);

    } else if (ethertype(packet) == ethertype_ip) {
      print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));
      printf("Received IP packet.\n");
      handle_ip(sr, packet, len, interface);

    } else {

      printf("Unknown packet received. Dropping.\n");
      return;

    }
  } else {

    printf("Packet invalid.\n");

  }

}/* end sr_ForwardPacket */

/* ----------------------------------------------- */

/*--------------------------------------------------------------------- 
 * checkers: Return 1 if valid, 0 if not.
 *---------------------------------------------------------------------*/
/* Common checksum validation function */
static int validate_checksum(uint8_t *packet, unsigned int offset, unsigned int length, uint16_t old_cksm) {
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
 * handle_arp
 *
 * Given either an ARP request or ARP reply, handle the packet appropriately.
 * If ARP opcode is unrecognized, drop the packet.
 *---------------------------------------------------------------------*/
void handle_arp(struct sr_instance *sr, uint8_t *pkt, char *interface, unsigned int len) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(pkt);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

    /* Get the interface associated with the incoming ARP request's target IP */
    struct sr_if *my_if = sr_get_interface(sr, interface);

    if (my_if) {
        if (htons(arp_hdr->ar_op) == arp_op_request) {
            printf("Received ARP request.\n");
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
            printf("Received ARP reply.\n");
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
            printf("Unrecognized ARP Opcode. Dropping.\n");
            return;
        }
    } else {
        printf("No matching interface found. Dropping packet.\n");
    }
}

