/**********************************************************************
 * file:  sr_router.c
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

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

  /*9
  Notes:
   - Use sr_send_packet() for sending a packet out an interface
  */

  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr, "Failed to cast ETHERNET header, insufficient length\n");
    return;
  }

  uint8_t* network_header = packet + sizeof(sr_ethernet_hdr_t);
  unsigned int new_len = len - sizeof(sr_ethernet_hdr_t);

  if (ethertype(packet) == ethertype_ip) {
    if (new_len < sizeof(sr_ip_hdr_t)) {
      fprintf(stderr, "Failed to cast IP header, insufficient length\n");
      return;
    }
    _sr_handle_ip_packet(sr, (sr_ip_hdr_t*) network_header, new_len);
  } else {
    if (new_len < sizeof(sr_arp_hdr_t)) {
      fprintf(stderr, "Failed to cast ARP header, insufficient length\n");
      return;
    }
    _sr_handle_arp_packet(sr, (sr_arp_hdr_t*) network_header, new_len);
  }

  // "Send ICMP messages based on certain conditions"
}

void _sr_handle_ip_packet(struct sr_instance* sr, sr_ip_hdr_t * packet/* lent */, unsigned int len)
{
  // Ignore packets with invalid IP checksums
  if (cksum(packet, len) != ntohl(packet->ip_sum)) {
    fprintf(stderr, "Failed to handle IP packet, invalid checksum\n");
    return;
  }
  
  // We ignore packets not targeted at this router
  if (ntohl(packet->ip_dst) not in hosts) {
    // Send ICMP type 3, code 0 (dest net unreachable)
    return;
  }
  
  // We handle ICMP requests seperately
  if (ip_protocol(packet) == ip_protocol_icmp) {
    unsigned int icmp_len = len - sizeof(sr_ip_hdr_t);
    if (icmp_len < sizeof(sr_icmp_hdr_t)) {
      fprintf(stderr, "Failed to cast ICMP header, insufficient length\n");
      return;
    }
    sr_icmp_hdr_t* icmp_header = packet + sizeof(sr_ip_hdr_t);
    
    // Ignore packets with invalid ICMP checksums
    if (cksum(icmp_header, icmp_len) != ntohl(icmp_header->icmp_sum)) {
      fprintf(stderr, "Failed to handle ICMP packet, invalid checksum\n");
      return;
    }

    // If the packet is ICMP Echo Request (type 8)
    //    ... Send an ICMP Echo reply (type 0) to the sending host
  }

  // Send (forward) IP packets
  // Don't forget to decrement TLL, check if 0, and update checksum
  // Queue as ARP request if not already in cache
}


void _sr_handle_arp_packet(struct sr_instance* sr, sr_arp_hdr_t* packet/* lent */, unsigned int len)
{
  /*
  pass arp packet

  // We ignore packets not targeted at this router
  // Check out  sr_arp_req_not_for_us()
  if (ntohl(packet->ar_tip) not in hosts) {
    return;
  }

  // We reply if it was a request
  if (ntohs(packet->ar_pro) == arp_op_request) {
    Send ARP reply
    return;
  }
  
  Cache ARP reply
  Send IP packets that were waiting on this reply
  Remove that ARP request from the queue (helper function somewhere)
  */  
}

/* Add any additional helper methods here & don't forget to also declare
them in sr_router.h.

If you use any of these methods in sr_arpcache.c, you must also forward declare
them in sr_arpcache.h to avoid circular dependencies. Since sr_router
already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
