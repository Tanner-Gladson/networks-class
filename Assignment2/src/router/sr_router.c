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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /*9
    Notes:
     - Use sr_send_packet() for sending a packet out an interface
    */

    if (len < sizeof(sr_ethernet_hdr_t))
    {
        fprintf(stderr, "Failed to cast ETHERNET header, insufficient length\n");
        return;
    }

    if (ethertype(packet) == ethertype_ip)
    {
        _sr_handle_ip_packet(sr, (sr_ethernet_hdr_t *)packet, len);
    }
    else
    {

        _sr_handle_arp_packet(sr, (sr_ethernet_hdr_t *)packet, len);
    }

    // "Send ICMP messages based on certain conditions"
}

void _sr_handle_ip_packet(struct sr_instance *sr, sr_ethernet_hdr_t *ether_hdr, unsigned int len)
{
    /* Check that IP header is completetly valid */    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    {
        fprintf(stderr, "Failed to cast IP header, insufficient length\n");
        return;
    }
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(ether_hdr + sizeof(sr_ethernet_hdr_t));
    if (cksum(ip_hdr, len) != ntohl(ip_hdr->ip_sum))
    {
        fprintf(stderr, "Failed to handle IP packet, invalid checksum\n");
        return;
    }

    /* Send ICMP type 3, code 0 (dest net unreachable) */
    if (ntohl(ip_hdr->ip_dst) not in known hosts)
    {
        const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t outgoing[len];
        create_icmp_packet(sr,
                        outgoing,
                        len,
                        ether_hdr->ether_shost,
                        ip_hdr->ip_id,
                        ip_hdr->ip_src,
                        0x03,
                        0x00
        );

        // TODO: Is it OK to get the interface via MAC address, or should I do it via IP?
        char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, ether_hdr->ether_shost);
        sr_send_packet(sr, outgoing, len, interface);
        return;
    }

    /* Interfaces don't support TCP/UDP, return ICMP type 3, code 3 (port unreachable)*/
    if (ip_protocol(ip_hdr) == 0x06 || ip_protocol(ip_hdr) == 0x11) {
        if (ip_hdr->ip_dst is one of routers interfaces) {
            
            const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
            uint8_t outgoing[len];
            create_icmp_packet(sr,
                            outgoing,
                            len,
                            ether_hdr->ether_shost,
                            ip_hdr->ip_id,
                            ip_hdr->ip_src,
                            0x03,
                            0x03
            );

            // TODO: Is it OK to get the interface via MAC address, or should I do it via IP?
            char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, ether_hdr->ether_shost);
            sr_send_packet(sr, outgoing, len, interface); 
        }
    }

    /* Handle ICMP requests seperately */
    if (ip_protocol(ip_hdr) == ip_protocol_icmp)
    {
        /* Check if valid ICMP header */
        unsigned int icmp_len = len - sizeof(sr_ip_hdr_t);
        if (icmp_len < sizeof(sr_icmp_hdr_t))
        {
            fprintf(stderr, "Failed to cast ICMP header, insufficient length\n");
            return;
        }
        sr_icmp_hdr_t *icmp_header = ip_hdr + sizeof(sr_ip_hdr_t);
        if (cksum(icmp_header, icmp_len) != ntohl(icmp_header->icmp_sum))
        {
            fprintf(stderr, "Failed to handle ICMP packet, invalid checksum\n");
            return;
        }

        /* If the packet is ICMP Echo Request (type 8) for our interfaces, we reply with echo */
        if (ntohl(ip_hdr->ip_dst) not in our interface IPs && icmp_header->icmp_code == 0x08) 
        {
            const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
            uint8_t outgoing[len];
            create_icmp_packet(sr,
                            outgoing,
                            len,
                            ether_hdr->ether_shost,
                            ip_hdr->ip_id,
                            ip_hdr->ip_src,
                            0x00,
                            0x00
            );

            // TODO: Is it OK to get the interface via MAC address, or should I do it via IP?
            char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, ether_hdr->ether_shost);
            sr_send_packet(sr, outgoing, len, interface);
        }
    }

    /* Forward all other IP packets */
    ip_hdr->ip_ttl -= hston(ntohs(ip_hdr->ip_ttl) - 1);
    ip_hdr->ip_sum = hston(cksum(ip_hdr, len - sizeof(sr_ethernet_hdr_t)));

    /* We can send if already in ARP cache, else queue for sending */
    sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
    if (arpentry) {
        memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(ether_hdr->ether_shost, this_router_mac, ETHER_ADDR_LEN);

        // TODO: how do I use the interface?
        char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, arp_entry->mac);
        sr_send_packet(sr, ether_hdr, len, interface);
    } else {
        // TODO: how do I use the interface?
        char interface[sr_IFACE_NAMELEN] = get_interface_from_ip(sr, ip_hdr->ip_dst);
        sr_arpcache_queuereq(
            &(sr->cache),
            ip_hdr->ip_dst,
            ether_hdr,
            len,
            interface
        );
    }
}

void _sr_handle_arp_packet(struct sr_instance *sr, sr_ethernet_hdr_t *packet, unsigned int len)
{
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
        fprintf(stderr, "Failed to cast ARP header, insufficient length\n");
        return;
    }
    sr_arp_hdr_t *arp_hdr = packet + sizeof(sr_ethernet_hdr_t);

    // We ignore packets not targeted at this router
    // Check out  sr_arp_req_not_for_us()
    if (arp_hdr->ar_tip not in our interface IPs)
    {
        return;
    }

    // We reply after recieving ARP request
    if (arp_hdr->ar_pro == arp_op_request)
    {
        const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t outgoing[len];
        create_arp_request(
            sr,
            outgoing,
            len,
            arp_op_reply,
            arp_hdr->ar_sha,
            arp_hdr->ar_sip);
        sr_send_packet(sr, outgoing, len, interface);
        return;
    }

    if (ntohs(arp_hdr->ar_pro) == arp_op_reply)
    {
        // Cache ARP reply, sweepreqs will handle queued msgs on next run
        sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        return;
    }
}
