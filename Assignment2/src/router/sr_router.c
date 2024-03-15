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

// TODO: Make sure that every time you edit a frame its in Network Byte-Order

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
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != ntohl(ip_hdr->ip_sum))
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
        if (_in_interfaces(sr, ip_hdr->ip_dst)) {
            
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
        if (cksum(icmp_header, sizeof(sr_icmp_hdr_t)) != ntohl(icmp_header->icmp_sum))
        {
            fprintf(stderr, "Failed to handle ICMP packet, invalid checksum\n");
            return;
        }

        /* If the packet is ICMP Echo Request (type 8) for our interfaces, we reply with echo */
        if (!_in_interfaces(sr, ip_hdr->ip_dst) && icmp_header->icmp_code == 0x08) 
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

    /* Forward all other IP packets unles they're expired */
    ip_hdr->ip_ttl -= hston(ntohs(ip_hdr->ip_ttl) - 1);
    if (ntohs(ip_hdr->ip_ttl) == 0) {
        const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t outgoing[len];
        create_icmp_packet(sr,
                        outgoing,
                        len,
                        ether_hdr->ether_shost,
                        ip_hdr->ip_id,
                        ip_hdr->ip_src,
                        0x11,
                        0x00
        );

        // TODO: Is it OK to get the interface via MAC address, or should I do it via IP?
        char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, ether_hdr->ether_shost);
        sr_send_packet(sr, outgoing, len, interface);
    }
    ip_hdr->ip_sum = hston(cksum(ip_hdr, sizeof(sr_ip_hdr_t)));

    // TODO: We need to search for longest prefix before forwarding?

    /* We can send if already in ARP cache, else queue for sending */
    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr->ip_dst);
    if (arp_entry) {
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

void _sr_handle_arp_packet(struct sr_instance *sr, sr_ethernet_hdr_t *ether_hdr, unsigned int len)
{
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
        fprintf(stderr, "Failed to cast ARP header, insufficient length\n");
        return;
    }
    sr_arp_hdr_t *arp_hdr = ether_hdr + sizeof(sr_ethernet_hdr_t);

    // We ignore packets not targeted at this router
    // TODO: Check out sr_arp_req_not_for_us()
    if (!_in_interfaces(sr, arp_hdr->ar_tip))
    {
        return;
    }

    /* We were the target, so we reply to ARP request */
    if (ntohs(arp_hdr->ar_pro) == arp_op_request)
    {
        /* We need to find the receiving interface */
        // TODO: how?
        struct sr_if* interface = get_interface_from_ip(sr, arp_hdr->ar_tip);
        
        uint8_t arp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
        create_arp_packet(
            sr,
            arp_reply,
            sizeof(arp_reply),
            ether_dhost = ether_hdr->ether_shost,
            ether_shost = /* set to receiving interface’s addr */
            arp_op = hston(arp_op_reply),
            arp_sha = /* set to receiving interface’s addr */
            arp_sip = /* set to receiving interface’s addr */
            arp_tha = ether_hdr->ether_shost,
            arp_tip = arp_hdr->ar_sip
        );

        sr_send_packet(sr, arp_reply, sizeof(arp_reply), interface);
        return;
    }

    if (ntohs(arp_hdr->ar_pro) == arp_op_reply)
    {
        // Cache ARP reply, sweepreqs will handle queued msgs on next run
        sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        return;
    }
}

/* Check if the IP is in this router's interfaces. Does not convert bytes orders */
int _in_interfaces(struct sr_instance *sr, const uint32_t ip) {
    struct sr_if* interface = get_interface_from_ip(sr, ip);
    if (interface) {
        return 1;
    }
    return 0;
}
