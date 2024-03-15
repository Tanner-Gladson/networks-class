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
    if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != ntohs(ip_hdr->ip_sum))
    {
        fprintf(stderr, "Failed to handle IP packet, invalid checksum\n");
        return;
    }

    /* Send ICMP type 3, code 0 (dest net unreachable) */
    if (!_is_known_host(sr, ip_hdr->ip_dst))
    {
        struct sr_if* interface = get_interface_from_eth(sr, ether_hdr->ether_dhost);
        assert(interface);

        uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)];
        create_icmp_packet(sr,
            icmp_reply,
            sizeof(icmp_reply),
            ether_hdr->ether_shost,
            interface->addr, /* TODO: If interface stores in host-byte, use hton? */
            interface->ip, /* TODO: Made my best guess here, TODO: If interfaces store in host-byte, convert to network */
            ip_hdr->ip_src,
            0x03,
            0x00,
            ip_hdr
        );

        sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
        return;
    }

    /* Interfaces don't support TCP/UDP, return ICMP type 3, code 3 (port unreachable)*/
    if (ip_protocol(ip_hdr) == 0x06 || ip_protocol(ip_hdr) == 0x11) {
        if (_in_interfaces(sr, ip_hdr->ip_dst)) {
            struct sr_if* interface = get_interface_from_eth(sr, ether_hdr->ether_dhost);
            assert(interface);

            uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)];
            create_icmp_packet(sr,
                icmp_reply,
                sizeof(icmp_reply),
                ether_hdr->ether_shost,
                interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                interface->ip, /* TODO: Made my best guess here, TODO: If interfaces store in host-byte, convert to network */
                ip_hdr->ip_src,
                0x03,
                0x03,
                ip_hdr
            );
            sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
            return;
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
        if (cksum(icmp_header, sizeof(sr_icmp_hdr_t)) != ntohs(icmp_header->icmp_sum))
        {
            fprintf(stderr, "Failed to handle ICMP packet, invalid checksum\n");
            return;
        }

        /* If the packet is ICMP Echo Request (type 8) for our interfaces, we reply with echo */
        if (_in_interfaces(sr, ip_hdr->ip_dst) && icmp_header->icmp_code == 0x08) 
        {
            struct sr_if* interface = get_interface_from_eth(sr, ether_hdr->ether_dhost);
            assert(interface);

            uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)];
            create_icmp_packet(sr,
                icmp_reply,
                sizeof(icmp_reply),
                ether_hdr->ether_shost,
                interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                interface->ip, /* TODO: Made my best guess here, TODO: If interfaces store in host-byte, convert to network */
                ip_hdr->ip_src,
                0x00,
                0x00,
                NULL
            );
            sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
        }
    }

    /* Forward all other IP packets unless they're expired */
    ip_hdr->ip_ttl -= hston(ntohs(ip_hdr->ip_ttl) - 1);
    if (ntohs(ip_hdr->ip_ttl) == 0) {
        struct sr_if* interface = get_interface_from_eth(sr, ether_hdr->ether_dhost);
        assert(interface);

        uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)];
        create_icmp_packet(sr,
                icmp_reply,
                sizeof(icmp_reply),
                ether_hdr->ether_shost,
                interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                interface->ip, /* TODO: Made my best guess here, TODO: If interfaces store in host-byte, convert to network */
                ip_hdr->ip_src,
                11,
                0,
                ip_hdr
            );
        sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
    }
    ip_hdr->ip_sum = hston(cksum(ip_hdr, sizeof(sr_ip_hdr_t)));

    /* We can send if already in ARP cache, else queue for sending */
    uint32_t longest_prefix = _find_longest_prefix(sr, ip_hdr->ip_dst);
    struct sr_if* interface = get_interface_from_ip(sr, ntohl(longest_prefix));

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), longest_prefix);
    if (arp_entry) {
        memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); // TODO: If interface stores in host-order, change this
        sr_send_packet(sr, ether_hdr, len, interface->name);
    } else {
        sr_arpcache_queuereq(
            &(sr->cache),
            ip_hdr->ip_dst,
            ether_hdr,
            len,
            interface->name
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

    /* Ignore ARP packets not targeted at this router */
    if (!_in_interfaces(sr, arp_hdr->ar_tip))
    {
        return;
    }

    /* Cache ARP reply, sweepreqs will handle queued msgs on next run */
    if (ntohs(arp_hdr->ar_pro) == arp_op_reply)
    {
        sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        return;
    }

    /* We were the target, so we reply to ARP request. Send back to same device */
    if (ntohs(arp_hdr->ar_pro) == arp_op_request)
    {
        struct sr_if* interface = get_interface_from_eth(sr, ether_hdr->ether_dhost);
        assert(interface);

        uint8_t arp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
        create_arp_packet(
            sr,
            arp_reply,
            sizeof(arp_reply),
            ether_hdr->ether_shost,
            interface->addr, // TODO: Are interfaces storing in host-order? If so, change
            hston(arp_op_reply),
            interface->addr, // TODO: Are interfaces storing in host-order? If so, change
            interface->ip, // TODO: Are interfaces storing in host-order? If so, change
            ether_hdr->ether_shost,
            arp_hdr->ar_sip
        );

        sr_send_packet(sr, arp_reply, sizeof(arp_reply), interface->name);
        return;
    }
}

/* Check if the IP is in this router's known hosts (including interfaces). Provide in network-byte order */
int _is_known_host(struct sr_instance *sr, uint32_t packet_ip) {
    packet_ip = ntohl(packet_ip);
    
    for (struct sr_rt* route = sr->routing_table; route != NULL; route = route->next) {
        uint32_t masked_packet_ip = packet_ip & (route->mask.s_addr);
        if (route->dest.s_addr == masked_packet_ip) {
            return 1;
        }
    }
    return 0;
}

/* Check if the IP is in this router's known hosts (including interfaces). Provide in network byte order 
    Returns 0 if no destination IP matches. */
uint32_t _find_longest_prefix(struct sr_instance *sr, uint32_t packet_ip) {
    packet_ip = ntohl(packet_ip);
    uint32_t longest_prefix = 0;
    uint32_t largest_mask = 0;
    
    for (struct sr_rt* route = sr->routing_table; route != NULL; route = route->next) {
        uint32_t masked_packet_ip = packet_ip & (route->mask.s_addr);

        /* The masked IP must match the destination and have longest mask */
        if (route->dest.s_addr == masked_packet_ip) {
            if (route->mask.s_addr > largest_mask) {
                largest_mask = route->mask.s_addr;
                longest_prefix = route->dest.s_addr;
            }
        }
    }
    return longest_prefix;
}

/* Check if the IP is in this router's interfaces. Provide in network byte order */
int _in_interfaces(struct sr_instance *sr, const uint32_t ip) {
    struct sr_if* interface = get_interface_from_ip(sr, ip);
    if (interface) {
        return 1;
    }
    return 0;
}
