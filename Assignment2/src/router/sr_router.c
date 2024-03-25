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

    printf("\n\n*** -> Received packet of length %d \n", len);
    print_hdrs(packet, len);

    if (len < sizeof(sr_ethernet_hdr_t))
    {
        fprintf(stderr, "Failed to cast ETHERNET header, insufficient length\n");
        return;
    }

    if (ethertype(packet) == ethertype_ip)
    {
        printf("Handling IP packet\n");
        _sr_handle_ip_packet(sr, packet, len, interface);
    }
    else if (ethertype(packet) == ethertype_arp) {
        printf("Handling ARP packet\n");
        _sr_handle_arp_packet(sr, packet, len, interface);
    } else {
        printf("Discarding packet, unrecognized ethertype\n");
    }

}

void _sr_handle_ip_packet(struct sr_instance *sr, uint8_t *buf, unsigned int len, const char* interface_name)
{
    /* Check that IP header is completetly valid */    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
    {
        fprintf(stderr, "Failed to cast IP header, insufficient length\n");
        return;
    }

    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) buf;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

    // TODO: Cksum() is always returning 1's ?
    // printf("Provided checksum of incoming packet: %d\n", ip_hdr->ip_sum);
    // printf("Calculated checksum of incoming packet: %d\n", cksum(ip_hdr, sizeof(sr_ip_hdr_t)));
    // if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != ip_hdr->ip_sum)
    // {
    //     fprintf(stderr, "Failed to handle IP packet, invalid checksum\n");
    //     return;
    // }

    /* Do not process expired IP packets */
    ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
    if (ip_hdr->ip_ttl == 0) {
        printf("Received IP packet had TTL 1, returning error (ICMP type 11, code 0)\n");
        struct sr_if* interface = sr_get_interface(sr, interface_name);
        assert(interface);

        uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)] = {0};
        create_icmp_packet(sr,
                icmp_reply,
                sizeof(icmp_reply),
                ether_hdr->ether_shost,
                interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                interface->ip, /* TODO: If interfaces store in host-byte, convert to network */
                ip_hdr->ip_src,
                11,
                0,
                ip_hdr
            );
        printf("Sending reply: \n");
        print_hdrs(icmp_reply, sizeof(icmp_reply));
        sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
        return;
    }
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    if (_in_interfaces(sr, ip_hdr->ip_dst)) {
        /* Interfaces don't support TCP/UDP, return ICMP type 3, code 3 (port unreachable)*/
        if (ip_protocol((uint8_t *) ip_hdr) == 0x06 || ip_protocol((uint8_t *) ip_hdr) == 0x11) {
            printf("Detected TCP or UDP packet targeted at router, unsupported (ICMP type 3, code 3)\n");
            struct sr_if* interface = sr_get_interface(sr, interface_name);
            assert(interface);

            uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)] = {0};
            create_icmp_packet(sr,
                icmp_reply,
                sizeof(icmp_reply),
                ether_hdr->ether_shost,
                interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                interface->ip, /* TODO: If interfaces store in host-byte, convert to network */
                ip_hdr->ip_src,
                0x03,
                0x03,
                ip_hdr
            );
            printf("Sending reply: \n");
            print_hdrs(icmp_reply, sizeof(icmp_reply));
            sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
            return;
        }

        /* We only respond to echo replies */
        if (ip_protocol((uint8_t *) ip_hdr) == ip_protocol_icmp)
        {
            printf("Packet is ICMP protocol\n");
            /* Check if valid ICMP header */
            unsigned int icmp_len = len - sizeof(sr_ip_hdr_t);
            if (icmp_len < sizeof(sr_icmp_hdr_t))
            {
                fprintf(stderr, "Failed to cast ICMP header, insufficient length\n");
                return;
            }
            sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            
            // TODO: Checksum broken?
            // if (cksum(icmp_hdr, sizeof(sr_icmp_hdr_t)) != icmp_hdr->icmp_sum)
            // {
            //     fprintf(stderr, "Failed to handle ICMP packet, invalid checksum\n");
            //     return;
            // }

            /* If the packet is ICMP Echo Request (type 8) for our interfaces, we reply with echo */
            if (icmp_hdr->icmp_type == 0x08) 
            {
                printf("Echo request recieved, echoing reply (ICMP type 0)\n");
                struct sr_if* interface = sr_get_interface(sr, interface_name);
                assert(interface);

                uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)] = {0};
                create_icmp_packet(sr,
                    icmp_reply,
                    sizeof(icmp_reply),
                    ether_hdr->ether_shost,
                    interface->addr, /* TODO: If interface stores in host-byte, use hton? */
                    interface->ip, /* TODO: If interfaces store in host-byte, convert to network */
                    ip_hdr->ip_src,
                    0x00,
                    0x00,
                    NULL
                );
                printf("Sending reply: \n");
                print_hdrs(icmp_reply, sizeof(icmp_reply));
                sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
                return;
            }
        }
    }

    /* Send ICMP type 3, code 0 (dest net unreachable) */
    if (!_is_known_host(sr, ip_hdr->ip_dst))
    {
        printf("Host not found, dest network unreachable (ICMP type 3, code 0)\n");
        struct sr_if* interface = sr_get_interface(sr, interface_name);
        assert(interface);

        uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)] = {0};
        create_icmp_packet(sr,
            icmp_reply,
            sizeof(icmp_reply),
            ether_hdr->ether_shost,
            interface->addr, /* TODO: If interface stores in host-byte, use hton? */
            interface->ip, /* TODO: If interfaces store in host-byte, convert to network */
            ip_hdr->ip_src,
            0x03,
            0x00,
            ip_hdr
        );

        sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
        printf("Sending reply: \n");
        print_hdrs(icmp_reply, sizeof(icmp_reply));
        return;
    }


    /* We can send if already in ARP cache, else queue for sending */
    char iface_name[sr_IFACE_NAMELEN];
    uint32_t longest_prefix = _find_longest_prefix(sr, ip_hdr->ip_dst, iface_name);
    struct sr_if* interface = sr_get_interface(sr, iface_name);

    struct in_addr temp = {
        .s_addr = longest_prefix
    };
    printf("Found longest matching prefix of %s\n", inet_ntoa(temp));
    printf("With interface %s\n", interface->name);
    assert(interface);

    struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), longest_prefix);
    if (arp_entry) {
        printf("Found existing ARP cache entry, forwarding...\n");        
        memcpy(ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(ether_hdr->ether_shost, interface->addr, ETHER_ADDR_LEN); // TODO: If interface stores in host-order, change this
        sr_send_packet(sr, (uint8_t*) ether_hdr, len, interface->name);
        return;
    } else {
        printf("Did not find existing ARP cache entry, queueing...\n");
        sr_arpcache_queuereq(
            &(sr->cache),
            ip_hdr->ip_dst,
            (uint8_t*) ether_hdr,
            len,
            interface->name
        );
        return;
    }
}

void _sr_handle_arp_packet(struct sr_instance *sr, uint8_t *buf, unsigned int len, const char *interface_name)
{
    assert(interface_name);
    assert(buf);
    assert(sr);
    
    if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
        fprintf(stderr, "Failed to cast ARP header, insufficient length\n");
        return;
    }
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*) buf;
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t));

    /* Ignore ARP packets not targeted at this router TODO:  */
    if (!_in_interfaces(sr, arp_hdr->ar_tip))
    {
        printf("Not targeted to this router's interfaces, discarding\n");
        return;
    }

    /* Cache ARP reply, sweepreqs will handle queued msgs on next run */
    if (ntohs(arp_hdr->ar_op) == arp_op_reply)
    {
        printf("Packet is ARP reply, inserting information into the ARP cache\n");
        sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
        return;
    }

    /* We were the target, so we reply to ARP request. Send back to same device */
    if (ntohs(arp_hdr->ar_op) == arp_op_request)
    {
        printf("Packet is ARP request, sending an ARP reply to iface %s\n", interface_name);
        struct sr_if* interface = sr_get_interface(sr, interface_name);
        assert(interface);

        uint8_t arp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)] = {0};
        create_arp_packet(
            sr,
            arp_reply,
            sizeof(arp_reply),
            ether_hdr->ether_shost,
            interface->addr, // TODO: Are interfaces storing in host-order? If so, change
            htons(arp_op_reply),
            interface->addr, // TODO: Are interfaces storing in host-order? If so, change
            interface->ip, // TODO: Are interfaces storing in host-order? If so, change
            ether_hdr->ether_shost,
            arp_hdr->ar_sip
        );

        printf("created the ARP reply, attempting to send the following:\n");
        print_hdrs(arp_reply, sizeof(arp_reply));
        sr_send_packet(sr, arp_reply, sizeof(arp_reply), interface->name);
        return;
    }
    printf("No supported ARP protocol detected. Discarding\n");
}

/* Check if the IP is in this router's known hosts (including interfaces). Provide in network-byte order */
int _is_known_host(struct sr_instance *sr, uint32_t packet_ip) {
    
    for (struct sr_rt* route = sr->routing_table; route != NULL; route = route->next) {
        uint32_t masked_packet_ip = packet_ip & (route->mask.s_addr);
        if (route->dest.s_addr == masked_packet_ip) {
            return 1;
        }
    }
    return 0;
}

/* Check if the IP is in this router's known hosts (including interfaces). Provide in network byte order 
    Returns 0 if no destination IP matches. Fills out the interface_name output-argument */
uint32_t _find_longest_prefix(struct sr_instance *sr, uint32_t packet_ip, char* interface_name) {
    uint32_t longest_prefix = 0;
    uint32_t largest_mask = 0;
    
    for (struct sr_rt* route = sr->routing_table; route != NULL; route = route->next) {
        uint32_t masked_packet_ip = packet_ip & (route->mask.s_addr);

        /* The masked IP must match the destination and have longest mask */
        if (route->dest.s_addr == masked_packet_ip) {
            if (route->mask.s_addr > largest_mask) {
                largest_mask = route->mask.s_addr;
                longest_prefix = route->dest.s_addr;
                memcpy(interface_name, route->interface, sr_IFACE_NAMELEN);
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
