#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
    struct sr_arpreq* req = sr->cache.requests;
    while (req != NULL) {
        struct sr_arpreq* next_req = req->next;
        handle_arpreq(sr, req);
        req = next_req;
    }
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *request) {

    // If the cache still doesn't have IP, we need to re-send
    struct sr_arpentry* entry = sr_arpcache_lookup(&(sr->cache), request->ip);
    if (entry) {
        // The cache has the IP, so we can send all of the packets waiting on it
        _send_queued_ip_packets(sr, request, entry);
        arpreq_destroy(sr, request);
        return;
    }


    time_t curtime = time(NULL);
    if (difftime(curtime, request->sent) < 1.0) {
        if (request->times_sent >= 5) {
            // Host cannot be reached
            _send_unreachable_to_queued_packets(sr, request);
            arpreq_destroy(sr, request);
            return;
        }
        _send_arp_request(sr, request);
        request->sent = curtime;
        request->times_sent++;
        return;
    }
    
}

void _send_arp_request(struct sr_instance *sr, struct sr_arpreq *request) {
    if (request->packets == NULL) {
        return; // No queued packets
    }
    
    const char broadcast_addr[ETHER_ADDR_LEN] = {255};
    char* interface_name = request->packets->iface;
    struct sr_if* interface = sr_get_interface(sr, interface_name);

    uint8_t arp_request[sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)];
    create_arp_packet(
        sr,
        arp_request,
        sizeof(arp_request),
        broadcast_addr,
        interface->addr, // TODO: Are interfaces storing in host-order? If so, change
        hston(arp_op_request),
        interface->addr, // TODO: Are interfaces storing in host-order? If so, change
        interface->ip, // TODO: Are interfaces storing in host-order? If so, change
        broadcast_addr,
        request->ip
    );

    sr_send_packet(sr, arp_request, sizeof(arp_request), interface_name);
}

void _send_unreachable_to_queued_packets(struct sr_instance *sr, struct sr_arpreq *request) {
    // Send ICMP type 3, code 1 (dest host unreachable) to the senders of each waiting packet
    for (struct sr_packet* packet = request->packets; packet != NULL; packet = packet->next) {
        // Extract the waiting frame
        sr_ethernet_hdr_t* waiting_frame_eth = packet->buf;
        sr_ip_hdr_t* waiting_frame_ip = packet->buf + sizeof(sr_ethernet_hdr_t);

        struct sr_if* interface = get_interface_from_eth(sr, waiting_frame_eth->ether_dhost);
        assert(interface);

        uint8_t icmp_reply[sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)];
        create_icmp_packet(sr,
            icmp_reply,
            sizeof(icmp_reply),
            waiting_frame_eth->ether_shost,
            interface->addr, /* TODO: If interface stores in host-byte, use hton? */
            interface->ip, /* TODO: Made my best guess here, TODO: If interfaces store in host-byte, convert to network */
            waiting_frame_ip->ip_src,
            0x03,
            0x01,
            waiting_frame_ip
        );

        sr_send_packet(sr, icmp_reply, sizeof(icmp_reply), interface->name);
    }
}

void _send_queued_ip_packets(struct sr_instance *sr, struct sr_arpreq *request, struct sr_arpentry* arp_entry) {
    for (struct sr_packet* packet = request->packets; packet != NULL; packet = packet->next) {
        sr_ethernet_hdr_t* frame = packet->buf;

        memcpy(frame->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
        memcpy(frame->ether_shost, this_router_mac, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, packet->len, packet->iface);
    }
}


/* Protocol Helper functions */

/* Create a complete ARP packet (ethernet and arp). Uses values as-is, does not change byte order*/
void create_arp_packet(
    struct sr_instance *sr, 
    sr_ethernet_hdr_t* buf, /* Buffer to be filled with packet */
    uint16_t len, /* Length of entire packet */
    char* ether_dhost, /* Destination Ethernet Address */
    char* ether_shost, /* Source Ethernet Address */
    unsigned short arp_op, /* ARP operation number */
    char* arp_sha, /* Sender Hardware Address */
    uint32_t arp_sip, /* Sender IP */
    char* arp_tha, /* Target Hardware Address */
    uint32_t arp_tip /* Target IP */
    ) 
{
    assert(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    memset(&buf, 0, len);

    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) buf;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));

    /* Fill out the fields of each header */

    // Ethernet
    memcpy(ethernet_hdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = htons(ethertype_arp);

    // ARP
    arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
    arp_hdr->ar_pro = htons(ethertype_ip);
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = 0x04;
    arp_hdr->ar_op = arp_op;

    memcpy(arp_hdr->ar_sha, arp_sha, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = arp_sip; 

    memcpy(arp_hdr->ar_tha, arp_tha, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = arp_tip;
}

/* Create a complete ICMP packet (ethernet, ip, icmp). Give most arguments in Network-Byte-Order. */
void create_icmp_packet(struct sr_instance *sr, 
    sr_ethernet_hdr_t* buf, /* Buffer to be overwritten with complete packet */
    uint16_t len, /* Length of entire buffer, give in host-byte order */
    char* ether_dhost, /* set to original packet’s ether_shost */
    char* ether_shost, /* set to outgoing interface’s addr */
    uint32_t ip_src, /* set to ip of our interface or outgoing interface based on whether the original packet was destined for us or not */
    uint32_t ip_dst, /* set to original packet’s ip_src */
    uint8_t icmp_type, /* ICMP type */
    uint8_t icmp_code, /* ICMP code*/
    uint8_t* icmp_data /* Optional. Null if echo reply, else original packet ip header */
    ) 
{
    /* Validate Buffer */
    assert(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    memset(&buf, 0, len);
    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) buf;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));
    sr_icmp_t3_hdr_t* icmp_hdr = (sr_icmp_t3_hdr_t*) (ip_hdr + sizeof(sr_ip_hdr_t));

    /* Fill out the fields of each header */

    // Ethernet
    memcpy(ethernet_hdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = htons(ethertype_ip);

    // IP
    ip_hdr->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
    if (ntohs(icmp_type) == 0) {
        ip_hdr->ip_off = 0x0000; // Don't set for echo replies
    } else {
        ip_hdr->ip_off = htons(IP_DF);
    }
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_p = ip_protocol_icmp;
    ip_hdr->ip_src = ip_src;
    ip_hdr->ip_dst = ip_dst;
    ip_hdr->ip_sum = htons(cksum(ip_hdr, sizeof(sr_ip_hdr_t)));
    
    // ICMP
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = htons(cksum(icmp_hdr, sizeof(icmp_hdr->icmp_type) + sizeof(icmp_hdr->icmp_code)));
    if (icmp_type != 0) {
        assert(icmp_data); // Required for packets which are not echo reply
        memcpy(icmp_hdr->data, icmp_data, ICMP_DATA_SIZE); 
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpentry *entry = NULL, *copy = NULL;

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }

    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }

    pthread_mutex_unlock(&(cache->lock));

    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }

    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }

    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));

        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));

    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            if (prev) {
                next = req->next;
                prev->next = next;
            }
            else {
                next = req->next;
                cache->requests = next;
            }

            break;
        }
        prev = req;
    }

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }

    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }

    pthread_mutex_unlock(&(cache->lock));

    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));

    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL;
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {
                if (prev) {
                    next = req->next;
                    prev->next = next;
                }
                else {
                    next = req->next;
                    cache->requests = next;
                }

                break;
            }
            prev = req;
        }

        struct sr_packet *pkt, *nxt;

        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }

        free(entry);
    }

    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }

    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));

    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;

    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);

    while (1) {
        sleep(1.0);

        pthread_mutex_lock(&(cache->lock));

        time_t curtime = time(NULL);

        int i;
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }

        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }

    return NULL;
}
