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

    // Create our ARP ethernet packet and extract pointers to the headers
    const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t outgoing[len];
    const char broadcast_addr[ETHER_ADDR_LEN] = {255};
    
    create_arp_request(
        sr, 
        outgoing, 
        len, 
        arp_op_request,
        broadcast_addr,
        request->ip
    );

    sr_send_packet(sr, outgoing, len, interface);
}

void _send_unreachable_to_queued_packets(struct sr_instance *sr, struct sr_arpreq *request) {
    // Send ICMP type 3, code 1 (dest host unreachable) to the senders of each waiting packet
    for (struct sr_packet* packet = request->packets; packet != NULL; packet = packet->next) {

        // Extract the waiting frame
        sr_ethernet_hdr_t* waiting_frame_eth = packet->buf;
        sr_ip_hdr_t* waiting_frame_ip = packet->buf + sizeof(sr_ethernet_hdr_t);

        // Create our frame and get references to each layer's header
        const uint16_t len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
        uint8_t outgoing[len];
        create_icmp_packet(sr, 
            outgoing, 
            len, 
            waiting_frame_eth->ether_shost, 
            waiting_frame_ip->ip_id, 
            waiting_frame_ip->ip_src, 
            0x03, 
            0x01
        );

        // TODO: Is it OK to get the interface via MAC address, or should I do it via IP?
        char interface[sr_IFACE_NAMELEN] = get_interface_from_eth(sr, waiting_frame_eth->ether_shost);
        sr_send_packet(sr, outgoing, len, interface);
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
void create_arp_packet(
    struct sr_instance *sr, 
    sr_ethernet_hdr_t* buf, 
    uint16_t len, 
    unsigned short arp_op,
    char* target_eth_addr,
    uint32_t target_ip_addr
    ) 
{
    assert(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    memset(&buf, 0, len);

    sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*) buf;
    sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*) (buf + sizeof(sr_ethernet_hdr_t));

    /* Fill out the fields of each header */

    // Ethernet
    
    memcpy(ethernet_hdr->ether_dhost, target_eth_addr, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, this_router_mac_addr, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = ethertype_arp;

    // ARP
    arp_hdr->ar_hrd = arp_hrd_ethernet;
    arp_hdr->ar_pro = arp_hrd_ethernet;
    arp_hdr->ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ar_pln = ETHER_ADDR_LEN;
    arp_hdr->ar_op = arp_op;

    memcpy(arp_hdr->ar_sha, this_router_mac_addr, ETHER_ADDR_LEN);
    arp_hdr->ar_sip = this_router_ip_addr;

    memcpy(arp_hdr->ar_tha, target_eth_addr, ETHER_ADDR_LEN);
    arp_hdr->ar_tip = target_ip_addr;
}


void create_icmp_packet(struct sr_instance *sr, 
    sr_ethernet_hdr_t* buf, 
    uint16_t len, 
    char* ether_dhost, 
    uint16_t ip_id, 
    uint32_t ip_dest,
    uint8_t icmp_type, 
    uint8_t icmp_code) 
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
    memcpy(ethernet_hdr->ether_shost, this_router_mac_addr, ETHER_ADDR_LEN);
    ethernet_hdr->ether_type = ethertype_ip;

    // IP
    ip_hdr->ip_len = len - sizeof(sr_ethernet_hdr_t);
    ip_hdr->ip_id = ip_id;
    ip_hdr->ip_ttl = 64;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    ip_hdr->ip_src = this_router_ip;
    ip_hdr->ip_dst = ip_dest;
    
    // ICMP
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t)); // TODO: this appears to be incorrect given Piazza posts
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
