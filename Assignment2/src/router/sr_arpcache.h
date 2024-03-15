/*  This file defines an ARP cache, which is made of two structures: an ARP
    request queue, and ARP cache entries. The ARP request queue holds data about
    an outgoing ARP cache request and the packets that are waiting on a reply
    to that ARP cache request. The ARP cache entries hold IP->MAC mappings and
    are timed out every SR_ARPCACHE_TO seconds.
 */

#ifndef SR_ARPCACHE_H
#define SR_ARPCACHE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sr_if.h"

#define SR_ARPCACHE_SZ    100
#define SR_ARPCACHE_TO    15.0

struct sr_packet {
    uint8_t *buf;               /* A raw Ethernet frame, presumably with the dest MAC empty */
    unsigned int len;           /* Length of raw Ethernet frame */
    char *iface;                /* The outgoing interface */
    struct sr_packet *next;
};

struct sr_arpentry {
    unsigned char mac[6];
    uint32_t ip;                /* IP addr in network byte order */
    time_t added;
    int valid;
};

struct sr_arpreq {
    uint32_t ip;
    time_t sent;                /* Last time this ARP request was sent. You
                                   should update this. If the ARP request was
                                   never sent, will be 0. */
    uint32_t times_sent;        /* Number of times this request was sent. You
                                   should update this. */
    struct sr_packet *packets;  /* List of pkts waiting on this req to finish */
    struct sr_arpreq *next;
};

struct sr_arpcache {
    struct sr_arpentry entries[SR_ARPCACHE_SZ];
    struct sr_arpreq *requests;
    pthread_mutex_t lock;
    pthread_mutexattr_t attr;
};

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip);

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. The packet argument should not be
   freed by the caller.

   A pointer to the ARP request is returned; it should be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                         uint32_t ip,
                         uint8_t *packet,               /* borrowed */
                         unsigned int packet_len,
                         char *iface);

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip);

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry);

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache);

/* You shouldn't have to call these methods--they're already called in the
   starter code for you. The init call is a constructor, the destroy call is
   a destructor, and a cleanup thread times out cache entries every 15
   seconds. */

int   sr_arpcache_init(struct sr_arpcache *cache);
int   sr_arpcache_destroy(struct sr_arpcache *cache);
void *sr_arpcache_timeout(void *cache_ptr);
void handle_arpreq(struct sr_instance *, struct sr_arpreq *);

/* IMPORTANT: To avoid circular dependencies, do a forward declaration of any
methods from other files that you need to use. For example, if your sr_arpcache
needs to use methods from sr_router, declare those methods here too.

Note: having sr_arpcache import sr_router.h will cause a circular dependency
since sr_router already imports sr_arpcache.h! - KM */

/* sr_utils.h */
/* list any declarations that you need here */

/* sr_router.h */
/* list any declarations that you need here */

/* sr_if.h */
struct sr_if *sr_get_interface(struct sr_instance *, const char *);
struct sr_if *get_interface_from_ip(struct sr_instance *, uint32_t);
struct sr_if *get_interface_from_eth(struct sr_instance *, uint8_t *);

#endif
