# README for Assignment 2: Router

Name:

JHED:

---

**DESCRIBE YOUR CODE AND DESIGN DECISIONS HERE**

This will be worth 10% of the assignment grade.

Some guiding questions:
- What files did you modify (and why)? What logic did you implement in each file

I modified the sr_arpcache.c and sr_router.c files. The sr_arpcache.c file contains all of the driver code for immediately responding to received frames. On the other hand, sr_arpcache.c contains the code for sending out ARP requests, maintaining the ARP cache, and it has some helper functions for creating frames.

arp_cache also contains helper functions for sending IP packets contained within an ARP request.

- What helper method did you write (and why)? What logic did you implement in each method?

* _sr_handle_ip_packet()
We need to handle the recieved IP packets. This function holds the driver logic for handling recieved IP packets. This extensively implements the logic for ICMP reponses, ICMP error, ARP cache searching, general IP packet forwarding, and more. It uses some helper functions found in sr_arpcache.c

* _sr_handle_arp_packet()
We need to handle the recieved ARP packets. This function holds the driver logic for handling recieved ARP packets. This implements the logic for handling ARP requests and ARP responses. It adds entries to the ARP cache.

* _is_known_host()
Check if the IP is in this router's known hosts (including interfaces), allowing us to send ICMP error if the host is unknown

* _find_longest_prefix()
We need to find the longest prefix out of the known hosts so that we can send ARP requests out of the correct interface. 

* _in_interfaces()
Check if this IP is in our router's interfaces so that we can ignore ICMP echo requests not targeted at us.

* sr_arpcache_sweepreqs
We need to send ARP requests, maybe multiple times. This method iterates over each queued ARP request and calls a helper function to process the request.

* handle_arpreq
Implements functionality for either a. sending another ARP request or b. sending host-unreachable errors to all waiting IP packets. Utilizes a few helper functions. Decrements the time-to-live of each ARP request in queue.

* _send_arp_request
The helper function which actually generates and sends the ARP request over the appropriate interface. Cleanly contains sending code.

* _send_unreachable_to_queued_packets
We need to inform the hosts that their IP packets could not be sent because the host could not be found. This function generates an ICMP error packet for each queued IP packet contanied in the expired ARP request.

* _send_queued_ip_packets
After we recieve an ARP reply, we need to forward all of the IP packets waiting on that request. This helper function is called from within sr_router.c. For each ip_packet in the linked list, the function creates an IP packet and sends it.

* create_arp_packet
Create a complete ARP packet (ethernet and arp) from a lent buffer. This helper allowed me to succinctly create ARP packets in the driver code.

* create_icmp_packet
Create a complete ICMP packet (ethernet, ip, icmp) from a lent buffer. This helper allowed me to succinctly create ICMP packets in the driver code.

- What problems or challenges did you encounter?
My multipass VM would irrecoverably break every time my laptop fell asleep or turned off. Recreating it each time was tedious.

The requirements were extensive and packed with small, easy-to-miss details. I had to spend a few hours reading the requirements and provided files before I had a shaky understanding of what I needed to do.

It was challenging identifying if something was stored in network-byte or host-byte order.

I faced a stack smashing error for a while because I was using the wrong length variable during a memcpy.

The most challenging part was identifying how I should be setting the fields of the headers. There were many components of information flowing around, and it wasn't always straightforward. Identifying when (and when not) to copy to IP headers was difficult.

