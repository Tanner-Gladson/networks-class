/*
 * transport.c 
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h> // Do I need this?
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


static const uint16_t FIXED_WINDOW_SIZE = 3072;

enum { 
    CSTATE_ESTABLISHED

};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num; /* Sending window initial sequence number (i think?)*/

    /* any other connection-wide global variables go here */
    uint16_t sending_window_size; /* Update after receiving datagram from peer */
    tcp_seq sending_window_last_ackd_byte; /* Update after receiving ACK from peer */
    uint32_t sending_window_num_unacked_bytes; /* Update after sending to peer */

    // TODO: why should I keep track of recieve window again?

    uint16_t recieving_window_size; /* Set during ctx initialization, send to peer with all packets */
    tcp_seq recieving_window_last_received_byte; /* Update after receiving from peer*/
} context_t;


static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;

    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);
    ctx->recieving_window_size = FIXED_WINDOW_SIZE;

    /* XXX: you should send a SYN packet here if is_active, or wait for one
     * to arrive if !is_active.  after the handshake completes, unblock the
     * application with stcp_unblock_application(sd).  you may also use
     * this to communicate an error condition back to the application, e.g.
     * if connection fails; to do so, just set errno appropriately (e.g. to
     * ECONNREFUSED, etc.) before calling the function.
     */

    if (is_active) {
        // send syn packet
        int success = send_syn(sd, ctx);
        if (success == -1) {
            errno = EHOSTUNREACH;
            stcp_unblock_application(sd);
        }

        // wait for syn ack
        success = wait_and_parse_syn_ack(sd, ctx);
        if (success == -1) {
            errno = ETIMEDOUT;
            stcp_unblock_application(sd);
        }

        // send ack
        success = send_ack(sd, ctx);
        if (success == -1) {
            errno = EHOSTUNREACH;
            stcp_unblock_application(sd);
        }

    } else {
        // wait for syn
        int success = wait_and_parse_syn(sd, ctx);
        if (success == -1) {
            errno = ETIMEDOUT;
            stcp_unblock_application(sd);
        }

        // send syn ack
        success = send_syn_ack(sd, ctx);
        if (success == -1) {
            errno = EHOSTUNREACH;
            stcp_unblock_application(sd);
        }

        // wait for ack
        success = wait_and_parse_ack(sd, ctx);
        if (success == -1) {
            errno = EHOSTUNREACH;
            stcp_unblock_application(sd);
        }
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

/* Helper Function */
int send_syn(mysocket_t sd, context_t *ctx) {
    // Create the packet
    STCPHeader datagram;
    datagram.th_seq = ctx->initial_sequence_num; /*seqx*/
    datagram.th_ack = 0;
    datagram.th_flags = TH_SYN;
    datagram.th_win = ctx->recieving_window_size;

    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    return 0;
}

int wait_and_parse_syn(mysocket_t sd, context_t* ctx) {
    uint8_t buffer[sizeof(STCPHeader) + STCP_MSS];
    read_STCP_datagram_from_network(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
    STCPHeader* datagram = buffer;

    if (!(datagram->th_flags & TH_SYN)) {
        return -1; // Should be a SYN
    }

    ctx->recieving_window_last_received_byte = datagram->th_seq; /*seqx*/
    ctx->sending_window_size = datagram->th_win;
    return 0;
}

int send_syn_ack(mysocket_t sd, context_t* ctx) {
    STCPHeader datagram;
    datagram.th_seq = ctx->initial_sequence_num; /*seqy*/
    datagram.th_ack = ctx->recieving_window_last_received_byte + 1; /*seqx + 1*/
    datagram.th_flags = TH_SYN | TH_ACK;
    datagram.th_win = ctx->recieving_window_size;

    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    return 0;
}

int wait_and_parse_syn_ack(mysocket_t sd, context_t *ctx) {
    uint8_t buffer[sizeof(STCPHeader) + STCP_MSS];
    read_STCP_datagram_from_network(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
    STCPHeader* datagram = buffer;

    if (!(datagram->th_flags & TH_SYN && datagram->th_flags & TH_ACK)) {
        return -1; // Should be a SYN and ACK
    }

    ctx->sending_window_last_ackd_byte = datagram->th_ack; /*seqx + 1*/
    ctx->recieving_window_last_received_byte = datagram->th_seq; /*seqy*/
    ctx->sending_window_size = datagram->th_win;
    return 0;
}

int send_ack(mysocket_t sd, context_t* ctx) {
    STCPHeader datagram;
    datagram.th_ack = ctx->recieving_window_last_received_byte + 1; /*seqy + 1*/
    datagram.th_flags = TH_ACK;
    datagram.th_win = ctx->recieving_window_size;
    
    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    return 0;
}

int wait_and_parse_ack(mysocket_t sd, context_t* ctx) {
    uint8_t buffer[sizeof(STCPHeader) + STCP_MSS];
    read_STCP_datagram_from_network(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
    STCPHeader* datagram = buffer;

    if (!(datagram->th_flags & TH_ACK)) {
        return -1; // Should be an ACK
    }

    ctx->sending_window_last_ackd_byte = datagram->th_ack; /*seqy + 1*/
    ctx->sending_window_size = datagram->th_win;
    return 0;
}

/* Returns size of bytes read (header + payload). Guaruntees valid-length header.
 Returns the header in host-byte order */
ssize_t read_STCP_datagram_from_network(mysocket_t sd, void *dst_buffer, size_t buffer_len) {
    assert(buffer_len >= sizeof(STCPHeader) + STCP_MSS);
    assert(dst_buffer);

    // TODO: Do I need to add a check that I've recieved an entire datagram?
    ssize_t num_read = stcp_network_recv(sd, dst_buffer, buffer_len);
    assert(num_read >= sizeof(STCPHeader));

    // Modify host byte order in place
    STCPHeader* datagram = (STCPHeader*) dst_buffer;
    datagram->th_seq = ntohl(datagram->th_seq);
    datagram->th_ack = ntohl(datagram->th_ack);
    datagram->th_win = ntohs(datagram->th_win);
    return num_read;
}

/* Sends an stcp datagram over the network, accepts STCP header in HOST BYTE order*/
void send_STCP_datagram_over_network(mysocket_t sd, const void *src, size_t src_len) {
    assert(src_len >= sizeof(STCPHeader));
    assert(src);

    // We need to convert byte orders
    uint8_t buf[src_len];
    memcpy(buf, src, src_len);

    STCPHeader* datagram = buf;
    datagram->th_seq = htonl(datagram->th_seq);
    datagram->th_ack = htonl(datagram->th_ack);
    datagram->th_win = htons(datagram->th_win);
    stcp_network_send(sd, &buf, src_len, NULL);
}

/* End helper functions */

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* init seq number bounded between [0, 255] */
    ctx->initial_sequence_num = (tcp_seq) (rand() >> 24);
#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    while (!ctx->done)
    {
        unsigned int event;

        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        /* check whether it was the network, app, or a close request */
        if (event & APP_DATA)
        {
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
        }

        if (event & NETWORK_DATA) {
            /* received data from STCP peer */
        }

        if (event & APP_CLOSE_REQUESTED) {

        }

        /* etc. */
    }
}


/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



