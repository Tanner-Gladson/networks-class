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
    CSTATE_ESTABLISHED,
    CSTATE_ONLY_PEER_FINISHED,
    CSTATE_ONLY_SELF_FINISHED,
    CSTATE_BOTH_FINISHED
};    /* obviously you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /* TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num; /* Sending window initial sequence number (i think?)*/

    /* any other connection-wide global variables go here */
    uint16_t cwnd_size;               /* Max Size. Update after receiving datagram from peer */
    tcp_seq cwnd_last_ackd_byte;      /* Update after receiving ACK from peer */
    uint16_t cwnd_num_unacked_bytes;  /* Update after sending to peer and when recieve ACK */

    uint16_t rwnd_size; /* Set during ctx initialization, send to peer with all packets */
    tcp_seq rwnd_last_received_byte; /* Update after receiving from peer*/
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
    ctx->rwnd_size = FIXED_WINDOW_SIZE;
    ctx->cwnd_last_ackd_byte = ctx->initial_sequence_num; // Artificial

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
void handle_ack(context_t *ctx, STCPHeader* header) {
    tcp_seq ackd_byte = header->th_ack;
    tcp_seq num_ackd;

    // sometimes we can overflow the sequence space
    if (ackd_byte < ctx->cwnd_last_ackd_byte) {
        num_ackd = ackd_byte + (UINT32_MAX - ctx->cwnd_last_ackd_byte); 
    } else {
        num_ackd = ackd_byte - ctx->cwnd_last_ackd_byte;
    }
    
    // the right-hand pointer of sending window remains the same
    ctx->cwnd_num_unacked_bytes -= num_ackd;
    ctx->cwnd_last_ackd_byte += num_ackd;
    ctx->cwnd_size = header->th_win;
}

int send_syn(mysocket_t sd, context_t *ctx) {
    // Create the packet
    STCPHeader datagram; 
    datagram.th_seq = get_next_unsent_seq_num(ctx); /*seqx*/
    datagram.th_ack = 0;
    datagram.th_flags = TH_SYN;
    datagram.th_win = ctx->rwnd_size;

    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    ctx->cwnd_num_unacked_bytes += 1; // syn is one byte of seq space
    return 0;
}

int wait_and_parse_syn(mysocket_t sd, context_t* ctx) {
    uint8_t buffer[sizeof(STCPHeader) + STCP_MSS];
    read_STCP_datagram_from_network(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
    STCPHeader* datagram = buffer;

    if (!(datagram->th_flags & TH_SYN)) {
        return -1; // Should be a SYN
    }

    ctx->rwnd_last_received_byte = datagram->th_seq; /*seqx*/
    ctx->cwnd_size = datagram->th_win;
    return 0;
}

int send_syn_ack(mysocket_t sd, context_t* ctx) {
    STCPHeader datagram;
    datagram.th_seq = get_next_unsent_seq_num(ctx); /*seqy*/
    datagram.th_ack = ctx->rwnd_last_received_byte + 1; /*seqx + 1*/
    datagram.th_flags = TH_SYN | TH_ACK;
    datagram.th_win = ctx->rwnd_size;

    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    ctx->cwnd_num_unacked_bytes += 1; // syn is one byte of seq space
    return 0;
}

int wait_and_parse_syn_ack(mysocket_t sd, context_t *ctx) {
    uint8_t buffer[sizeof(STCPHeader) + STCP_MSS];
    read_STCP_datagram_from_network(sd, buffer, sizeof(STCPHeader) + STCP_MSS);
    STCPHeader* datagram = buffer;

    if (!(datagram->th_flags & TH_SYN && datagram->th_flags & TH_ACK)) {
        return -1; // Should be a SYN and ACK
    }

    ctx->rwnd_last_received_byte = datagram->th_seq; /*seqy*/
    handle_ack(ctx, datagram);
    return 0;
}

int send_ack(mysocket_t sd, context_t* ctx) {

    STCPHeader datagram;
    datagram.th_seq = get_next_unsent_seq_num(ctx);
    datagram.th_ack = ctx->rwnd_last_received_byte + 1; /*seqy + 1*/
    datagram.th_flags = TH_ACK;
    datagram.th_win = ctx->rwnd_size;
    
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

    ctx->cwnd_last_ackd_byte = datagram->th_ack; /*seqy + 1*/
    ctx->cwnd_size = datagram->th_win;
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
    stcp_network_send(sd, buf, src_len, NULL);
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
            handle_application_event(sd, ctx);
        }

        if (event & NETWORK_DATA) {
            handle_network_event(sd, ctx);
        }

        if (event & APP_CLOSE_REQUESTED) {
            handle_app_close_request(sd, ctx);
        }

        /* etc. */
    }
}

/* HELPER FUNCTIONS */

void handle_application_event(mysocket_t sd, context_t *ctx) {
    // Keep payload and buffer contigious
    uint8_t     buffer[sizeof(STCPHeader) + STCP_MSS] = {0};
    STCPHeader* header_ptr = (STCPHeader*) buffer;
    uint8_t*    payload_ptr = buffer + sizeof(STCPHeader);

    size_t payload_size = stcp_app_recv(sd, payload_ptr, STCP_MSS);

    /* don't want to overload our peer's window */
    while (payload_size > ctx->cwnd_size - ctx->cwnd_num_unacked_bytes) {
        stcp_wait_for_event(sd, NETWORK_DATA, NULL);
        handle_network_event(sd, ctx);
    }

    header_ptr->th_seq = get_next_unsent_seq_num(ctx);
    header_ptr->th_win = ctx->rwnd_size;
    header_ptr->th_flags = 0;

    send_STCP_datagram_over_network(sd, header_ptr, sizeof(STCPHeader) + payload_size);
    ctx->cwnd_num_unacked_bytes += payload_size;
}

void handle_network_event(mysocket_t sd, context_t *ctx) {
    // Read the data in from the network
    uint8_t     buffer[sizeof(STCPHeader) + STCP_MSS];
    STCPHeader* header_ptr = (STCPHeader*) buffer;
    uint8_t*    payload_ptr = buffer + sizeof(STCPHeader);
    ssize_t total_size = read_STCP_datagram_from_network(sd, buffer, sizeof(buffer));

    if (header_ptr->th_flags & TH_ACK) {
        handle_ack(ctx, header_ptr);
    }

    bool_t requires_ack = 0;
    ssize_t payload_size = total_size - sizeof(STCPHeader);
    if (payload_size > 0) {
        stcp_app_send(sd, payload_ptr, payload_size);
        ctx->rwnd_last_received_byte += payload_size;
        requires_ack = 1;
    }

    if (header_ptr->th_flags & TH_FIN) {
        update_ctx_after_peer_finish(ctx);
        ctx->rwnd_last_received_byte += 1;
        requires_ack = 1;
    }

    if (requires_ack) {
        send_ack(sd, ctx);
    }
}

void handle_app_close_request(mysocket_t sd, context_t *ctx) {
    // Create the packet
    STCPHeader datagram; 
    datagram.th_seq = get_next_unsent_seq_num(ctx);
    datagram.th_ack = 0;
    datagram.th_flags = TH_FIN;
    datagram.th_win = ctx->rwnd_size;

    // Send over network
    send_STCP_datagram_over_network(sd, &datagram, sizeof(datagram));
    ctx->cwnd_num_unacked_bytes += 1; // syn is one byte of seq space
    update_ctx_after_self_finish(ctx);
    return 0;
}

void update_ctx_after_peer_finish(context_t *ctx) {
    if (ctx->connection_state == CSTATE_ONLY_SELF_FINISHED) {
        ctx->connection_state = CSTATE_BOTH_FINISHED;
        ctx->done = 1;
    } else {
        ctx->connection_state = CSTATE_ONLY_PEER_FINISHED;
    }
}

void update_ctx_after_self_finish(context_t *ctx) {
    if (ctx->connection_state == CSTATE_ONLY_PEER_FINISHED) {
        ctx->connection_state = CSTATE_BOTH_FINISHED;
        ctx->done = 1;
    } else {
        ctx->connection_state = CSTATE_ONLY_SELF_FINISHED;
    }
}

tcp_seq get_next_unsent_seq_num(context_t *ctx) {
    return ctx->cwnd_last_ackd_byte + ctx->cwnd_num_unacked_bytes; 
}

/* END HELPER FUNCTIONS */


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



