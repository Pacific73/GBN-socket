#ifndef _gbn_h
#define _gbn_h

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>

/*----- Error variables -----*/
extern int h_errno;
extern int errno;

/*----- Protocol parameters -----*/
#define LOSS_PROB 1e-2    /* Loss probability                            */
#define CORR_PROB 1e-3    /* Corruption probability                      */
#define DATALEN   1024    /* Length of the payload                       */
#define N         1024    /* Max number of packets a single call to gbn_send can process */
#define TIMEOUT      1    /* Timeout to resend packets (1 second)        */

/*----- Packet types -----*/
#define SYN      0        /* Opens a connection                          */
#define SYNACK   1        /* Acknowledgement of the SYN packet           */
#define DATA     2        /* Data packets                                */
#define DATAACK  3        /* Acknowledgement of the DATA packet          */
#define FIN      4        /* Ends a connection                           */
#define FINACK   5        /* Acknowledgement of the FIN packet           */
#define RST      6        /* Reset packet used to reject new connections */

/*----- Self defined parameters -----*/
#define BUFFLEN   2048    /* Length of the buffer that prevents overflow */
#define INFOLEN      6    /* Length of first three vars in hdr           */
#define SEQ_SIZE    10    /* Max sliding window size                     */

/*----- Go-Back-n packet format -----*/
typedef struct {
	uint8_t  type;            /* packet type (e.g. SYN, DATA, ACK, FIN)     */
	uint8_t  seqnum;          /* sequence number of the packet              */
    uint16_t length;          /* length of header and payload               */
    uint16_t checksum;        /* header and payload checksum                */
    uint8_t data[DATALEN];    /* pointer to the payload                     */
} __attribute__((packed)) gbnhdr;

enum GBN_State {
    CLOSED=0,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    FIN_SENT,
    FIN_RCVD
};

enum WIN_Size {
    SLOW=1,
    MODERATE=2,
    FAST=4
};

typedef struct state_t {
    int fd;
    enum GBN_State state;

    int is_server;
    int flags;
    struct sockaddr remote;

    int syn_times;
    uint8_t cur_seq;
    uint8_t tail_seq;

    enum WIN_Size win_size;

    gbnhdr data_array[SEQ_SIZE];
    int acked[SEQ_SIZE];

    char last_buf[BUFFLEN * SEQ_SIZE];
    int last_len;

	/* TODO: Your state information could be encoded here. */

} state_t;

/* Socket related functions. */
void gbn_init();
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_listen(int sockfd, int backlog);
int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen);
int gbn_socket(int domain, int type, int protocol);
int gbn_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int gbn_close(int sockfd);
ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags);

ssize_t  maybe_recvfrom(int  s, char *buf, size_t len, int flags, \
            struct sockaddr *from, socklen_t *fromlen);

/* Some helper functions. */
uint16_t checksum(uint16_t *buf, int nwords);
int cmp_addr(struct sockaddr *s1, struct sockaddr *s2);
int window_cnt(uint8_t cur_seq, uint8_t tail_seq);

/* Time out handlers. */
void client_time_out();
void server_time_out();


#endif
