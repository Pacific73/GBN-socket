#include "gbn.h"

state_t s;

void client_time_out() {
    if (s.state == SYN_SENT) {
        char syn[4];
        gbnhdr *syn_hdr = (gbnhdr *)syn;
        syn_hdr->type = SYN;
        syn_hdr->seqnum = s.syn_start;
        syn_hdr->checksum = 0;
        syn_hdr->checksum = checksum((uint16_t *)syn_hdr, 4);

        while (1) {
            int send_size =
                sendto(s.fd, syn, 4, 0, &s.remote, sizeof(s.remote));
            if (send_size != 4) {
                perror("CONNECT RESEND FAIL");
                continue;
            }
            s.state = SYN_SENT;
            s.syn_times -= 1;
            break;
        }
    } else if (s.state == ESTABLISHED) {
    }
}

void server_time_out() {
    if (s.state == ESTABLISHED) {
        /*repeat synack*/
    }
}

void gbn_init() {
    s.fd = -1;
    s.state = CLOSED;
    s.is_server = 0;
    memset(&s.remote, 0, sizeof(s.remote));
    s.syn_times = 5;
    s.syn_start = -1;
}

int gbn_socket(int domain, int type, int protocol) {

    /*----- Randomizing the seed. This is used by the rand() function -----*/
    srand((unsigned)time(0));

    /* TODO: Your code here. */
    gbn_init();
    s.fd = socket(domain, type, protocol);
    return s.fd;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen) {

    /* TODO: Your code here. */
    int res = bind(sockfd, server, socklen);
    return res;
}

int gbn_listen(int sockfd, int backlog) {

    /* TODO: Your code here. */
    if (backlog != 1) {
        errno = EINVAL;
        return -1;
    }

    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    signal(SIGALRM, server_time_out);
    s.is_server = 1;
    /* If gbn_listen(), then it's a server. */

    return 0;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen) {

    /* TODO: Your code here. */
    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    signal(SIGALRM, client_time_out);
    /* If gbn_connect(), then it's a client. */

    int send_size, recv_size;
    char buf[BUFFLEN];
    uint8_t seq = rand() % SEQ_SIZE;
    uint8_t seq_synack = (seq + 1) % SEQ_SIZE;
    struct sockaddr _server;
    socklen_t _socklen = sizeof(_server);
    /* Init some variables, generate random start seqnum. */

    char syn[4];
    gbnhdr *syn_hdr = (gbnhdr *)syn;
    syn_hdr->type = SYN;
    syn_hdr->seqnum = seq;
    syn_hdr->checksum = 0;
    syn_hdr->checksum = checksum((uint16_t *)syn_hdr, 4);
    /* Make a SYN packet. */

    while (1) {
        send_size = sendto(sockfd, syn, 4, 0, server, socklen);
        if (send_size != 4) {
            perror("CONNECT SEND FAIL");
            continue;
        }
        s.state = SYN_SENT;
        s.syn_times -= 1;
        break;
    }
    /* Send this SYN packet. */

    s.remote = *server;
    s.syn_start = seq;
    /* Update the state of socket. (for timeout func) */

    while (1) {
        alarm(TIMEOUT);
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_server, &_socklen);
        alarm(0);

        if (recv_size != 4) {
            perror("CONNECT RECV FAIL");
            continue;
        }
        if (s.syn_times <= 0)
            return -1;
        /* Set a timer.
         * If timeout, execute client_time_out() to resend a SYN.
         * Back here to find recv_size != 4, continue.
         * After trying 5 times, return as failed.
         */

        gbnhdr *pkt = (gbnhdr *)buf;
        uint16_t old_sum = pkt->checksum;
        pkt->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)pkt, 4);
        if (pkt->type == SYNACK && pkt->seqnum == seq_synack &&
            old_sum == new_sum) {
            s.state = ESTABLISHED;
            break;
        }
        /* Validate the SYNACK packet we just received.
         * Treat error packets as lost.
         */
    }

    return 0;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen) {
    /* TODO: Your code here. */
    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    int recv_size, send_size;
    char buf[BUFFLEN];
    uint8_t seq;
    struct sockaddr _client;
    socklen_t _socklen = sizeof(_client);
    /* Init some variables. */

    while (1) {
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_client, &_socklen);
        if (recv_size != 4) {
            perror("ACCEPT RECV FAIL");
            continue;
        }
        gbnhdr *pkt = (gbnhdr *)buf;
        seq = pkt->seqnum;
        uint16_t old_sum = pkt->checksum;
        pkt->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)buf, INFOLEN);
        if (pkt->type == SYN && new_sum == old_sum)
            break;
    }
    /* Receive SYN and validate it. */

    if (s.state != CLOSED) {
        char rst[4];
        gbnhdr *rst_hdr = (gbnhdr *)rst;
        rst_hdr->type = RST;
        rst_hdr->seqnum = (seq + 1) % SEQ_SIZE;
        rst_hdr->checksum = 0;
        rst_hdr->checksum = checksum((uint16_t *)rst_hdr, 4);

        while (1) {
            send_size = sendto(sockfd, &rst, 4, 0, &_client, _socklen);
            if (send_size != 4) {
                perror("ACCEPT SEND RST FAIL");
                continue;
            }
            return -1;
        }
    }
    /* We can only supports one sockfd. Reject this SYN and return rst. */

    s.state = SYN_RCVD;
    s.remote = _client;
    /* Update the state of socket. (for timeout func) */

    char synack[4];
    gbnhdr *sa_hdr = (gbnhdr *)synack;
    sa_hdr->type = SYNACK;
    sa_hdr->seqnum = seq + 1;
    sa_hdr->checksum = 0;
    sa_hdr->checksum = checksum((uint16_t *)synack, 4);
    /* Make a SYNACK packet. */

    while (1) {
        send_size = sendto(sockfd, &synack, 4, 0, &_client, _socklen);
        if (send_size != 4) {
            perror("ACCEPT SEND SYNACK FAIL");
            continue;
        }
        break;
    }
    /* Send a SYNACK. */

    return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags) {

    /* TODO: Your code here. */

    /* Hint: Check the data length field 'len'.
     *       If it is > DATALEN, you will have to split the data
     *       up into multiple packets - you don't have to worry
     *       about getting more than N * DATALEN.
     */

    return (-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {

    /* TODO: Your code here. */

    return (-1);
}

int gbn_close(int sockfd) {

    /* TODO: Your code here. */

    return (-1);
}

ssize_t maybe_recvfrom(int s, char *buf, size_t len, int flags,
                       struct sockaddr *from, socklen_t *fromlen) {

    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB * RAND_MAX) {

        /*----- Receiving the packet -----*/
        int retval = recvfrom(s, buf, len, flags, from, fromlen);

        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB * RAND_MAX) {
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len - 1) * rand() / (RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buf[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buf[index] = c;
        }

        return retval;
    }
    /*----- Packet lost -----*/
    return (len); /* Simulate a success */
}

uint16_t checksum(uint16_t *buf, int nwords) {
    uint32_t sum;

    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

int cmp_addr(struct sockaddr *s1, struct sockaddr *s2) {
    if (s1->sa_family != s2->sa_family)
        return -1;
    return strcmp(s1->sa_data, s2->sa_data);
}
