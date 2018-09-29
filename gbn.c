#include "gbn.h"

state_t s;
gbnhdr data_array[SEQ_SIZE];

void client_time_out() {
    if (s.state == SYN_SENT) {
        char syn[INFOLEN];
        gbnhdr *syn_hdr = (gbnhdr *)syn;
        syn_hdr->type = SYN;
        syn_hdr->seqnum = s.cur_seq;
        syn_hdr->length = INFOLEN;
        syn_hdr->checksum = 0;
        syn_hdr->checksum = checksum((uint16_t *)syn_hdr, INFOLEN);

        int send_size =
            sendto(s.fd, syn, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("client_time_out() send failed");
            return;
        }
        s.state = SYN_SENT;
        s.syn_times -= 1;
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
    s.cur_seq = 0;
    s.tail_seq = 0;
    s.win_size = SLOW;

    memset(data_array, 0, sizeof(data_array));
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

    char syn[INFOLEN];
    gbnhdr *syn_hdr = (gbnhdr *)syn;
    syn_hdr->type = SYN;
    syn_hdr->seqnum = seq;
    syn_hdr->length = INFOLEN;
    syn_hdr->checksum = 0;
    syn_hdr->checksum = checksum((uint16_t *)syn_hdr, INFOLEN);
    /* Make a SYN packet. */

    send_size = sendto(sockfd, syn, INFOLEN, 0, server, socklen);
    if (send_size != INFOLEN) {
        perror("gbn_connect() send syn failed");
        return -1;
    }
    s.state = SYN_SENT;
    s.syn_times -= 1;
    /* Send this SYN packet. */

    s.remote = *server;
    s.cur_seq = seq_synack;
    s.tail_seq = seq_synack;
    /* Update the state of socket. (for timeout func) */

    while (1) {
        alarm(TIMEOUT);
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_server, &_socklen);
        alarm(0);

        if (recv_size != INFOLEN) {
            perror("CONNECT RECV FAIL");
            continue;
        }
        if (s.syn_times <= 0)
            return -1;
        /* Set a timer.
         * If timeout, execute client_time_out() to resend a SYN.
         * Back here to find recv_size != INFOLEN, continue.
         * After trying 5 times, return as failed.
         */

        gbnhdr *pkt = (gbnhdr *)buf;
        uint16_t old_sum = pkt->checksum;
        pkt->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)pkt, INFOLEN);
        if (pkt->type != SYNACK)
            continue;
        if (pkt->seqnum != seq_synack)
            continue;
        if (old_sum != new_sum)
            continue;
        s.state = ESTABLISHED;
        break;
        /* Validate the SYNACK packet we just received.
         * Treat error packets as lost.
         */
    }

    s.cur_seq = (seq_synack + 1) % SEQ_SIZE;
    s.tail_seq = s.cur_seq;

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
    uint8_t seq, seq_synack;
    struct sockaddr _client;
    socklen_t _socklen = sizeof(_client);
    /* Init some variables. */

    while (1) {
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_client, &_socklen);
        if (recv_size != INFOLEN) {
            perror("ACCEPT RECV FAIL");
            continue;
        }
        gbnhdr *pkt = (gbnhdr *)buf;
        seq = pkt->seqnum;
        seq_synack = (seq + 1) % SEQ_SIZE;
        uint16_t old_sum = pkt->checksum;
        pkt->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)buf, INFOLEN);
        if (pkt->type != SYN)
            continue;
        if (new_sum != old_sum)
            continue;
        break;
    }
    /* Receive SYN and validate it. */

    if (s.state != CLOSED) {
        char rst[INFOLEN];
        gbnhdr *rst_hdr = (gbnhdr *)rst;
        rst_hdr->type = RST;
        rst_hdr->seqnum = seq_synack;
        rst_hdr->length = INFOLEN;
        rst_hdr->checksum = 0;
        rst_hdr->checksum = checksum((uint16_t *)rst_hdr, INFOLEN);

        send_size = sendto(sockfd, &rst, INFOLEN, 0, &_client, _socklen);
        if (send_size != INFOLEN)
            perror("gbn_accept() send rst failed");
        return -1;
    }
    /* We can only supports one sockfd. Reject this SYN and return rst. */

    s.state = SYN_RCVD;
    s.remote = _client;
    s.cur_seq = seq_synack;
    /* Update the state of socket. (for timeout func) */

    char synack[INFOLEN];
    gbnhdr *sa_hdr = (gbnhdr *)synack;
    sa_hdr->type = SYNACK;
    sa_hdr->seqnum = seq_synack;
    sa_hdr->length = INFOLEN;
    sa_hdr->checksum = 0;
    sa_hdr->checksum = checksum((uint16_t *)synack, INFOLEN);
    /* Make a SYNACK packet. */

    send_size = sendto(sockfd, &synack, INFOLEN, 0, &_client, _socklen);
    if (send_size != INFOLEN) {
        perror("gbn_accept() send synack failed");
        return -1;
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
    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    assert(s.state == ESTABLISHED);

    int has_frag = (int)len % DATALEN == 0 ? 0 : 1;
    int n_pkts = (int)len / DATALEN + has_frag;
    /* Calculate the number of packets to send. */

    ssize_t sent_len = 0;

    while(sent_len < (ssize_t)len) {

    }

    for (int i = 0; i < n_pkts; i++) {
        uint16_t pl_len = DATALEN;
        if (has_frag && i == n_pkts - 1)
            pl_len = (uint16_t)len % DATALEN;
        /* Determine length of payload. */

        while(1) {
        	// 
        }

        gbnhdr *pkt = &data_array[s.cur_seq];
        pkt->type = DATA;
        pkt->seqnum = s.cur_seq;
        pkt->length = pl_len + INFOLEN;
        pkt->checksum = 0;
        memcpy(pkt->data, buf + DATALEN * i, (size_t)pl_len);
        pkt->checksum = checksum((uint16_t *)&pkt, (int)pkt->length);
        /* Copy data to packet window. */

        int send_size = sendto(sockfd, pkt, (int)pkt->length, flags, &s.remote,
                               sizeof(s.remote));
        if (send_size != (int)pkt->length) {
            perror("gbn_send() send data failed");
            if(sent_len > 0) return sent_len;
            return -1;
        }
        sent_len += (ssize_t)pl_len;
    }

    return (-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {

    /* TODO: Your code here. */
    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    int recv_size;
    char _buf[BUFFLEN];
    struct sockaddr client;
    socklen_t socklen = sizeof(client);

    while (1) {
        recv_size =
            maybe_recvfrom(sockfd, _buf, BUFFLEN, flags, &client, &socklen);
        if (recv_size < 0)
            continue;
        gbnhdr *header = (gbnhdr *)_buf;
        uint8_t old_sum = header->checksum;
        header->checksum = 0;
        uint8_t new_sum = checksum((uint16_t *)header, (int)header->length);
        if (new_sum != old_sum)
            continue;
        if (s.state == ESTABLISHED)
            break;
        if (s.state == SYN_RCVD) {
            if (header->type == SYN) {
                char synack[INFOLEN];
                gbnhdr *sa_hdr = (gbnhdr *)synack;
                sa_hdr->type = SYN;
                sa_hdr->seqnum = (header->seqnum + 1) % SEQ_SIZE;
                sa_hdr->length = INFOLEN;
                sa_hdr->checksum = 0;
                sa_hdr->checksum = checksum((uint16_t *)sa_hdr, INFOLEN);

                while (1) {
                    int send_size = sendto(s.fd, synack, INFOLEN, 0, &s.remote,
                                           sizeof(s.remote));
                    if (send_size != INFOLEN) {
                        perror("CONNECT RESEND FAIL");
                        continue;
                    }
                    break;
                }
            } else if (header->type == DATA) {
                s.state = ESTABLISHED;
                break;
            } else {
                perror("error in recv syn_rcvd");
            }
        } else
            perror("error in recv s.state other than synrcvd and established");
    }

    gbnhdr *header = (gbnhdr *)_buf;

    /* Deal with window...*/

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
