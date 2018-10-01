#include "gbn.h"

state_t s;
gbnhdr empty;

void client_time_out() {
    printf("timeout: s.state = %d\n", s.state);
    if (s.state == SYN_SENT) {
        /* Timeout after the client sends SYN.
         * Resend a SYN, decrease the times for trying.
         */
        printf("SYN timeout! left times: %d\n", s.syn_times);

        char syn[INFOLEN];
        gbnhdr *syn_hdr = (gbnhdr *)syn;
        syn_hdr->type = SYN;
        syn_hdr->seqnum = s.cur_seq;
        syn_hdr->length = INFOLEN;
        syn_hdr->checksum = 0;
        syn_hdr->checksum = checksum((uint16_t *)syn_hdr, INFOLEN / 2);

        int send_size =
            sendto(s.fd, syn, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("client_time_out() send failed");
            return;
        }
        
        if (s.syn_times > 0) {
            s.syn_times -= 1;
            alarm(TIMEOUT);
        } else s.state = CLOSED;

    } else if (s.state == ESTABLISHED) {
        /* Timeout after the client sends a DATA pkt.
         * Resend Go-Back-N pkts. Restart the timer.
         * Switch to SLOW mode.
         */

        s.win_size = SLOW;
        for (int i = 0; i < s.win_size; i++) {
            gbnhdr *header = &s.data_array[((int)s.cur_seq + i) % SEQ_SIZE];
            if (header->length == 0)
                continue;
            int send_size = sendto(s.fd, header, DATALEN + INFOLEN, s.flags,
                                   &s.remote, sizeof(s.remote));
            if (send_size != DATALEN + INFOLEN) {
                i -= 1;
                continue;
            }
            if (i == 0) {
                if (s.data_times > 0) {
                    s.data_times -= 1;
                    alarm(TIMEOUT);
                    return;
                }
                s.state = CLOSED;
            }
        }
    } else if (s.state == FIN_SENT) {
        char fin[INFOLEN];
        gbnhdr *fin_hdr = (gbnhdr *)fin;
        fin_hdr->type = FIN;
        fin_hdr->seqnum = s.cur_seq;
        fin_hdr->length = INFOLEN;
        fin_hdr->checksum = 0;
        fin_hdr->checksum = checksum((uint16_t *)fin_hdr, INFOLEN / 2);
        /* Make a FIN pkt. */

        int send_size =
            sendto(s.fd, fin, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("client_time_out() send FIN failed");
            return;
        }

        if (s.fin_times > 0) {
            s.fin_times -= 1;
            alarm(TIMEOUT);
        } else s.state = CLOSED;

    } else {
        perror("client_time_out() error");
    }
}

void server_time_out() {
    if (s.state == FIN_SENT) {
        char fin[INFOLEN];
        gbnhdr *fin_hdr = (gbnhdr *)fin;
        fin_hdr->type = FIN;
        fin_hdr->seqnum = s.cur_seq;
        fin_hdr->length = INFOLEN;
        fin_hdr->checksum = 0;
        fin_hdr->checksum = checksum((uint16_t *)fin_hdr, INFOLEN / 2);
        /* Make a FIN pkt. */

        int send_size =
            sendto(s.fd, fin, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("client_time_out() send FIN failed");
            return;
        }

        if (s.fin_times > 0) {
            s.fin_times -= 1;
            alarm(TIMEOUT);
        } else s.state = CLOSED;

    } else {
        perror("server_time_out() error");
    }
}

void gbn_init() {
    s.fd = -1;
    s.state = CLOSED;
    s.is_server = 0;
    memset(&s.remote, 0, sizeof(s.remote));
    s.syn_times = 5;
    s.data_times = 5;
    s.fin_times = 5;
    s.cur_seq = 0;
    s.tail_seq = 0;
    s.win_size = SLOW;

    memset(s.data_array, 0, sizeof(gbnhdr) * SEQ_SIZE);
    memset(s.acked, 0, sizeof(int) * SEQ_SIZE);
    memset(s.last_buf, 0, sizeof(s.last_buf));
    s.last_len = 0;

    memset(&empty, 0, sizeof(empty));
}

int gbn_socket(int domain, int type, int protocol) {

    /*----- Randomizing the seed. This is used by the rand() function -----*/
    // srand((unsigned)time(0));

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

    struct sigaction alarmact;
    bzero(&alarmact, sizeof(alarmact));
    alarmact.sa_handler = server_time_out;
    alarmact.sa_flags = 0;

    sigaction(SIGALRM, &alarmact, NULL);
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

    struct sigaction alarmact;
    bzero(&alarmact, sizeof(alarmact));
    alarmact.sa_handler = client_time_out;
    alarmact.sa_flags = 0;

    sigaction(SIGALRM, &alarmact, NULL);
    /* If gbn_connect(), then it's a client. */

    int send_size, recv_size;
    char buf[BUFFLEN];
    uint8_t seq = rand() % SEQ_SIZE;
    struct sockaddr _server;
    socklen_t _socklen = sizeof(_server);
    /* Init some variables, generate random start seqnum. */

    char syn[INFOLEN];
    gbnhdr *syn_hdr = (gbnhdr *)syn;
    syn_hdr->type = SYN;
    syn_hdr->seqnum = seq;
    syn_hdr->length = INFOLEN;
    syn_hdr->checksum = 0;
    syn_hdr->checksum = checksum((uint16_t *)syn, INFOLEN / 2);
    printf("gbn_connect() checksum:%hu\n", syn_hdr->checksum);
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
    s.cur_seq = seq;
    s.tail_seq = seq;
    /* Update the state of socket. (for timeout func) */

    printf("gbn_connect() send SYN\n");

    while (1) {
        alarm(TIMEOUT);
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_server, &_socklen);
        if(s.state == CLOSED)
        	return -1;

        if (recv_size != INFOLEN) {
            perror("gbn_connect() recvfrom failed");
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
        uint16_t new_sum = checksum((uint16_t *)pkt, INFOLEN / 2);

        if (pkt->type != SYNACK)
            continue;
        if (pkt->seqnum != seq)
            continue;
        if (old_sum != new_sum)
            continue;

        alarm(0);
        s.state = ESTABLISHED;

        printf("gbn_connect() recv SYNACK\n");
        break;
        /* Validate the SYNACK packet we just received.
         * Treat error packets as lost.
         */
    }

    s.cur_seq = (seq + 1) % SEQ_SIZE;
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
    uint8_t seq;
    struct sockaddr _client;
    socklen_t _socklen = sizeof(_client);
    /* Init some variables. */

    while (1) {
        recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &_client, &_socklen);
        if (recv_size != INFOLEN) {
            perror("gbn_accept() recv failed");
            continue;
        }

        gbnhdr *pkt = (gbnhdr *)buf;
        seq = pkt->seqnum;
        uint16_t old_sum = pkt->checksum;
        pkt->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)buf, INFOLEN / 2);
        if (pkt->type != SYN)
            continue;
        if (new_sum != old_sum)
            continue;
        break;
    }
    /* Receive SYN and validate it. */
    printf("gbn_accept() recv SYN\n");

    if (s.state != CLOSED) {
        char rst[INFOLEN];
        gbnhdr *rst_hdr = (gbnhdr *)rst;
        rst_hdr->type = RST;
        rst_hdr->seqnum = seq;
        rst_hdr->length = INFOLEN;
        rst_hdr->checksum = 0;
        rst_hdr->checksum = checksum((uint16_t *)rst_hdr, INFOLEN / 2);

        send_size = sendto(sockfd, &rst, INFOLEN, 0, &_client, _socklen);
        if (send_size != INFOLEN)
            perror("gbn_accept() send rst failed");
        printf("gbn_accept() send RST\n");
        return -1;
    }
    /* We can only supports one sockfd. Reject this SYN and return rst. */

    s.state = SYN_RCVD;
    s.remote = _client;
    s.cur_seq = (seq + 1) % SEQ_SIZE;
    /* Update the state of socket. (for timeout func) */

    char synack[INFOLEN];
    gbnhdr *sa_hdr = (gbnhdr *)synack;
    sa_hdr->type = SYNACK;
    sa_hdr->seqnum = seq;
    sa_hdr->length = INFOLEN;
    sa_hdr->checksum = 0;
    sa_hdr->checksum = checksum((uint16_t *)synack, INFOLEN / 2);
    /* Make a SYNACK packet. */

    send_size = sendto(sockfd, &synack, INFOLEN, 0, &_client, _socklen);
    if (send_size != INFOLEN) {
        perror("gbn_accept() send SYNACK failed");
        return -1;
    }
    printf("gbn_accept() send SYNACK\n");
    /* Send a SYNACK. */

    return s.fd;
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
    printf("gbn_send(): n_pkts = %d\n", n_pkts);
    /* Calculate the number of packets to send. */

    ssize_t sent_len = 0;
    int sent_n = 0;

    while (1) {
        /* First, send as many pkts as we can.
         * Second, recv ack to push sliding window.
         */
        printf("gbn_send() ---------------------------\n");

        int cnt = 0;
        if (sent_len < (ssize_t)len &&
            (cnt = window_cnt(s.cur_seq, s.tail_seq)) < s.win_size) {
            /* If we haven't done sending,
             * and available slots in sending window...
             */
            printf("gbn_send() can send: %d - %d = %d pkts\n", s.win_size, cnt,
                   s.win_size - cnt);

            alarm(TIMEOUT);

            for (int i = cnt; i < s.win_size; i++) {
                int payload_len = DATALEN;
                if (has_frag && (sent_n + i) == n_pkts - 1)
                    payload_len = (int)len % DATALEN;
                /* Determine the length of payload. */

                gbnhdr *pkt = &s.data_array[((int)s.cur_seq + i) % SEQ_SIZE];
                pkt->type = DATA;
                pkt->seqnum = (s.cur_seq + (uint8_t)i) % SEQ_SIZE;
                pkt->length = (uint16_t)payload_len + INFOLEN;
                pkt->checksum = 0;
                memcpy(pkt->data, buf + sent_len, (size_t)payload_len);
                pkt->checksum =
                    checksum((uint16_t *)pkt, (INFOLEN + DATALEN) / 2);
                /* Copy data to packet window. */

                int send_size = sendto(sockfd, pkt, INFOLEN + DATALEN, flags,
                                       &s.remote, sizeof(s.remote));
                printf("gbn_send() send_size = %d | payload_len = %hu | "
                       "checksum: %hu\n",
                       send_size, pkt->length - INFOLEN, pkt->checksum);
                if (send_size != INFOLEN + DATALEN) {
                    perror("gbn_send() send data failed");
                    if (sent_len > 0)
                        return sent_len;
                    return -1;
                }

                sent_len += (ssize_t)payload_len;
                sent_n += 1;
                s.tail_seq = (s.tail_seq + 1) % SEQ_SIZE;
            }
        }

        char buf[BUFFLEN];
        struct sockaddr client;
        socklen_t socklen = sizeof(client);

        int recv_size =
            maybe_recvfrom(sockfd, buf, BUFFLEN, 0, &client, &socklen);
        if (recv_size != INFOLEN)
            continue;
        // check source!

        gbnhdr *header = (gbnhdr *)buf;
        uint16_t old_sum = header->checksum;
        header->checksum = 0;
        uint16_t new_sum = checksum((uint16_t *)header, INFOLEN / 2);
        if (header->type != DATAACK)
            continue;
        if (new_sum != old_sum)
            continue;

        uint8_t ackseq = header->seqnum;
        uint8_t q_front = s.cur_seq;
        uint8_t q_tail = s.tail_seq;
        if (q_tail < q_front)
            q_tail += SEQ_SIZE;
        if (ackseq < q_front)
            ackseq += SEQ_SIZE;

        printf("gbn_send() [%hhu, %hhu](%hhu) recv ACK: %hhu\n", s.cur_seq,
               (s.cur_seq + (uint8_t)s.win_size - 1) % SEQ_SIZE, s.tail_seq,
               header->seqnum);
        printf("gbn_send() q [%hhu, %hhu] ackseq:%hhu\n", q_front, q_tail,
               ackseq);

        if (s.data_array[ackseq % SEQ_SIZE].length == 0)
            continue;
        /* If no content in the cell,
         * ignore it.
         */

        assert(ackseq >= q_front);
        alarm(0);
        s.data_times = 5;
        /* Received ack after q_front, cancel the alarm. */

        for (uint8_t i = q_front; i <= ackseq; i++)
            s.acked[i % SEQ_SIZE] = 1;
        /* Acknowledge all cells before ackseq. */

        uint8_t push_pos;
        for (push_pos = q_front;; push_pos++) {
            uint8_t index = push_pos % SEQ_SIZE;
            if (s.acked[index] == 0)
                break;
            s.acked[index] = 0;
            s.data_array[index] = empty;
        }

        /* Find next cell waiting for ACK.
         * Clean old cells.
         */

        if (q_tail < push_pos)
            q_tail = push_pos;
        s.cur_seq = push_pos % SEQ_SIZE;
        s.tail_seq = q_tail % SEQ_SIZE;
        /* Update s.tail_seq, push s.cur_seq forward. */

        if (s.win_size == SLOW) {
            s.win_size = MODERATE;
        } else if (s.win_size == MODERATE) {
            s.win_size = FAST;
        }
        printf("gbn_send() --> [%hhu, %hhu](%hhu)\n", s.cur_seq,
               (s.cur_seq + (uint8_t)s.win_size - 1) % SEQ_SIZE, s.tail_seq);

        if (sent_len == (ssize_t)len && sent_n == n_pkts
        	&& s.cur_seq == s.tail_seq)
            break;
    }

    return sent_len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags) {

    /* TODO: Your code here. */
    if (sockfd != s.fd) {
        errno = EINVAL;
        return -1;
    }

    if (s.last_len > 0) {
        printf("gbn_recv() have last pkt\n");
        if (s.last_len <= (int)len) {
            memcpy(buf, s.last_buf, s.last_len);
            ssize_t ret = (ssize_t)s.last_len;
            s.last_len = 0;
            return ret;
        }
        memcpy(buf, s.last_buf, len);
        s.last_len -= len;
        memcpy(s.last_buf, s.last_buf + len, s.last_len);
        return (ssize_t)len;
    }

    int recv_size;
    char _buf[BUFFLEN];
    struct sockaddr client;
    socklen_t socklen = sizeof(client);

    while (1) {
        while (1) {
            recv_size =
                maybe_recvfrom(sockfd, _buf, BUFFLEN, flags, &client, &socklen);
            if (recv_size != INFOLEN && recv_size != INFOLEN + DATALEN)
                continue;

            gbnhdr *header = (gbnhdr *)_buf;
            uint16_t old_sum = header->checksum;
            header->checksum = 0;
            int check_len = INFOLEN;
            if (header->type == DATA)
                check_len += DATALEN;
            uint16_t new_sum = checksum((uint16_t *)header, check_len / 2);

            printf(
                "gbn_recv() recv type: %hhu | pkt_len: %hu | os:%hu | ns:%hu\n",
                header->type, header->length, old_sum, new_sum);

            if (header->type == DATA && s.state == SYN_RCVD)
                s.state = ESTABLISHED;

            if (new_sum != old_sum)
                continue;
            if (header->type == FIN) {
                s.state = FIN_RCVD;
                return 0;
            }
            if (s.state == ESTABLISHED && header->type == DATA)
                break;

            if (s.state == SYN_RCVD) {
                printf("s.state == SYN_RCVD\n");
                if (header->type == SYN) {
                    char synack[INFOLEN];
                    gbnhdr *sa_hdr = (gbnhdr *)synack;
                    sa_hdr->type = SYN;
                    sa_hdr->seqnum = header->seqnum;
                    sa_hdr->length = INFOLEN;
                    sa_hdr->checksum = 0;
                    sa_hdr->checksum =
                        checksum((uint16_t *)sa_hdr, INFOLEN / 2);

                    int send_size = sendto(s.fd, synack, INFOLEN, 0, &s.remote,
                                           sizeof(s.remote));
                    if (send_size != INFOLEN) {
                        perror("gbn_recv() resend SYNACK failed");
                        continue;
                    }
                } else {
                    perror("gbn_recv() error");
                }
            } else
                perror("gbn_recv() s.state is not SYN_RCVD or ESTABLISHED");
        }

        /* Received DATA */

        gbnhdr *header = (gbnhdr *)_buf;
        uint8_t seq = header->seqnum;
        uint8_t q_front = s.cur_seq;
        uint8_t q_tail = q_front + FAST - 1;
        if (seq < q_front)
            seq += SEQ_SIZE;

        printf("gbn_recv() DATA [%hhu, %hhu] recv->%hhu\n", q_front, q_tail,
               seq);

        if (!(q_front <= seq && seq <= q_tail))
            continue;
        /* If not in the window, ignore it. */

        s.acked[header->seqnum] = 1;
        s.data_array[header->seqnum] = *header;
        /* Record it. */


        uint8_t push_pos;
        for (push_pos = s.cur_seq;; push_pos++) {
            uint8_t index = push_pos % SEQ_SIZE;
            if (s.acked[index] == 0)
                break;

            memcpy(s.last_buf + s.last_len, s.data_array[index].data,
                   s.data_array[index].length - INFOLEN);
            s.last_len += (int)s.data_array[index].length - INFOLEN;
            /* Copy payload to last_buf. */

            s.acked[index] = 0;
            s.data_array[index] = empty;
        }
        /* Find next empty cell and clean old cells. */

        char ack[INFOLEN];
        gbnhdr *ack_hdr = (gbnhdr *)ack;
        ack_hdr->type = DATAACK;
        ack_hdr->seqnum = (push_pos + SEQ_SIZE - 1) % SEQ_SIZE;
        ack_hdr->length = INFOLEN;
        ack_hdr->checksum = 0;
        ack_hdr->checksum = checksum((uint16_t *)ack_hdr, INFOLEN / 2);

        int send_size =
            sendto(s.fd, ack, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("gbn_recv() send ACK failed");
            continue;
        }
        /* Send ack. */
        printf("gbn_recv() send ACK:%hhu\n", ack_hdr->seqnum);

        s.cur_seq = push_pos % SEQ_SIZE;
        /* Push the window */

        if(s.last_len == 0)
        	continue;

        if (s.last_len <= (int)len) {
            memcpy(buf, s.last_buf, s.last_len);
            ssize_t ret = (ssize_t)s.last_len;
            s.last_len = 0;
            return ret;
        }

        memcpy(buf, s.last_buf, len);
        s.last_len -= len;
        memcpy(s.last_buf, s.last_buf + len, s.last_len);
        return (ssize_t)len;
    }
}

int gbn_close(int sockfd) {
	if(s.state == CLOSED)
		return 0;

    /* TODO: Your code here. */
    if (s.is_server == 0 || (s.is_server == 1 && s.state == SYN_RCVD)) {

        char fin[INFOLEN];
        gbnhdr *fin_hdr = (gbnhdr *)fin;
        fin_hdr->type = FIN;
        fin_hdr->seqnum = s.cur_seq;
        fin_hdr->length = INFOLEN;
        fin_hdr->checksum = 0;
        fin_hdr->checksum = checksum((uint16_t *)fin_hdr, INFOLEN / 2);
        /* Make a FIN pkt. */

        int send_size =
            sendto(s.fd, fin, INFOLEN, 0, &s.remote, sizeof(s.remote));
        if (send_size != INFOLEN) {
            perror("gbn_close() send failed");
            return -1;
        }
        s.state = FIN_SENT;
        alarm(TIMEOUT);
        /* Send FIN. */

        printf("gbn_close() send FIN\n");

        alarm(TIMEOUT);

        char buf[BUFFLEN];
        struct sockaddr client;
        socklen_t socklen = sizeof(client);
        int recv_size;

        gbnhdr *fa_hdr;

        while (1) {
            recv_size =
                maybe_recvfrom(s.fd, buf, BUFFLEN, 0, &client, &socklen);
            if(s.state == CLOSED)
            	return 0;

            if (recv_size != INFOLEN) {
                perror("gbn_close() recv FINACK error");
                continue;
            }
            /* Recv FINACK. */

            fa_hdr = (gbnhdr *)buf;
            uint16_t old_sum = fa_hdr->checksum;
            fa_hdr->checksum = 0;
            uint16_t new_sum = checksum((uint16_t *)fa_hdr, INFOLEN / 2);
            if (fa_hdr->length != INFOLEN)
                continue;
            if (fa_hdr->type != FINACK && fa_hdr->type != FIN)
                continue;
            if (new_sum != old_sum)
                continue;
            /* Check validity of FIN/FINACK. */
            printf("gbn_close() recv SYN/SYNACK\n");
            break;
        }

        if (fa_hdr->type == FIN) {
            char finack[INFOLEN];
            gbnhdr *fa_hdr = (gbnhdr *)finack;
            fa_hdr->type = FINACK;
            fa_hdr->seqnum = s.cur_seq;
            fa_hdr->length = INFOLEN;
            fa_hdr->checksum = 0;
            fa_hdr->checksum = checksum((uint16_t *)fa_hdr, INFOLEN / 2);
            /* Make a FIN pkt. */

            int send_size =
                sendto(s.fd, finack, INFOLEN, 0, &s.remote, sizeof(s.remote));
            if (send_size != INFOLEN) {
                perror("gbn_close() send SYNACK failed");
                return -1;
            }
            printf("gbn_close() send FINACK\n");
        }

        s.state = CLOSED;
        alarm(0);
        gbn_init();
        /* Close the sock. */

        return 0;
    }

    /* If is_server == 1 and FIN_RCVD */

    char finack[INFOLEN];
    gbnhdr *fa_hdr = (gbnhdr *)finack;
    fa_hdr->type = FINACK;
    fa_hdr->seqnum = s.cur_seq;
    fa_hdr->length = INFOLEN;
    fa_hdr->checksum = 0;
    fa_hdr->checksum = checksum((uint16_t *)fa_hdr, INFOLEN / 2);
    /* Make a FIN pkt. */

    int send_size =
        sendto(s.fd, finack, INFOLEN, 0, &s.remote, sizeof(s.remote));
    if (send_size != INFOLEN) {
        perror("gbn_close() send SYNACK failed");
        return -1;
    }
    printf("gbn_close() send SYNACK\n");

    s.state = CLOSED;
    alarm(0);
    gbn_init();
    /* Close the sock. */

    return 0;
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

int window_cnt(uint8_t cur_seq, uint8_t tail_seq) {
    if (tail_seq >= cur_seq) {
        return tail_seq - cur_seq;
    }
    return tail_seq + SEQ_SIZE - cur_seq;
}
