#include "gbn.h"
#include "fd_queue.h"

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */
	if(backlog < 0) {
		errno = EINVAL;
		return -1;
	}

	fd_q_init(backlog);
	return 0;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	int res = bind(sockfd, server, socklen);
	return res;
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
	int res = socket(domain, type, protocol);
	return res;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */
	int recv_size;
	char buff[BUFFLEN];
	sockaddr_in _client;
	socklen_t _socklen;

	while(1) {
		recv_size = maybe_recvfrom(sockfd, buff, BUFFLEN, 0, &_client, &_socklen);
		gbnhdr* pkt = (gbnhdr*)buf;
		uint16_t old_sum = pkt->checksum;
		pkt->checksum = 0;
		uint16_t new_sum = checksum(buff, INFOLEN + DATALEN);
		if(new_sum == old_sum && pkt->type == SYN)
			break;
	}
	// receive SYN

	// add it to queue...

	// timer and keep sending SYNACK before receiving ACK
	// max retrials...
	


	return(-1);
}

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){

	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){


		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

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
	return(len);  /* Simulate a success */
}
