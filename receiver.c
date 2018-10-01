#include "gbn.h"

int main(int argc, char *argv[])
{
	int sockfd;
	int newSockfd;
	int numRead;
	char buf[DATALEN];
	struct sockaddr_in server;
	struct sockaddr_in client;
	FILE *outputFile;
	socklen_t socklen;
	
	/*----- Checking arguments -----*/
	if (argc != 3){
		fprintf(stderr, "usage: receiver <port> <filename>\n");
		exit(-1);
	}

	/*----- Opening the output file -----*/
	if ((outputFile = fopen(argv[2], "wb")) == NULL){
		perror("fopen");
		exit(-1);
	}

	/*----- Opening the socket -----*/
	if ((sockfd = gbn_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		perror("gbn_socket");
		exit(-1);
	}

	printf("[receiver] socket(): %d finished.\n", sockfd);
	
	/*--- Setting the server's parameters -----*/
	memset(&server, 0, sizeof(struct sockaddr_in));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port        = htons(atoi(argv[1]));

	/*----- Binding to the designated port -----*/
	if (gbn_bind(sockfd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) == -1){
		perror("gbn_bind");
		exit(-1);
	}

	printf("[receiver] bind() finished.\n");
	
	/*----- Listening to new connections -----*/
	if (gbn_listen(sockfd, 1) == -1){
		perror("gbn_listen");
		exit(-1);
	}
	printf("[receiver] listen() finished.\n");

	/*----- Waiting for the client to connect -----*/
	socklen = sizeof(struct sockaddr_in);
	newSockfd = gbn_accept(sockfd, (struct sockaddr *)&client, &socklen);
	if (newSockfd == -1){
		perror("gbn_accept");
		exit(-1);
	}
	
	printf("[receiver] accept() finished.\n");
	/*----- Reading from the socket and dumping it to the file -----*/
	while(1){
		if ((numRead = gbn_recv(newSockfd, buf, DATALEN, 0)) == -1){
			perror("gbn_recv");
			exit(-1);
		}
		else if (numRead == 0)
			break;
		printf("[receiver] recv() this round finished.\n");
		fwrite(buf, 1, numRead, outputFile);
	}
	printf("[receiver] recv() finished.\n");
	/*----- Closing the socket -----*/
	if (gbn_close(sockfd) == -1){
		perror("gbn_close");
		exit(-1);
	}
	printf("[receiver] close() finished.\n");

	/*----- Closing the file -----*/
	if (fclose(outputFile) == EOF){
		perror("fclose");
		exit(-1);
	}
			
	return (0);
}
