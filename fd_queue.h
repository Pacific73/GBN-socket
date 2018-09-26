#ifndef _fd_queue_h
#define _fd_queue_h

#include "gbn.h"

state_t *fds = NULL;
int q_capacity = -1;
int q_size = -1;
int front_pos = -1;

void fd_q_init(int capacity);
int fd_q_fini();

int fd_q_size();

void fd_q_push(state_t *state);
state_t *fd_q_pop();

state_t *fd_q_front();
state_t *fd_q_back();

state_t *find_fd(int fd);


#endif