#include "fd_queue.h"
#include <malloc.h>
#include <string.h>

void fd_q_init(int capacity) {
    q_capacity = capacity > 0 ? capacity : -1;
    if (capacity == -1)
        return;
    q_size = 0;
    front_pos = 0;

    fds = (int *)malloc(q_capacity * sizeof(int));
    memset(fds, 0, sizeof(fds));
}

int fd_q_size() { return q_size; }

void fd_q_push(state_t *state) {
    int next_pos = (front_pos + 1) % q_capacity;
    fds[next_pos] = state;
    front_pos = next_pos;

    int new_size = q_size + 1;
    if(new_size <= q_capacity)
        q_size = new_size;
}

int fd_q_pop() {
    // code here...
}

state_t* fd_q_front() {
    if (front_pos == -1 || fds == NULL)
        return -1;
    return fds[front_pos];
}

state_t* fd_q_back() {
    if (front_pos == -1 || fds == NULL)
        return -1;
    int tail_pos = (front + q_size - 1) % q_capacity;
    return fds[tail_pos];
}

state_t *find_fd(int fd) {
    // code here...
}