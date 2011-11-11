/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#pragma once

#ifdef _WIN32
#include <winsock2.h>
#endif

#include <bio_poll.h>

#ifdef _WIN32
#define POLL_READ (FD_READ | FD_CLOSE)
#define POLL_WRITE (FD_WRITE | FD_CLOSE | FD_CONNECT)
#define POLL_CONNECT POLL_WRITE
#define POLL_ACCEPT FD_ACCEPT
#else
#error
#endif

struct poll {
	BIO_poller*     poller;
	void*           ptr;
	int             fd;
	BIO_poll_fn     read_cb;
	void*           read_arg;
	BIO_poll_fn     write_cb;
	void*           write_arg;
	int             wait;
	int		read;
	int		write;

	unsigned int    registered : 1;
	unsigned int    in_callback : 1;
	unsigned int    read_finished : 1;
	unsigned int    write_finished : 1;
	unsigned int    wait_connect : 1;
	unsigned int    delegated : 1;
};

void add_poll(struct poll* p, int flags);
void update_poll(struct poll* p, int flags);
void remove_poll(struct poll* s);

