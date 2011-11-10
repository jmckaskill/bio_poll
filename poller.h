/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#pragma once

#include <bio_poll.h>

struct poll {
	BIO_poller*     poller;
	void*           ptr;
	int             fd;
	BIO_poll_fn     read_cb;
	void*           read_arg;
	BIO_poll_fn     write_cb;
	void*           write_arg;
	unsigned int    wait_read : 1;
	unsigned int    wait_write : 1;
	unsigned int    in_read : 1;
	unsigned int    in_write : 1;
	unsigned int    read : 1;
	unsigned int    write : 1;
	unsigned int    read_after_write : 1;
	unsigned int    write_after_read : 1;
	unsigned int    read_finished : 1;
	unsigned int    write_finished : 1;
	unsigned int    registered : 1;
	unsigned int    delegated : 1;
};

void add_poll(struct poll* s, int read, int write);
void remove_poll(struct poll* s);
void update_read(struct poll* s, int enabled);
void update_write(struct poll* s, int enabled);

