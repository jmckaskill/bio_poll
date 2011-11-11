/* vim: set noet sts=8 ts=8 sw=8 tw=78: */
#pragma once

#include <openssl/bio.h>

typedef struct BIO_poller BIO_poller;

BIO_poller* BIO_new_poller(int threads);
void BIO_free_poller(BIO_poller* p);
int BIO_poll(BIO_poller* p, int64_t timeoutns);
void BIO_exit_poll(BIO_poller* p, int exitcode);

enum {
	BIO_C_SET_READ_CALLBACK = 1000,
	BIO_C_SET_READ_ARG,
	BIO_C_SET_WRITE_CALLBACK,
	BIO_C_SET_WRITE_ARG,
	BIO_C_SET_POLLER,
};

BIO_METHOD* BIO_f_poll(void);
#define BIO_set_poller(b,p) BIO_ctrl(b, BIO_C_SET_POLLER, 0, p)

typedef void (*BIO_poll_fn)(void*);

#define BIO_set_read_callback(b,cb) BIO_callback_ctrl(b, BIO_C_SET_READ_CALLBACK, (void (*)()) (cb))
#define BIO_set_read_arg(b,u) BIO_ctrl(b, BIO_C_SET_READ_ARG, 0, u)
#define BIO_set_write_callback(b,cb) BIO_callback_ctrl(b, BIO_C_SET_WRITE_CALLBACK, (void (*)()) (cb))
#define BIO_set_write_arg(b,u) BIO_ctrl(b, BIO_C_SET_WRITE_ARG, 0, u)
