/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#include "poller.h"
#include <bio_poll.h>

static int poll_new(BIO* b);
static int poll_free(BIO* b);
static int poll_gets(BIO* b, char* buf, int sz);
static long poll_ctrl(BIO* b, int cmd, long larg, void* parg);
static long poll_callback_ctrl(BIO* b, int cmd, bio_info_cb* fp);
static int poll_puts(BIO* b, const char* str);
static int poll_write(BIO* b, const char* buf, int sz);
static int poll_read(BIO* b, char* buf, int sz);

static BIO_METHOD poll_method = {
	BIO_TYPE_FILTER,
	"poll proxy",
	&poll_write,
	&poll_read,
	&poll_puts,
	&poll_gets,
	&poll_ctrl,
	&poll_new,
	&poll_free,
	&poll_callback_ctrl,
};

BIO_METHOD* BIO_f_poll(void) {
	return &poll_method;
}

static int poll_new(BIO* b) {
	struct poll* s = (struct poll*) calloc(1, sizeof(struct poll));
	s->fd = -1;
	b->ptr = s;
	b->init = 1;
	return 1;
}

static int register_poll(struct poll* s, BIO* next) {
	/* someone down the chain is handling the callback */
	if (BIO_set_read_callback(next, s->read_cb) && BIO_set_write_callback(next, s->write_cb)) {
		BIO_set_read_arg(next, s->read_arg);
		BIO_set_write_arg(next, s->write_arg);
		s->delegated = 1;
		return 1;
	}

	BIO_get_fd(next, &s->fd);

	/* no way for us to wait without a fd, we will try to get the
	 * fd next time we hit a read retry */
	if (s->fd < 0) {
		return 1;
	}

	add_poll(s, s->read | s->write);
	return 0;
}

static void disconnect(struct poll* s, BIO* next) {
	if (s->registered) {
		remove_poll(s);
	}

	if (next && s->delegated) {
		BIO_set_read_callback(next, NULL);
		BIO_set_write_callback(next, NULL);
	}

	s->fd = -1;
	s->read = 0;
	s->write = 0;
	s->delegated = 0;
	s->read_finished = 0;
	s->write_finished = 0;
}

static int poll_free(BIO* b) {
	struct poll* s = (struct poll*) b->ptr;

	if (s) {
		disconnect(s, b->next_bio);
		free(s);
	}

	b->init = 0;
	return 1;
}

static void on_read(BIO* b, int ret) {
	struct poll* s = (struct poll*) b->ptr;
	BIO* next = b->next_bio;

	if (ret > 0) {
		s->read = 0;
	} else {
		int rr = BIO_should_io_special(next) ? BIO_get_retry_reason(next) : 0;
		s->read = (BIO_should_write(next) ? POLL_WRITE : 0)
			| (BIO_should_read(next) ? POLL_READ : 0)
			| (rr == BIO_RR_CONNECT ? POLL_CONNECT : 0)
			| (rr == BIO_RR_ACCEPT ? POLL_ACCEPT : 0);
	}

	if (ret == 0 && !BIO_should_retry(next)) {
		s->read_finished = 1;
	}

	BIO_copy_next_retry(b);

	if (!s->poller || s->delegated || !s->registered) {
		return;
	}

	if ((ret < 0 && !BIO_should_retry(next)) || (s->read_finished && s->write_finished)) {
		disconnect(s, next);
	} else {
		update_poll(s, s->read | s->write);
	}
}

static void on_write(BIO* b, int ret) {
	struct poll* s = (struct poll*) b->ptr;
	BIO* next = b->next_bio;
	int rr = BIO_should_io_special(next) ? BIO_get_retry_reason(next) : 0;

	if (ret > 0) {
		s->write = 0;
	} else {
		s->write = (BIO_should_write(next) ? POLL_WRITE : 0)
			| (BIO_should_read(next) ? POLL_READ : 0)
			| (rr == BIO_RR_CONNECT ? POLL_CONNECT : 0)
			| (rr == BIO_RR_ACCEPT ? POLL_ACCEPT : 0);
	}

	BIO_copy_next_retry(b);

	if (!s->poller || s->delegated || !s->registered) {
		return;
	}

	if ((ret < 0 && !BIO_should_retry(next)) || (s->read_finished && s->write_finished)) {
		disconnect(s, next);
	} else {
		update_poll(s, s->read | s->write);
	}
}

static int poll_gets(BIO* b, char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	BIO_clear_retry_flags(b);

	ret = BIO_gets(next, buf, sz);
	on_read(b, ret);

	if (s->read && !s->registered) {
		if (register_poll(s, next)) {
			return ret;
		}

		ret = BIO_gets(next, buf, sz);
		on_read(b, ret);
	}

	return ret;
}

static int poll_read(BIO* b, char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	BIO_clear_retry_flags(b);

	ret = BIO_read(next, buf, sz);
	on_read(b, ret);

	if (s->read && !s->registered) {
		if (register_poll(s, next)) {
			return ret;
		}

		ret = BIO_read(next, buf, sz);
		on_read(b, ret);
	}

	return ret;
}

static int poll_write(BIO* b, const char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	BIO_clear_retry_flags(b);

	ret = BIO_write(next, buf, sz);
	on_write(b, ret);

	/* If we haven't registered, we need to retry after registering to
         * handle edge triggered polling.
         */
	if (s->write && !s->registered) {
		if (register_poll(s, next)) {
			return ret;
		}

		ret = BIO_write(next, buf, sz);
		on_write(b, ret);
	}

	return ret;
}

static int poll_puts(BIO* b, const char* str) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (!s || !next) {
		return 0;
	}

	BIO_clear_retry_flags(b);

	ret = BIO_puts(next, str);
	on_write(b, ret);

	if (s->write && !s->registered) {
		if (register_poll(s, next)) {
			return ret;
		}

		ret = BIO_puts(next, str);
		on_write(b, ret);
	}

	return ret;
}

static long poll_callback_ctrl(BIO* b, int cmd, bio_info_cb* fp) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;

	switch (cmd) {
	case BIO_C_SET_READ_CALLBACK:
		s->read_cb = (BIO_poll_fn) fp;
		if (s->delegated) {
			BIO_set_read_callback(next, s->read_cb);
		}
		return 1;

	case BIO_C_SET_WRITE_CALLBACK:
		s->write_cb = (BIO_poll_fn) fp;
		if (s->delegated) {
			BIO_set_write_callback(next, s->write_cb);
		}
		return 1;

	default:
		return BIO_callback_ctrl(next, cmd, fp);
	}
}

static long poll_ctrl(BIO* b, int cmd, long larg, void* parg) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	switch (cmd) {
	case BIO_C_SET_READ_ARG:
		s->read_arg = parg;
		if (s->delegated) {
			BIO_set_read_arg(next, s->read_arg);
		}
		return 1;

	case BIO_C_SET_WRITE_ARG:
		s->write_arg = parg;
		if (s->delegated) {
			BIO_set_write_arg(next, s->write_arg);
		}
		return 1;

	case BIO_C_SET_POLLER:
		disconnect(s, next);
		s->poller = (BIO_poller*) parg;
		if (parg) {
			BIO_set_nbio(next, 1);
		}
		return 1;

	case BIO_CTRL_FLUSH:
		BIO_clear_retry_flags(b);
		ret = BIO_ctrl(next, cmd, larg, parg);

		/* 0 means flushing isn't supported */
		if (ret == 0) {
			return ret;
		}

		on_write(b, ret);
		if (s->write && !s->registered) {
			if (register_poll(s, next)) {
				return ret;
			}

			ret = BIO_ctrl(next, cmd, larg, parg);
			on_write(b, ret);
		}

		return ret;

	case BIO_C_SHUTDOWN_WR:
		BIO_clear_retry_flags(b);
		s->write_finished = 1;
		s->write = 0;
		ret = BIO_ctrl(next, cmd, larg, parg);

		/* If the underlying bio doesn't support write shutdown, we
                 * convert it into a request to flush.
                 */
		if (ret == 0) {
			return BIO_flush(b);
		}

		on_write(b, ret);
		if (s->write && !s->registered) {
			if (register_poll(s, next)) {
				return ret;
			}

			ret = BIO_ctrl(next, cmd, larg, parg);
			on_write(b, ret);
		}

		return ret;

	default:
		return BIO_ctrl(next, cmd, larg, parg);
	}
}

