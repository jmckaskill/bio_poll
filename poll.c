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

BIO* BIO_new_poll(BIO_poller* p) {
	BIO* b = BIO_new(BIO_f_poll());
	BIO_set_poller(b, p);
	return b;
}

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

static void disconnect(struct poll* s, BIO* next) {
	if (s->registered) {
		remove_poll(s);
	}

	if (next && s->delegated) {
		BIO_set_read_callback(next, NULL);
		BIO_set_write_callback(next, NULL);
	}

	s->fd = -1;
	s->wait_read = 0;
	s->wait_write = 0;
	s->registered = 0;
	s->read = 0;
	s->write = 0;
	s->read_after_write = 0;
	s->write_after_read = 0;
	s->delegated = 0;
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

static int update_poll(struct poll* s, BIO* next, int ret) {
	int read = s->read || s->write_after_read;
	int write = s->write || s->read_after_write;

	/* We are not handling updates */
	if (!s->poller || s->delegated) {
		return ret;
	}

	/* success - turn off wait */
	if (ret > 0) {
		if (read != s->wait_read && !s->in_read) {
			update_read(s, read);
		}

		if (write != s->wait_write && !s->in_write) {
			update_write(s, write);
		}
		
		s->wait_write = write;
		s->wait_read = read;
		return ret;
	}

	/* read/write fatal error or clean disconnect */
	if ((ret < 0 && !BIO_should_retry(next)) || (s->read_finished && s->write_finished)) {
		disconnect(s, next);
		return ret;
	}

	/* nothing we can wait on */
	if (!read && !write && !s->registered) {
		return ret;
	}

	/* We need to wait, try and get the fd */
	if (s->fd < 0) {
		/* someone down the chain is handling the callback */
		if (BIO_set_read_callback(next, s->read_cb) && BIO_set_write_callback(next, s->write_cb)) {
			BIO_set_read_arg(next, s->read_arg);
			BIO_set_write_arg(next, s->write_arg);
			s->delegated = 1;
			return ret;
		}

		BIO_get_fd(next, &s->fd);

		/* no way for us to wait without a fd, we will try to get the
		 * fd next time we hit a read retry */
		if (s->fd < 0) {
			return ret;
		}
		
		BIO_set_nbio(next, 1);
	}

	read = s->read || s->write_after_read;
	write = s->write || s->read_after_write;

	if (!s->registered) {
		add_poll(s, read, write);
		s->registered = 1;
	} else {
		if (read != s->wait_read && !s->in_read) {
			update_read(s, read);
		}

		if (write != s->wait_write && !s->in_write) {
			update_write(s, write);
		}
	}

	s->wait_read = read;
	s->wait_write = write;

	return ret;
}

#define should_connect(b) (BIO_should_io_special(b) && BIO_get_retry_reason(b) == BIO_RR_CONNECT)
#define should_accept(b) (BIO_should_io_special(b) && BIO_get_retry_reason(b) == BIO_RR_ACCEPT)

static int on_read(struct poll* s, BIO* next, int ret) {
	s->read = ret <= 0 && (BIO_should_read(next) || should_accept(next));
	s->read_after_write = ret <= 0 && (BIO_should_write(next) || should_connect(next));
	s->read_finished = ret <= 0 && !BIO_should_retry(next);

	return update_poll(s, next, ret);
}

static int on_write(struct poll* s, BIO* next, int ret) {
	s->write = ret <= 0 && (BIO_should_write(next) || should_connect(next));
	s->write_after_read = ret <= 0 && (BIO_should_read(next) || should_accept(next));
	s->write_finished = ret <= 0 && !BIO_should_retry(next);

	return update_poll(s, next, ret);
}

static int poll_gets(BIO* b, char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	ret = BIO_gets(next, buf, sz);
	BIO_copy_next_retry(b);
	return on_read(s, next, ret);
}

static int poll_read(BIO* b, char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	ret = BIO_read(next, buf, sz);
	BIO_copy_next_retry(b);
	return on_read(s, next, ret);
}

static int poll_write(BIO* b, const char* buf, int sz) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (sz == 0 || !s || !next) {
		return 0;
	}

	ret = BIO_write(next, buf, sz);
	BIO_copy_next_retry(b);
	return on_write(s, next, ret);
}

static int poll_puts(BIO* b, const char* str) {
	BIO* next = b->next_bio;
	struct poll* s = (struct poll*) b->ptr;
	int ret;

	if (!s || !next) {
		return 0;
	}

	ret = BIO_puts(next, str);
	BIO_copy_next_retry(b);
	return on_write(s, next, ret);
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
	long ret;

	switch (cmd) {
	case BIO_C_SET_READ_ARG:
		s->read_arg = parg;
		if (s->delegated) {
			BIO_set_read_arg(next, s->read_arg);
		}
		return 1;

	case BIO_C_SET_WRITE_ARG:
		s->read_arg = parg;
		if (s->delegated) {
			BIO_set_write_arg(next, s->read_arg);
		}
		return 1;

	case BIO_C_SET_POLLER:
		disconnect(s, next);
		s->poller = (BIO_poller*) parg;
		return 1;

	case BIO_CTRL_FLUSH:
		ret = BIO_ctrl(next, cmd, larg, parg);
		if (!ret) {
			return ret;
		}

		BIO_copy_next_retry(b);
		return on_write(s, next, (int) ret);

	case BIO_CTRL_EOF:
		ret = BIO_ctrl(next, cmd, larg, parg);
		if (!ret) {
			return ret;
		}

		s->write = 0;
		s->write_after_read = 0;
		s->write_finished = 1;

		return update_poll(s, next, (int) ret);

	default:
		return BIO_ctrl(next, cmd, larg, parg);
	}
}

