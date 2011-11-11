/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

DVECTOR_INIT(HANDLE, HANDLE);

struct BIO_poller {
	d_vector(HANDLE) events;
	d_vector(poll) poll;
	struct poll* current;
};

#define READ_FLAGS (FD_READ | FD_CLOSE | FD_ACCEPT)
#define WRITE_FLAGS (FD_WRITE | FD_CONNECT)

void update_poll(struct poll* p, int read, int write) {
	BIO_poller* s = p->poller;
	DWORD flags = (read ? READ_FLAGS : 0) | (write ? WRITE_FLAGS : 0);

	if (p->wait_read == read && p->wait_write == write) {
		return;
	}

	if (!p->registered) {
		HANDLE e = WSACreateEvent();
		p->wait_read = read;
		p->wait_write = write;
		WSAEventSelect((SOCKET) p->fd, p->ptr, flags);
		dv_append1(&s->events, e);
		dv_append1(&s->poll, p);
		p->ptr = e;
	} else if (!p->in_callback) {
		WSAEventSelect((SOCKET) p->fd, p->ptr, flags);
	}

	p->registered = 1;
	p->wait_read = read;
	p->wait_write = write;
}

void remove_poll(BIO_poller* s, struct poll* p) {
	for (i = 0; i < s->poll.size; i++) {
		if (s->poll.data[i] == p) {
			dv_erase(&s->poll, i, 1);
			dv_erase(&s->events, i, 1);
			break;
		}
	}

	CloseHandle(p->ptr);

	if (s->current == p) {
		s->current = NULL;
	}

	p->registered = 0;
	p->wait_read = 0;
	p->wait_write = 0;
}

BIO_poller* BIO_new_poller(int threads) {
	if (threads) {
		return NULL;
	}

	return (BIO_poller*) calloc(1, sizeof(BIO_poller));
}

void BIO_free_poller(BIO_poller* s) {
	if (!s) {
		return;
	}

	dv_free(s->poll);
	dv_free(s->events);
	free(s);
}

int BIO_poll(BIO_poller* s, int64_t timeoutns) {
	DWORD timeout = (timeoutns >= 0) ? (timeoutns / 1000000) : INFINITE;

	for (;;) {
		int ret;
		DWORD time;
		bool read, write;
		WSANETWORKEVENTS ev;

		if (timeout != INFINITE) {
			time = GetTickCount();
		}

		ret = WaitForMultipleObjects(s->events.size, s->events.data, FALSE, timeout);

		if (ret == WAIT_TIMEOUT) {
			return 0;
		} else if (ret < 0 || ret > s->events.size) {
			return -1;
		}

		p = &s->poll.data[ret];
		if (WSAEnumNetworkEvents((SOCKET) p->fd, p->ptr, &ev)) {
			goto loop_end;
		}

		read = ev.lNetworkEvents & READ_FLAGS;
		write = ev.lNetworkEvents & WRITE_FLAGS;
		s->current = p;
		p->in_callback = 1;

		if (read && p->read && p->read_cb) {
			p->read_cb(p->read_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		if (write && p->write && p->write_cb) {
			p->write_cb(p->write_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		if (write && p->read_after_write && p->read_cb) {
			p->read_cb(p->read_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		if (read && !write && p->write_after_read && p->write_cb) {
			p->write_cb(p->writ_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		p->in_callback = 0;

		read2 = p->wait_read;
		write2 = p->wait_write;

		p->wait_read = read;
		p->wait_write = write;

		update_poll(p, read2, write2);

	loop_end:
		if (timeout != INFINITE) {
			time = GetTickCount() - time;

			if (timeout < time) {
				return 0;
			}

			timeout -= time;
		}
	}
}

#endif

