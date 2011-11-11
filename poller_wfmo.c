/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

#include "poller.h"
#include <dmem/vector.h>

DVECTOR_INIT(HANDLE, HANDLE);
DVECTOR_INIT(poll, struct poll*);

struct BIO_poller {
	d_vector(HANDLE) events;
	d_vector(poll) poll;
	struct poll* current;
	int exit_code;
	int die;
};

void add_poll(struct poll* p, int flags) {
	BIO_poller* s = p->poller;
	HANDLE e = WSACreateEvent();
	WSAEventSelect((SOCKET) p->fd, p->ptr, flags);
	dv_append1(&s->events, e);
	dv_append1(&s->poll, p);
	p->ptr = e;
	p->registered = 1;
	p->wait = flags;
}

void update_poll(struct poll* p, int flags) {
	if (p->wait != flags && !p->in_callback) {
		WSAEventSelect((SOCKET) p->fd, p->ptr, flags);
	}

	p->wait = flags;
}

void remove_poll(struct poll* p) {
	BIO_poller* s = p->poller;
	int i;

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
	p->wait = 0;
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

void BIO_exit_poll(BIO_poller* s, int exitcode) {
	s->die = 1;
	s->exit_code = exitcode;
}

int BIO_poll(BIO_poller* s, int64_t timeoutns) {
	DWORD timeout = (timeoutns >= 0) ? (timeoutns / 1000000) : INFINITE;

	while (!s->die) {
		int ret;
		DWORD time;
		int wait_before, wait_after;
		WSANETWORKEVENTS ev;
		struct poll* p;

		if (timeout != INFINITE) {
			time = GetTickCount();
		}

		ret = WaitForMultipleObjects(s->events.size, s->events.data, FALSE, timeout);

		if (ret == WAIT_TIMEOUT) {
			return 0;
		} else if (ret < 0 || ret > s->events.size) {
			return -1;
		}

		p = s->poll.data[ret];
		if (WSAEnumNetworkEvents((SOCKET) p->fd, p->ptr, &ev)) {
			goto loop_end;
		}

		wait_before = p->wait;

		s->current = p;
		p->in_callback = 1;

		if (ev.lNetworkEvents & POLL_CONNECT) {
			p->wait_connect = 0;
		}

		if (p->read_cb && (ev.lNetworkEvents & p->read)) {
			p->read_cb(p->read_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		if (p->write_cb && (ev.lNetworkEvents & p->write)) {
			p->write_cb(p->read_arg);

			if (!s->current) {
				goto loop_end;
			}
		}

		p->in_callback = 0;

		wait_after = p->wait;
		p->wait = wait_before;

		update_poll(p, wait_after);

	loop_end:
		if (timeout != INFINITE) {
			time = GetTickCount() - time;

			if (timeout < time) {
				return 0;
			}

			timeout -= time;
		}
	}

	s->die = 0;
	return s->exit_code;
}

#endif

