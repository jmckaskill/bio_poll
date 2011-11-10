/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>

DVECTOR_INIT(HANDLE, HANDLE);

struct BIO_poller {
	d_vector(HANDLE) events;
	d_vector(wait) wait;
	struct wait* current;
};

#define READ_FLAGS (FD_READ | FD_CLOSE | FD_ACCEPT)
#define WRITE_FLAGS (FD_WRITE | FD_CONNECT)

static void update_event(struct wait* w) {
	int flags = 0;

	if (w->flags & POLL_READ) {
		flags |= READ_FLAGS;
	}

	if (w->flags & POLL_WRITE) {
		flags |= WRITE_FLAGS;
	}

	WSAEventSelect((SOCKET) w->fd, w->ptr, flags);
}

void update_read(BIO_poller* s, struct wait* w) {
	update_event(w);
}

void update_write(BIO_poller* s, struct wait* w) {
	update_event(w);
}

void add_poll(BIO_poller* s, struct wait* w) {
	HANDLE e = WSACreateEvent();
	WSAEventSelect((SOCKET) w->fd, w->ptr, READ_FLAGS | WRITE_FLAGS);
	dv_append1(&s->events, e);
	dv_append1(&s->wait, w);
	w->ptr = e;
}

void remove_poll(BIO_poller* s, struct wait* w) {
	for (i = 0; i < s->wait.size; i++) {
		if (s->wait.data[i] == w) {
			dv_erase(&s->wait, i, 1);
			dv_erase(&s->events, i, 1);
			break;
		}
	}

	CloseHandle(w->ptr);

	if (s->current == w) {
		s->current = NULL;
	}
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

		w = &s->wait.data[ret];
		if (WSAEnumNetworkEvents((SOCKET) w->fd, w->ptr, &ev)) {
			goto loop_end;
		}

		w->flags |= POLL_IN_READ | POLL_IN_WRITE;
		read = ev.lNetworkEvents & READ_FLAGS;
		write = ev.lNetworkEvents & WRITE_FLAGS;
		s->current = w;

		if (read) {
			w->read(w->read_arg);

			if (s->current != w) {
				goto loop_end;
			}
		}

		if (write) {
			w->write(w->write_arg);

			if (s->current != w) {
				goto loop_end;
			}
		}

		w->flags &= ~(POLL_IN_READ | POLL_IN_WRITE);

		if (read && !(w->flags & POLL_READ)) || (write && !(w->flags & POLL_WRITE)) {
			update_event(w);
		}

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

