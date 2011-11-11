/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#if defined __MACH__ || defined BSD

#include "poller.h"
#include <dmem/vector.h>
#include <bio_poll.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>

DVECTOR_INIT(kevent, struct kevent);

struct thread {
	struct thread* prev;
	struct thread* next;
	pthread_mutex_t* lock;
	d_vector(kevent) changes;
	d_vector(kevent) events;
};

struct BIO_poller {
	int kq;
	int threads;
	int die;
	int exit_code;
	pthread_key_t key;
	pthread_mutex_t lock;
	struct thread main;
};

static void free_thread(void* u) {
	struct thread* t = (struct thread*) u;
	if (t) {
		pthread_mutex_lock(t->lock);
		t->prev->next = t->next;
		t->next->prev = t->prev;
		pthread_mutex_unlock(t->lock);
		dv_free(t->changes);
		dv_free(t->events);
		free(t);
	}
}

static struct thread* get_thread(BIO_poller* s) {
	struct thread* t;

	if (!s->threads) {
		return &s->main;
	}

	t = (struct thread*) pthread_getspecific(s->key);

	if (t) {
		return t;
	}

	t = (struct thread*) calloc(1, sizeof(struct thread));
	t->lock = &s->lock;

	pthread_mutex_lock(t->lock);
	t->next = &s->main;
	t->prev = s->main.prev;
	s->main.prev->next = t;
	s->main.prev = t;
	pthread_mutex_unlock(t->lock);

	pthread_setspecific(s->key, t);
	return t;
}

void update_poll(struct poll* p, int read, int write) {
	if (p->wait_read == read && p->wait_write == write) {
		return;
	}
       
	if (!p->registered) {
		struct thread* t = get_thread(p->poller);
		struct kevent* e = dv_append_buffer(&t->changes, 2);
		EV_SET(&e[0], p->fd, EVFILT_READ, EV_ADD | (read ? EV_ENABLE : EV_DISABLE), 0, 0, p);
		EV_SET(&e[1], p->fd, EVFILT_WRITE, EV_ADD | (write ? EV_ENABLE : EV_DISABLE), 0, 0, p);

	} else if (!p->in_callback) {

		if (p->wait_write != read) {
			struct thread* t = get_thread(p->poller);
			struct kevent* e = dv_append_buffer(&t->changes, 1);
			EV_SET(e, p->fd, EVFILT_READ, read ? EV_ENABLE : EV_DISABLE, 0, 0, p);
		}

		if (p->wait_write != write) {
			struct thread* t = get_thread(p->poller);
			struct kevent* e = dv_append_buffer(&t->changes, 1);
			EV_SET(e, p->fd, EVFILT_WRITE, write ? EV_ENABLE : EV_DISABLE, 0, 0, p);
		}
	}

	p->registered = 1;
	p->wait_write = write;
	p->wait_write = read;
}

void remove_poll(struct poll* p) {
	struct thread* t = get_thread(p->poller);
	struct kevent* e = dv_append_buffer(&t->changes, 2);
	int i;

	EV_SET(&e[0], p->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	EV_SET(&e[1], p->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

	dv_remove2(&t->changes, t->changes.data[INDEX].udata == p);

	for (i = 0; i < t->events.size; i++) {
		if (t->events.data[i].udata == p) {
			t->events.data[i].udata = NULL;
		}
	}

	p->wait_read = 0;
	p->wait_write = 0;
	p->registered = 0;
}

BIO_poller* BIO_new_poller(int threads) {
	BIO_poller* s = (BIO_poller*) calloc(1, sizeof(BIO_poller));
	s->threads = threads;
	s->kq = kqueue();

	if (threads) {
		pthread_key_create(&s->key, &free_thread);
		pthread_mutex_init(&s->lock, NULL);
	}

	s->main.next = &s->main;
	s->main.prev = &s->main;

	return s;
}

void BIO_free_poller(BIO_poller* s) {
	if (!s) {
		return;
	}

	if (s->threads) {
		struct thread* t = s->main.next;
		while (t != &s->main) {
			dv_free(t->changes);
			dv_free(t->events);
			t = t->next;
			free(t->prev);
		}

		pthread_key_delete(s->key);
		pthread_mutex_destroy(&s->lock);
	} else {
		dv_free(s->main.changes);
		dv_free(s->main.events);
	}

	close(s->kq);
	free(s);
}

void BIO_exit_poll(BIO_poller* s, int exitcode) {
	s->die = 1;
	s->exit_code = exitcode;
}

#define NS INT64_C(1000000000)

int BIO_poll(BIO_poller* s, int64_t timeoutns) {
	int i, ret;
	struct thread* t = get_thread(s);
	struct timespec to, *pto;

	if (timeoutns >= 0) {
		pto = &to;
	}

	s->die = 0;
	while (!s->die) {
		int64_t time;
		dv_resize(&t->events, 64);

		if (pto) {
			struct timeval tv;
			gettimeofday(&tv, NULL);
			time = tv.tv_sec * NS + tv.tv_usec * INT64_C(1000);
			pto->tv_sec = timeoutns / NS;
			pto->tv_nsec = timeoutns % NS;
		}

		ret = kevent(s->kq,
				t->changes.data,
				t->changes.size,
				t->events.data,
				t->events.size,
				pto);

		dv_resize(&t->changes, 0);

		if (ret <= 0) {
			dv_resize(&t->events, 0);
			return ret;
		}

		dv_resize(&t->events, ret);
		for (i = 0; i < ret; i++) {
			struct kevent* e = &t->events.data[i];
			struct poll* p = (struct poll*) e->udata;
			int read, write;

			if (p == NULL) {
				continue;
			}

			read = p->wait_read;
			write = p->wait_write;
			p->in_callback = 1;

			if (e->filter == EVFILT_READ) {
				if (p->read && p->read_cb) {
					p->read_cb(p->read_arg);
				}

				if (e->udata == NULL) {
					continue;
				}

				if (p->write_after_read && p->write_cb) {
					p->write_cb(p->write_arg);
				}

			} else {
				if (p->write && p->write_cb) {
					p->write_cb(p->write_arg);
				}

				if (e->udata == NULL) {
					continue;
				}

				if (p->read_after_write && p->read_cb) {
					p->read_cb(p->read_arg);
				}
			}

			if (e->udata == NULL) {
				continue;
			}

			p->in_callback = 0;

			read2 = p->wait_read;
			write2 = p->wait_write;

			p->wait_read = read;
			p->wait_write = write;

			update_poll(p, read2, write2);
		}

		if (pto) {
			struct timeval tv;
			gettimeofday(&tv, NULL);
			timeoutns -= (tv.tv_sec * NS + tv.tv_usec * INT64_C(1000)) - time;

			if (timeoutns <= 0) {
				return 0;
			}
		}
	}

	return s->exit_code;
}

#endif

