/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#include <bio_poll.h>
#include <openssl/bio.h>

static BIO* gbio;
static BIO_poller* gpoller;

static void onwrite(void* arg) {
    (void) BIO_flush(gbio);
}

static void onread(void* arg) {
	char buf[4096];
	for (;;) {
		int ret = BIO_read(gbio, buf, sizeof(buf));
		if (ret <= 0 && !BIO_should_retry(gbio)) {
			BIO_exit_poll(gpoller, 0);
		}

		if (ret <= 0) {
			break;
		}

		fwrite(buf, 1, ret, stdout);
	}
}

int main(void) {
	gpoller = BIO_new_poller(0);
	gbio = BIO_new_connect("www.google.com:80");
	gbio = BIO_push(BIO_new(BIO_f_buffer()), gbio);
	gbio = BIO_push(BIO_new(BIO_f_poll()), gbio);

	BIO_set_poller(gbio, gpoller);
	BIO_set_read_callback(gbio, &onread);
    BIO_set_write_callback(gbio, &onwrite);

	BIO_puts(gbio, "GET / HTTP/1.0\r\n\r\n");

    onwrite(NULL);
    onread(NULL);
	BIO_poll(gpoller, -1);
	BIO_free_all(gbio);
	BIO_free_poller(gpoller);
	return 0;
}

