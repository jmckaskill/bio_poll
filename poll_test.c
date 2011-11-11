/* vim: set noet sts=8 ts=8 sw=8 tw=78: */

#include <bio_poll.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

static BIO_poller* gpoller;

static void onwrite(void* arg) {
	BIO* b = (BIO*) arg;
	BIO_shutdown_wr(b);
}

static void onread(void* arg) {
	BIO* b = (BIO*) arg;
	char buf[4096];
	for (;;) {
		int ret = BIO_read(b, buf, sizeof(buf));
		if (ret <= 0 && !BIO_should_retry(b)) {
			BIO_exit_poll(gpoller, 0);
		}

		if (ret <= 0) {
			break;
		}

		fwrite(buf, 1, ret, stdout);
	}
}

int main(void) {
	BIO* b;
	SSL_CTX* ctx;

	SSL_load_error_strings();
	SSL_library_init();
	ctx = SSL_CTX_new(TLSv1_client_method());

	b = BIO_new_connect("www.google.com:443");
	b = BIO_push(BIO_new_ssl(ctx, 1), b);
	b = BIO_push(BIO_new(BIO_f_buffer()), b);
	b = BIO_push(BIO_new(BIO_f_poll()), b);

	gpoller = BIO_new_poller(0);

	BIO_set_poller(b, gpoller);
	BIO_set_read_callback(b, &onread);
	BIO_set_read_arg(b, b);
	BIO_set_write_callback(b, &onwrite);
	BIO_set_write_arg(b, b);

	BIO_puts(b, "GET / HTTP/1.0\r\n\r\n");
	BIO_shutdown_wr(b);

	onread(b);

	BIO_poll(gpoller, -1);
	BIO_free_all(b);
	BIO_free_poller(gpoller);
	return 0;
}

