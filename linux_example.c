#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "x25519-cortex-m4.h"

static int rand_fd = -1;

static void init_rand(void) {
	rand_fd = open("/dev/urandom", O_RDONLY);
	if (rand_fd < 0) {
		perror("opening /dev/urandom");
		exit(1);
	}
}

static void get_random_bytes(unsigned char* buf, int len) {
	if (rand_fd == -1) {
		fprintf(stderr, "rand_fd not initialized\n");
		exit(1);
	}

	int nread = 0;
	while (len) {
		int nbytes = read(rand_fd, buf + nread, len);
		if (nbytes < 0) {
			if (errno == EINTR) {
				continue;
			}
			perror("get_random_bytes");
			exit(1);
		}
		if (nbytes == 0) {
			fprintf(stderr, "rand_fd closed\n");
			exit(1);
		}
		nread += nbytes;
		len -= nbytes;
	}
}

int main() {
	unsigned char secret_key_alice[32], secret_key_bob[32];
	unsigned char public_key_alice[32], public_key_bob[32];
	unsigned char shared_secret_alice[32], shared_secret_bob[32];

	init_rand();

	// Alice computes
	get_random_bytes(secret_key_alice, 32);
	X25519_calc_public_key(public_key_alice, secret_key_alice);

	// Bob computes
	get_random_bytes(secret_key_bob, 32);
	X25519_calc_public_key(public_key_bob, secret_key_bob);

	// The public keys are now exchanged over some protocol

	// Alice computes
	X25519_calc_shared_secret(shared_secret_alice, secret_key_alice, public_key_bob);

	// Bob computes
	X25519_calc_shared_secret(shared_secret_bob, secret_key_bob, public_key_alice);

	if (memcmp(shared_secret_alice, shared_secret_bob, 32) == 0) {
		puts("SUCCESS: Both Bob and Alice computed the same shared secret");
	} else {
		puts("FAILED: Bob and Alice did not compute the same shared secret");
		exit(1);
	}

	return 0;
}
