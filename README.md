# X25519 for ARM Cortex-M4 and other ARM processors

This implements highly optimimzed assembler versions of X25519 for ARMv7. It's optimized for Cortex-M4 but works on other ARM processors as well (ARMv7 and newer 32-bit architectures).

## X25519
X25519 is an Elliptic curve version of the Diffie-Hellman protocol, using Curve25519 as the elliptic curve, as introduced in https://cr.yp.to/ecdh.html.

### API
```
void X25519_calc_public_key(uint8_t output_public_key[32], const uint8_t input_secret_key[32]);
void X25519_calc_shared_secret(uint8_t output_shared_secret[32], const uint8_t my_secret_key[32], const uint8_t their_public_key[32]);
```

* To use, first generate a 32 byte random value using a Cryptographically Secure Number Generator (specifically do NOT use `rand()` from the C library), which gives your secret key.
* Feed that secret key into `X25519_calc_public_key` which will give you the corresponding public key you then transfer to the other part. The other part does the same.
* When you get the other part's public key, feed that into `X25519_calc_shared_secret` together with your private key which will give you the shared secret. Rather than using this shared secret directly, it should be hashed (for example with SHA-256) on both sides before use. For further usage instructions see the official web site.

Note that this library automatically "clamps" the secret key for you (i.e. sets all the three lowest bits to 0 and the two highest to 0 and 1), compared to some other implementations.

### Setup
* The header file `x25519-cortex-m4.h` should be included when using the API from C/C++.
* For Keil, the file `x25519-cortex-m4-keil.s` must be added to the project as a Source file.
* When compiling with GCC, `x25519-cortex-m4-gcc.s` must be added to the project as a compilation unit. The compiler switch `-march=armv7-a`, `-march=armv7e-m` or similar might be needed depending on target architecture.

### Example
An example can be seen in `linux_example.c` that uses `/dev/urandom` to get random data. It can be compiled on for example Raspberry Pi 3 with:
```
gcc linux_example.c x25519-cortex-m4-gcc.s -o linux_example -march=armv7-a
```

### Performance
The library uses only 1892 bytes of code space in compiled form, uses 368 bytes of stack and runs one scalar multiplication in 548 873 cycles on Cortex-M4, which is speed record as far as I know. For a 64 MHz processor that means less than 9 ms per operation!

There is also an even more optimized version that uses the FPU which runs in 476 275 cycles on ARM Cortex-M4F.

### Code
The code is written in Keil's assembler format (`x25519-cortex-m4-keil.s`) but was converted to GCC's assembler syntax (`x25519-cortex-m4-gcc.s`) using the following regex command:
`perl -0777 -pe 's/^;/\/\//g;s/(\s);/\1\/\//g;s/export/\.global/g;s/(([a-zA-Z0-9_]+) proc[\W\w]+?)endp/\1\.size \2, \.-\2/g;s/([a-zA-Z0-9_]+) proc/\t\.type \1, %function\n\1:/g;s/end//g;s/(\r?\n)(\d+)(\r?\n)/\1\2:\3/g;s/%b(\d+)/\1b/g;s/%f(\d+)/\1f/g;s/(frame[\W\w]+?\n)/\/\/\1/g;s/area \|([^\|]+)\|[^\n]*\n/\1\n/g;s/align /\.align /g;s/^/\t.syntax unified\n\t.thumb\n/' < x25519-cortex-m4-keil.s > x25519-cortex-m4-gcc.s`

### Security
The basic implementation runs in constant time and uses a constant memory access pattern, regardless of the private key in order to protect against side channel attacks. The FPU version however reads data from RAM in a non-constant pattern and therefore that version is only suited for embedded devices without data cache, such as Cortex-M4 and Cortex-M33.

### License
The code is licensed under a 2-clause BSD license, with an extra exception for Nordic Semiconductor and Dialog Semiconductor devices.
