/* Curve25519 scalar multiplication
 * Copyright (c) 2017, Emil Lenngren
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA or Dialog Semiconductor PLC integrated circuit in a product
 *    or a software update for such product, must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * This is an armv7 implementation of X25519.
 * It follows the reference implementation where the representation of
 * a field element [0..2^255-19) is represented by a 256-bit little endian integer,
 * reduced modulo 2^256-38, and may possibly be in the range [2^256-38..2^256).
 * The scalar is a 256-bit integer where certain bits are hardcoded per specification.
 *
 * The implementation runs in constant time (548 873 cycles on ARM Cortex-M4,
 * assuming no wait states), and no conditional branches or memory access
 * pattern depend on secret data.
 */

#ifndef X25519_CORTEX_M4_H
#define X25519_CORTEX_M4_H

// Assembler function
void curve25519_scalarmult(unsigned char result[32], const unsigned char scalar[32], const unsigned char point[32]);

// User macros
#define X25519_calc_public_key(output_public_key, input_secret_key) do { \
    static const unsigned char basepoint[32] = {9}; \
    curve25519_scalarmult(output_public_key, input_secret_key, basepoint); \
} while(0)

#define X25519_calc_shared_secret(output_shared_secret, my_secret_key, their_public_key) \
curve25519_scalarmult(output_shared_secret, my_secret_key, their_public_key)

#endif
