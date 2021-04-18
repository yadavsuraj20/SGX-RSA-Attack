/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int ecall_sum_ints(int x, int y){
    printf("Executing sum...\n");
    int z = x+y;
    return z;
}

void ecall_print_something(){
    printf("Something!\n");
}

void ecall_generate_RSA_key(){
    printf("Generating RSA key...\n");
    
    // generate RSA key using OpenSSL
    RSA *r = NULL;

    const BIGNUM *bnn, *bnp = NULL, *bnq = NULL, *bne = NULL, *bnd = NULL;
    unsigned long e = RSA_F4; // default e = 0x10001
    
    BIGNUM *bn_exp = BN_new();
    if(!BN_set_word(bn_exp, e)){
        // free and exit
    }

    r = RSA_new();
    if(!RSA_generate_key_ex(r, 2048, bn_exp, NULL)){
        // free and exit
    }

    RSA_get0_key(r, &bnn, &bne, &bnd);
    RSA_get0_factors(r, &bnp, &bnq);

    // BN_gcd()

}

void* ecall_get_gcd_addr(void)
{
    return (void*)BN_gcd;
}

// https://www.dynamsoft.com/codepool/how-to-use-openssl-generate-rsa-keys-cc.html
// https://www.openssl.org/docs/man1.1.1/man3/RSA_get0_key.html