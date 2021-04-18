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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

// sgxstep headers
// extern "C" {
// #include "libsgxstep/apic.h"
// #include "libsgxstep/cpu.h"
// #include "libsgxstep/pt.h"
// #include "libsgxstep/sched.h"
// #include "libsgxstep/enclave.h"
// #include "libsgxstep/debug.h"
// #include "libsgxstep/idt.h"
// #include "libsgxstep/spy.h"
// #include "libsgxstep/config.h"
// }

#include "common/debug.h"
#include "common/pf.h"
#include "common/cacheutils.h"
#include <sys/mman.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

struct sigaction act; // sigaction action variable

/* Configuring required page-table info */
static uint64_t gcd_page_offset = 0x39240;
static uint64_t sub_page_offset = 0x53a50;
static uint64_t rShift1_page_offset = 0x357c50;
// static uint64_t modInversePageOffset = 0x596e0;

void *gcd_page = NULL, *sub_page = NULL, *rshift1_page = NULL;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);

    // ecall_print_something(global_eid);

}

void* get_base_addr(void* addr){
    return (void*) ((uint64_t)addr & 0xfffffffffffff000);
}

void pagefault_handler(void* base_addr){
    printf("pagefault_handler triggered\n");

    if(base_addr == gcd_page){
        printf("gcd_page\n");
        mprotect(base_addr, 0x1000, PROT_EXEC);
    }
    return;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    /* Utilize edger8r attributes */
    // edger8r_array_attributes();
    // edger8r_pointer_attributes();
    // edger8r_type_attributes();
    // edger8r_function_attributes();
    
    /* Utilize trusted libraries */
    // ecall_libc_functions();
    // ecall_libcxx_functions();
    // ecall_thread_functions();

    printf("registering fault handler..\n");
    register_fault_handler(pagefault_handler);

    /* Setting up page fault handler*/
    // memset(&act, '\0', sizeof(act));
    // act.sa_sigaction = &pagefault_handler;
    // act.sa_flags = SA_SIGINFO;
    // if(sigaction(SIGSEGV, &act, NULL) !=0)
    // {
    //     printf("Page fault handler code not setup correctly. Terminating!\n");
    //     sgx_destroy_enclave(global_eid);
    //     return 0;
    // }

    /* Setting up sgx-step */
    // register_enclave_info();
    // print_enclave_info();
    // printf("\n");
    // uint64_t enclave_base_addr = (uint64_t) get_enclave_base();

    // gcd_page = (void *)(enclave_base_addr | gcd_page_offset);

    // printf("gcd_page 0x%lx\n", gcd_page);

    // void* sq_pt;

    ecall_get_gcd_addr(global_eid, &gcd_page);
    gcd_page = get_base_addr(gcd_page);
    printf("gcd_page 0x%lx\n", gcd_page);

    mprotect(gcd_page, 0x1000, PROT_NONE);

    // int x = 2, y = 4;
    // int result;
    // sgx_status_t status = ecall_sum_ints(global_eid, &result, x, y);

    // if (status != SGX_SUCCESS)
	// {
	// 	printf("Ecall didn't return successfully. Terminating!\n");
    //     sgx_destroy_enclave(global_eid);
    //     return 0;
    // }

    // printf("Ecall returned successfully.\n");

    // printf("Result: %d\n", result);

    ecall_generate_RSA_key(global_eid);

    // ecall_print_something(global_eid);

    // ocall_print_string("xyz");
 
    

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("RSAEnclave worked successfully.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

