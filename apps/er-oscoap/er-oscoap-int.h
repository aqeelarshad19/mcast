/*
Copyright (c) 2016, SICS
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the 
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the 
following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the 
following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote 
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * \file
 *      A trial implementation of OSCOAP. Based on er-coap by Matthias Kovatsch <kovatsch@inf.ethz.ch>
 * \author
 *      Martin Gunnarsson martin.gunnarsson@sics.se and Joakim Brorsson b.joakim@gmail.com
 */
#ifndef _OSCOAP_INT_H
#define _OSCOAP_INT_H

#include "er-coap.h"
#include <sys/types.h>

//#include "uthash.h"

#define CONTEXT_CID_LEN 2 
#define CONTEXT_KEY_LEN 16 
#define CONTEXT_INIT_VECT_LEN 7
#define CONTEXT_SEQ_LEN 4 


typedef struct OSCOAP_CONTEXT
{
	uint16_t	CONTEXT_ID; //16 bits should be enough of context for now
  uint8_t  	ALG;
  struct OSCOAP_CONTEXT *next;
	
  uint8_t	SENDER_WRITE_KEY[CONTEXT_KEY_LEN];
	uint8_t 	SENDER_WRITE_IV[CONTEXT_INIT_VECT_LEN];
  uint32_t   SENDER_WRITE_SEQ;
	
  uint8_t	RECEIVER_WRITE_KEY[CONTEXT_KEY_LEN];
	uint8_t	RECEIVER_WRITE_IV[CONTEXT_INIT_VECT_LEN];
  uint32_t   RECEIVER_WRITE_SEQ;

	//unsigned long REPLAY_WINDOW; //TODO add replay window support
}OSCOAP_CONTEXT;
/*
typedef struct OS_URI_CID
{
    char* uri;
    short uri_len;
    int cid;
    UT_hash_handle hh;
} OS_URI_CID;

typedef struct OS_TOKEN_CID
{
    char* token;
    int cid;
    UT_hash_handle hh;
} OS_TOKEN_CID;
*/

#define CONTEXT_SIZE sizeof(OSCOAP_CONTEXT)


#endif
