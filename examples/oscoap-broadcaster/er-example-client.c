/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      Erbium (Er) CoAP client example.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "er-coap-engine.h"
#include "dev/button-sensor.h"
#include "er-oscoap.h"
#include "sha.h"

#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINTF_HEX(data, len) oscoap_printf_hex(data, len)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]", (lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3], (lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

/* FIXME: This server address is hard-coded for Cooja and link-local for unconnected border router. */
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0212, 0x7402, 0x0002, 0x0202)      /* cooja2 */
/* #define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xbbbb, 0, 0, 0, 0, 0, 0, 0x1) */

//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0xc30c, 0, 0, 0x0001)      /* */
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xff1e, 0, 0, 0, 0, 0, 0x89, 0xabcd)      /* */

#define LOCAL_PORT      UIP_HTONS(COAP_DEFAULT_PORT + 1)
#define REMOTE_PORT     UIP_HTONS(COAP_DEFAULT_PORT)
#define TOGGLE_INTERVAL 30
#define GEN_KEYLEN 16
#define GEN_IVLEN 8

PROCESS(er_example_client, "Erbium Example Client");
AUTOSTART_PROCESSES(&er_example_client);

uip_ipaddr_t server_ipaddr;
static struct etimer et;

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 5
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char *service_urls[NUMBER_OF_URLS] =
{ ".well-known/core", "/actuators/toggle", "battery/", "error/in//path", "/test/hello" };
#if PLATFORM_HAS_BUTTON
static int uri_switch = 0;
#endif

/* Because er-oscoap.c DEBUG mode is off, added here for printing log. */
void oscoap_printf_hex2(unsigned char *data, unsigned int len)
{                  
  int i=0;
  for(i=0; i<len; i++)
  {
    printf(" %02x ",data[i]);
  }
  PRINTF("\n");
}

/* This function is will be passed to COAP_BLOCKING_REQUEST() to handle responses. */
void client_chunk_handler(void *response)
{
  const uint8_t *chunk;

  int len = coap_get_payload(response, &chunk);
  printf("|%.*s", len, (char *)chunk);
  printf("\n");
}

PROCESS_THREAD(er_example_client, ev, data)
{
  PROCESS_BEGIN();

  static coap_packet_t request[1];      /* This way the packet can be treated as pointer as usual. */

  SERVER_NODE(&server_ipaddr);

  /* receives all CoAP messages */
  coap_init_engine();


#if PLATFORM_HAS_BUTTON
  SENSORS_ACTIVATE(button_sensor);
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif

  oscoap_ctx_store_init();
  uint8_t cid[CONTEXT_ID_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0x02};
  char master_secret[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
  char sender_key[] =   {0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41};
  char receiver_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
  char sender_iv[] = {0x47, 0x47, 0x47, 0x47, 0x47, 0x47, 0x47 };
  char receiver_iv[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 };

  // HKDF
  //uint8_t generated_key[GKEYLEN]= {0};
  hkdf(SHA256, 0, 0, master_secret, 16, "SenderKey", 9, sender_key, GEN_KEYLEN);
  //memcpy(sender_key, generated_key, GEN_KEYLEN); 
  printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"); 
  oscoap_printf_hex2(sender_key, GEN_KEYLEN);

  hkdf(SHA256,0, 0, master_secret, 16, "IV", 2, sender_iv, GEN_IVLEN);
  //memcpy(sender_iv, generated_key, GEN_IVLEN);
  oscoap_printf_hex2(sender_iv, GEN_IVLEN);

  if(oscoap_new_ctx( cid, sender_key, sender_iv, receiver_key, receiver_iv) == 0){
    printf("Error creating context!\n");
  }


  OSCOAP_COMMON_CONTEXT* c = NULL;
  uint8_t cid2[CONTEXT_ID_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0x02};
  c = oscoap_find_ctx_by_cid(cid2);
  PRINTF("COAP max size %d\n", COAP_MAX_PACKET_SIZE);
  if(c == NULL){
    printf("could not fetch cid\n");
  }else{
    printf("Context sucessfully added to DB!\n");
    printf("!!!!!!!!!!!!!!!!!!!Server ID  is %u \n", c->SENDER_CONTEXT->SENDER_ID);
  }

  printf("server ip poither %p\n", &server_ipaddr);

  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

#if PLATFORM_HAS_BUTTON
  SENSORS_ACTIVATE(button_sensor);
  printf("Press a button to request %s\n", service_urls[uri_switch]);
#endif

  while(1) {
    PROCESS_YIELD();


    if(etimer_expired(&et)) {
      printf("\n --Get test/hello-- \n");

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);

      //TODO, this should be implemented using the uri -> cid map, not like this.
      uint8_t cid3[CONTEXT_ID_LEN] = { 0, 0, 0, 0, 0, 0, 0, 0x02};
      request->context = oscoap_find_ctx_by_cid(cid3);

      coap_set_header_uri_path(request, service_urls[4]);

      char* u_buffer;
      int uri_len = coap_get_header_uri_path(request, &u_buffer);
      printf("ubuf: %s\n",u_buffer);

      coap_set_header_object_security(request);
      //request->ipaddr = &server_ipaddr;
      char token[] = { 0x05, 0x05};
      coap_set_token(request, token, 2);
      printf("--Requesting %s--\n", service_urls[4]);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
          client_chunk_handler);

      printf("\n--Done--\n");

      etimer_reset(&et);

#if PLATFORM_HAS_BUTTON
    } else if(ev == sensors_event && data == &button_sensor) {

      /* send a request to notify the end of the process */

      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      printf("--Requesting %s--\n", service_urls[uri_switch]);

      PRINT6ADDR(&server_ipaddr);
      PRINTF(" : %u\n", UIP_HTONS(REMOTE_PORT));

      COAP_BLOCKING_REQUEST(&server_ipaddr, REMOTE_PORT, request,
          client_chunk_handler);

      printf("\n--Done--\n");

      uri_switch = (uri_switch + 1) % NUMBER_OF_URLS;
#endif
    }
  }

  PROCESS_END();
}
