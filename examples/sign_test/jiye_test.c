#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "edsign.h"
#include "contiki.h"

uint8_t public_key[32];
uint8_t private_key[32];
uint8_t signature[64];


void print_hex(const char *label, const uint8_t *data, int len)
{
  int i;

  printf("%s: ", label);
  for (i = 0; i < len; i++)
    printf("%02x", data[i]);
  printf("\n");
}

PROCESS(hello_sign_process, "Hello sign process");
AUTOSTART_PROCESSES(&hello_sign_process);

PROCESS_THREAD(hello_sign_process, ev, data) {
  PROCESS_BEGIN();
  uint8_t msg[5] = {1,2,3,4,5};
  printf("Running\n");
  printf("Key generating....\n");
  edsign_sec_to_pub(public_key, private_key);
  printf("Key pair generated! \n");
  print_hex("publickey", public_key, 32);
  print_hex("privatekey", private_key, 32);
  printf("Making signature...\n");
  edsign_sign(signature, public_key, private_key, msg, 5);
  print_hex("signature", signature, 64);
  printf("verifying ...\n");
  assert(edsign_verify(signature, public_key, msg, 5 ));
  printf("verified!\n");

  PROCESS_END();
}

