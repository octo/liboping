#include <oping.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <string.h>

#include <arpa/inet.h>

#define DATA "=TOTO="

#define FUNCTION_ERROR(FORMAT, ARGS...) printf(FORMAT, ## ARGS); return -1

int main (int argc, char const *argv[])
{
  pingobj_t       *ping;
  pinghost_t      *ph;
  struct ifaddrs  *addrs, *addr;
  char            *ip;
  bool            found = false;
  char            source_address[INET_ADDRSTRLEN + 1];
  
  
  if( argc < 3 ) {
    printf("Usage: %s <interface> <destination>\n", argv[0]);
    exit(1);
  }
  
  ping = ping_construct();
  if( ping == NULL ) {
    FUNCTION_ERROR("ping_construct failed\n");
  }
  
  // find the ip address attached to the interface we wants to bind on
  // if more than one address are attached to the interface just
  // take the first one
  //
  if( getifaddrs(&addrs) < 0 ) {
    FUNCTION_ERROR("Unable to get interface addresses");
  }
  
  for(addr = addrs; addr != NULL; addr = addr->ifa_next) {
    // check if this is the interface we want
    if( (strcmp(addr->ifa_name, argv[1]) == 0) && (addr->ifa_addr->sa_family == AF_INET) ) {
      // convert addr to human form
      ip = inet_ntoa(((struct sockaddr_in *)addr->ifa_addr)->sin_addr);
      strncpy((char *) source_address, ip, INET_ADDRSTRLEN);
      printf("%s : %s\n", addr->ifa_name, ip);
      found = true;
      break;
    }
  }
  
  if( found == false ) {
    FUNCTION_ERROR("Unable to find address for interface <%s>", argv[1]);
  }
  
  if( ping_setopt(ping, PING_OPT_SOURCE, (void*) source_address) != 0 ) {
    FUNCTION_ERROR("Setting source address to %s on %s failed: %s\n", 
      source_address, argv[1], ping_get_error(ping));
  }
  
  if( ping_setopt(ping, PING_OPT_DEVICE, (void *) argv[1]) != 0 ) {
    FUNCTION_ERROR("Setting source interface to %s failed: %s\n", 
      argv[1], ping_get_error(ping));
  }
  
  // payload
  if( ping_setopt(ping, PING_OPT_DATA, (void *) DATA) != 0 ) {
    FUNCTION_ERROR("Setting payload failed: %s\n", ping_get_error(ping));
  }
  
  // add the hosts
  for(int i= 2; i< argc; i++) {
    if( ping_host_add(ping, argv[i]) < 0 ) {
      FUNCTION_ERROR("Unable to add host '%s' : %s\n", argv[i], ping_get_error(ping));
    }
  }
  
  if( arp_init(ping) < 0 ) {
    FUNCTION_ERROR("arp_init failed\n");
  }
  
  ping->use_arp = 1;
  
  for(int i = 0; i< 4; i++) {
    ping_send(ping);
  
    for( ph = ping->head; ph != NULL; ph = ph->next ) {
      printf("latency [%s]: %f\n", inet_ntoa(((struct sockaddr_in *)ph->addr)->sin_addr), ph->latency * 1000);
    }
  }
  
  return 0;
}

