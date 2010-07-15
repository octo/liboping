/**
 * Object oriented C module to send ARP `echo's.
 * Copyright (C) 2010  Julien Ammous <j.ammous at gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "oping.h"
#include "oping_private.h"


/* #define PCAP_FILTER "arp" */
/* match arp reply packets sent to me originating from ip give */
/* "arp && ether dst 00:16:cb:07:4d:da && src 192.168.0.138 && arp[7] = 0x02" */
#define PCAP_FILTER "arp && ether dst %02x:%02x:%02x:%02x:%02x:%02x && arp[7] = 0x02"
#define PCAP_FILTER_LEN 60

static uint8_t ethnull[ETH_ALEN];
static uint8_t ethall[ETH_ALEN];

/* initialize structure
 * must be called after ping_construct */
int arp_init(pingobj_t *pingobj) {
  struct bpf_program arp_p;
  char pcap_filter[PCAP_FILTER_LEN];
  char ebuf[PCAP_ERRBUF_SIZE] = "\0";
  uint8_t *cp;
  
  bzero(ethnull, sizeof(ethnull));
  memset(ethall, 0xff, ETH_ALEN);
  
  /* libnet init */
  if( !(pingobj->ln = libnet_init(LIBNET_LINK_ADV, pingobj->device, ebuf)) ) {
      dprintf("libnet_init: %s\n", ebuf);
      return -1;
  }
  
  /* get interface mac address */
  cp = (uint8_t *) libnet_get_hwaddr(pingobj->ln);
  if( cp == NULL ) {
    dprintf("arping: libnet_get_hwaddr(): %s\n", libnet_geterror(pingobj->ln));
    return -1;
  }
  memcpy(pingobj->srcmac, cp, ETH_ALEN);
  
  dprintf("mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", 
      cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]
    );
  
  /* pcap init */
  if( !(pingobj->pcap = pcap_open_live(pingobj->device, 100, 0, 10, ebuf)) ) {
    dprintf("pcap_open_live failed: %s\n", ebuf);
    return -1;
  }
  
  if( strlen(ebuf) ) dprintf("warning: %s\n", ebuf);
  
  snprintf(pcap_filter, PCAP_FILTER_LEN, PCAP_FILTER, cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
  dprintf("pcap filter: %s\n", pcap_filter);
  
  /* compile pcap filter */
  if( pcap_compile(pingobj->pcap, &arp_p, pcap_filter, 0, -1) == -1 ) {
      dprintf("pcap_compile(): %s\n", pcap_geterr(pingobj->pcap));
      return -1;
  }
  
  if( pcap_setfilter(pingobj->pcap, &arp_p) == -1 ) {
      dprintf("pcap_setfilter(): %s\n", pcap_geterr(pingobj->pcap));
      return -1;
  }
  
  return 0;
}

/* below: to rewrite */

int arp_ping_send(pingobj_t *pingobj, pinghost_t *ph) {
  
  if( libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, ETH_ALEN, IP_ALEN, ARPOP_REQUEST,
      (uint8_t *) pingobj->srcmac,                              /* src mac address */
      (uint8_t *) &((struct sockaddr_in *) pingobj->srcaddr)->sin_addr,                   /* src ip address */
      ethnull,                                                  /* dst mac address */
      (uint8_t *) &(((struct sockaddr_in *) ph->addr)->sin_addr),   /* dest ip address */
      (u_int8_t *) ph->data,                                                 /* payload */
      strlen(ph->data),                                         /* payload size */
      pingobj->ln,
      0                                                         /* build new packet */
      ) == -1) {
        dprintf("libnet_build_arp: %s", libnet_geterror(pingobj->ln));
        return -1;
  }
  
  if( libnet_build_ethernet(
      ethall,                         /* dest mac address */
      (uint8_t *) pingobj->srcmac,    /* src mac address */
      ETHERTYPE_ARP, NULL, 0, pingobj->ln, 0) == -1) {
        dprintf("libnet_build_ethernet: %s", libnet_geterror(pingobj->ln));
        return -1;
  }
  
  if( gettimeofday(ph->timer, NULL) == -1 ) {
    timerclear( ph->timer );
    return -1;
  }
  
  ph->latency = -1.0;
  
  /* send packet */
  if( libnet_write(pingobj->ln) == -1 ) {
    dprintf("libnet_write: %s", libnet_geterror(pingobj->ln));
    return -1;
  }
  
  libnet_clear_packet(pingobj->ln);
  return 0;
}

/* wait for all the answers
 * return conditions:
 * - all answers received
 * - timeout reached
 */
void arp_pings_recv(pingobj_t *pingobj) {
  const uint8_t               *data;
  struct pcap_pkthdr          pkthdr;
  pinghost_t                  *host;
  uint32_t                    ip;
  struct libnet_ethernet_hdr  *heth;
  struct libnet_arp_hdr       *harp;
  struct timeval              diff;
  struct timeval              timeout, nowtime;
  
  int                         break_loop;
  
  if( gettimeofday(&nowtime, NULL) == -1 ) {
    dprintf("gettimeofday: %s\n", strerror(errno));
    return;
  }
  
  /* Set up timeout */
  timeout.tv_sec = (time_t) pingobj->timeout;
  timeout.tv_usec = (suseconds_t) (1000000 * (pingobj->timeout - ((double) timeout.tv_sec)));
  
  while (1) {
    data = pcap_next(pingobj->pcap, &pkthdr);
    if( data == NULL ) {
      dprintf("pcap_next returned NULL !\n");
      continue;
    }
    
    heth = (void*) data;
    harp = (void*)((char*)heth + LIBNET_ETH_H);
    
    memcpy(&ip, (char*)harp + harp->ar_hln + LIBNET_ARP_H, 4);
    
    /* check if the arp reply comes from a known host */
    for(host = pingobj->head; host != NULL; host = host->next) {
      
      timersub(&pkthdr.ts, host->timer, &diff);
      
      if( (host->latency >= 0.0) || (host->timeout_reached == 1) ) {
        continue;
      }
      
      if( ((struct sockaddr_in *) host->addr)->sin_addr.s_addr == ip ) {
        /* we found a matching host, compute latency */
        host->latency  = ((double) diff.tv_usec) / 1000000.0;
        host->latency += ((double) diff.tv_sec);
        
        dprintf("received ARP REPLY for %s\n", inet_ntoa( *((struct in_addr *) &ip)) );
      }
      
      timersub(&nowtime, host->timer, &diff);
      
      dprintf("timeout state: %f > %f\n", (diff.tv_sec * 1000.0) + (diff.tv_usec / 1000.0), pingobj->timeout*1000);
      
      if( ((double)diff.tv_sec + (diff.tv_usec / 1000000)) > pingobj->timeout ) {
        host->timeout_reached = 1;
      }
    }
    
    /* check if there are some hosts left */
    break_loop = 1;
    for(host = pingobj->head; host != NULL; host = host->next) {
      if( (host->timeout_reached == 0) && (host->latency < 0.0) ) {
        break_loop = 0;
        break;
      }
    }
    
    if( break_loop )
      break;
  }
}

int ping_send_all_arp(pingobj_t *obj) {
  pinghost_t *host;
  
  /* check if init is done */
  if( obj->ln == NULL ) {
    arp_init(obj);
  }
  
  for(host = obj->head; host != NULL; host = host->next) {
    if( arp_ping_send(obj, host) < 0 ) {
      return -1;
    }
  }
  
  return 0;
}

int ping_receive_all_arp(pingobj_t *obj) {
  arp_pings_recv(obj);
  return 0;
}
