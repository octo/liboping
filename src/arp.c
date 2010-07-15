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

#include "config.h"

#include <stdlib.h>

#if HAVE_STDINT_H
# include <stdint.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#endif

#include "oping.h"
#include "oping_private.h"

/*
 * Private functions
 */
static int arp_ping_send(pingobj_t *pingobj, pinghost_t *ph) /* {{{ */
{
  uint8_t ethnull[ETH_ALEN];
  uint8_t ethall[ETH_ALEN];
  libnet_ptag_t status;

  /* sender's protocol address */
  void *spa;
  /* targer protocol address */
  void *tpa;

  /* TODO: Check if this is an IPv4 address. If not, return an appropriate
   * error. */

  memset (ethnull, 0x00, sizeof (ethnull));
  memset (ethall,  0xff, sizeof (ethall));

  spa = &((struct sockaddr_in *) pingobj->srcaddr)->sin_addr;
  tpa = &((struct sockaddr_in *) ph->addr)->sin_addr;

  status = libnet_build_arp
  (
      /*   hardware address format */ ARPHRD_ETHER,
      /*   protocol address format */ ETHERTYPE_IP,
      /*   hardware address length */ ETH_ALEN,
      /*   protocol address length */ IP_ALEN,
      /*        ARP operation type */ ARPOP_REQUEST,
      /* sender's hardware address */ pingobj->srcmac,
      /* sender's protocol address */ spa,
      /*   target hardware address */ ethnull,
      /*   targer protocol address */ tpa,
      /*                   payload */ (uint8_t *) ph->data,
      /*            payload length */ (uint32_t) strlen (ph->data),
      /*            libnet context */ pingobj->ln,
      /*    build new protocol tag */ 0
  );
  if (status == -1)
  {
    dprintf("libnet_build_arp: %s", libnet_geterror(pingobj->ln));
    return -1;
  }
  
  status = libnet_build_ethernet
  (
      /* destination ethernet address */ ethall,
      /*      source ethernet address */ pingobj->srcmac,
      /*    upper layer protocol type */ ETHERTYPE_ARP,
      /*                      payload */ NULL,
      /*               payload length */ 0,
      /*               libnet context */ pingobj->ln,
      /*       build new protocol tag */ 0
  );
  if (status == -1)
  {
    dprintf("libnet_build_ethernet: %s", libnet_geterror(pingobj->ln));
    return -1;
  }
  
  if (gettimeofday (ph->timer, NULL) == -1)
  {
    timerclear (ph->timer);
    libnet_clear_packet (pingobj->ln);
    return -1;
  }
  
  ph->latency = -1.0;
  
  /* send packet */
  if (libnet_write(pingobj->ln) == -1)
  {
    libnet_clear_packet(pingobj->ln);
    dprintf ("libnet_write: %s", libnet_geterror(pingobj->ln));
    return -1;
  }
  
  libnet_clear_packet(pingobj->ln);
  return 0;
} /* }}} int arp_ping_send */

/* wait for all the answers
 * return conditions:
 * - all answers received
 * - timeout reached
 */
static void arp_pings_recv(pingobj_t *pingobj) /* {{{ */
{
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
} /* }}} void arp_pings_recv */

/*
 * Semi-public functions
 * (can be called from liboping.c)
 */
int ping_construct_arp (pingobj_t *pingobj) /* {{{ */
{
  struct bpf_program arp_p;
  char mac_addr[20];
  char pcap_filter[256];
  char ebuf[PCAP_ERRBUF_SIZE];
  uint8_t *cp;

  if (pingobj == NULL)
    return (EINVAL);

  /* Initialize the pointers only used here. The "memset (0)" in
   * "ping_construct" may not initialize them to NULL. */
  pingobj->pcap = NULL;
  pingobj->ln = NULL;

  memset (ebuf, 0, sizeof (ebuf));
  
  /* libnet init */
  pingobj->ln = libnet_init(LIBNET_LINK_ADV, pingobj->device, ebuf);
  if(pingobj->ln == NULL)
  {
    dprintf("libnet_init: %s\n", ebuf);
    return -1;
  }
  
  /* get interface mac address */
  cp = (uint8_t *) libnet_get_hwaddr(pingobj->ln);
  if (cp == NULL)
  {
    dprintf("arping: libnet_get_hwaddr(): %s\n", libnet_geterror(pingobj->ln));
    return -1;
  }
  memcpy(pingobj->srcmac, cp, ETH_ALEN);
  
  snprintf (mac_addr, sizeof (mac_addr),
      "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8,
      cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
  mac_addr[sizeof (mac_addr) - 1] = 0;
  dprintf("ping_construct_arp: mac_addr = %s\n", mac_addr);
  
  /* pcap init */
  pingobj->pcap = pcap_open_live (pingobj->device, 100, 0, 10, ebuf);
  if (pingobj->pcap == NULL)
  {
    libnet_destroy (pingobj->ln);
    pingobj->ln = NULL;
    dprintf("pcap_open_live failed: %s\n", ebuf);
    return -1;
  }
  
  if (strlen(ebuf) > 0)
    dprintf("warning: %s\n", ebuf);
  
  snprintf (pcap_filter, sizeof (pcap_filter),
      "arp && ether dst %s && arp[7] = 0x02",
      mac_addr);
  dprintf("ping_construct_arp: pcap_filter = %s\n", pcap_filter);
  
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
} /* }}} int ping_construct_arp */

void ping_destroy_arp (pingobj_t *obj) /* {{{ */
{
  if (obj == NULL)
    return;

  if (obj->pcap != NULL)
  {
    pcap_close (obj->pcap);
    obj->pcap = NULL;
  }

  if (obj->ln != NULL)
  {
    libnet_destroy (obj->ln);
    obj->ln = NULL;
  }
} /* }}} void ping_destroy_arp */

int ping_send_all_arp (pingobj_t *obj) /* {{{ */
{
  pinghost_t *host;

  if ((obj == NULL) || (obj->ln == NULL) || (obj->pcap == NULL))
    return (EINVAL);
  
  for (host = obj->head; host != NULL; host = host->next)
    if (arp_ping_send (obj, host) < 0)
      return (-1);
  
  return (0);
} /* }}} int ping_send_all_arp */

int ping_receive_all_arp (pingobj_t *obj) /* {{{ */
{
  if ((obj == NULL) || (obj->ln == NULL) || (obj->pcap == NULL))
    return (EINVAL);

  arp_pings_recv (obj);
  return 0;
} /* }}} int ping_receive_all_arp */

/* vim: set sw=2 sts=2 et fdm=marker : */
