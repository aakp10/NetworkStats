#include <iostream>
#include <cassert>
#include "packet.h"
#include <ifaddrs.h>

bool sameinaddr(in_addr one, in_addr other) {
  return one.s_addr == other.s_addr;
}

bool samein6addr(in6_addr one, in6_addr other) {
  return std::equal(one.s6_addr, one.s6_addr + 16, other.s6_addr);
}

/* 2 packets match if they have the same
 * source and destination ports and IP's. */
bool Packet_match(Packet *pk,Packet *other) {
  return pk->sa_family == other->sa_family && (pk->sport == other->sport) &&
         (pk->dport == other->dport) &&
         (pk->sa_family == AF_INET
              ? (sameinaddr(pk->sip, other->sip)) && (sameinaddr(pk->dip, other->dip))
              : (samein6addr(pk->sip6, other->sip6)) &&
                    (samein6addr(pk->dip6, other->dip6)));
}

bool Packet_matchSource(Packet *pk,Packet *other) {
  return (pk->sport == other->sport) && (sameinaddr(pk->sip, other->sip));
}
