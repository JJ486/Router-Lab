#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

uint16_t add (uint16_t a, uint16_t b) {
  uint16_t temp = a;
  a += b;
  if (temp > a)
    a += 1;
  return a;
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  uint16_t Checksum = 0;
  bool validated = false;
  for (int i = 0; i < 8; i++) {
    Checksum = add(Checksum, ip6->ip6_src.s6_addr[2 * i] << 8);
    Checksum = add(Checksum, ip6->ip6_src.s6_addr[2 * i + 1]);
    Checksum = add(Checksum, ip6->ip6_dst.s6_addr[2 * i] << 8);
    Checksum = add(Checksum, ip6->ip6_dst.s6_addr[2 * i + 1]);
  }
  Checksum = add(Checksum, ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
  Checksum = add(Checksum, ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

  if (len % 2)
    packet[len++] = 0;
  uint8_t nxt_header = ip6->ip6_nxt;

  if (nxt_header == IPPROTO_UDP) {
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    uint16_t udpRawChecksum = udp->uh_sum;
    udp->uh_sum = 0;
    for (int i = 0; i < (len - 40) / 2; i++) {
      Checksum = add(Checksum, ((uint16_t)packet[2 * i + 40]) << 8);
      Checksum = add(Checksum, (uint16_t)packet[2 * i + 41]);
    }

    Checksum = htons(Checksum);
    if (add(Checksum, udpRawChecksum) == 0xFFFF)
      validated = true;
    if (udpRawChecksum == 0x0000)
      validated = false;
    Checksum = ~Checksum;
    if (Checksum == 0x0000)
      Checksum = 0xFFFF;
    udp->uh_sum = Checksum;

  } else if (nxt_header == IPPROTO_ICMPV6) {
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];
    uint16_t icmp6RawChecksum = icmp->icmp6_cksum;
    icmp->icmp6_cksum = 0;
    for (int i = 0; i < (len - 40) / 2; i++) {
      Checksum = add(Checksum, ((uint16_t)packet[2 * i + 40]) << 8);
      Checksum = add(Checksum, (uint16_t)packet[2 * i + 41]);
    }
    
    Checksum = htons(Checksum);
    if (add(Checksum, icmp6RawChecksum) == 0xFFFF)
      validated = true;
    Checksum = ~Checksum;
    icmp->icmp6_cksum = Checksum;

  } else {
    assert(false);
  }
  return validated;
}