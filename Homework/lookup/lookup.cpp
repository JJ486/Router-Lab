#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

std::vector<RoutingTableEntry> RoutingTable;

void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  std::vector<RoutingTableEntry>::iterator it = RoutingTable.begin();
  bool flag = true;
  for (it; it != RoutingTable.end(); it++) {
    if (it->len == entry.len) {
      for (int i = 0; i < it->len / 8; i++) {
        if (it->addr.s6_addr[i] != entry.addr.s6_addr[i]) {
          flag = false;
          break;
        }
      }
      if (it->len % 8 != 0) {
        for (int i = 0; i < it->len % 8; i++) {
          if ((it->addr.s6_addr[it->len / 8] & (0x80 >> i)) != (entry.addr.s6_addr[it->len / 8] & (0x80 >> i))) {
            flag = false;
            break;
          }
        }
      }
      if (flag) {
        if (insert) {
          RoutingTable.erase(it);
          RoutingTable.push_back(entry);
        }
        else
          RoutingTable.erase(it);
        return;
      } else
        flag = true;
    }
  }
  if (insert && it == RoutingTable.end())
    RoutingTable.push_back(entry);
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  std::vector<RoutingTableEntry>::iterator it = RoutingTable.begin();
  int maxMatchLength = -1, tempMatchLength = 0;
  bool flag = true;
  std::vector<RoutingTableEntry>::iterator maxMatchAddr = RoutingTable.end();
  for (it; it != RoutingTable.end(); it++) {
    for (int i = 0; i < it->len / 8; i++) {
      if (it->addr.s6_addr[i] != addr.s6_addr[i]) {
        flag = false;
        break;
      }
      tempMatchLength += 8;
    }
    if (flag == false) {
      flag = true;
      tempMatchLength = 0;
      continue;
    } else {
      if (it->len % 8 != 0) {
        for (int i = 0; i < it->len % 8; i++) {
          if ((it->addr.s6_addr[it->len / 8] & (0x80 >> i)) != (addr.s6_addr[it->len / 8] & (0x80 >> i))) {
            flag = false;
            break;
          }
          tempMatchLength++;
        }
        if (flag == false) {
          flag = true;
          tempMatchLength = 0;
          continue;
        }
      }
      if (tempMatchLength > maxMatchLength) {
        maxMatchLength = tempMatchLength;
        maxMatchAddr = it;
      }
      tempMatchLength = 0;
    }
  }
  if (maxMatchAddr != RoutingTable.end()) {
    for (int i = 0; i < 16; i++) {
      nexthop->s6_addr[i] = maxMatchAddr->nexthop.s6_addr[i];
    }
    *if_index = maxMatchAddr->if_index;
  } else
    return false;
  return true;
}

int mask_to_len(const in6_addr mask) {
  // TODO
  int len = 0;
  bool flag = false;
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 8; j++) {
      if (!(mask.s6_addr[i] & (0x80 >> j))) {
        flag = true;
        break;
      }
      len++;
    }
    if (flag)
      break;
  }
  return len;
}

in6_addr len_to_mask(int len) {
  // TODO
  if (len > 128 || len < 0)
    return {};
  in6_addr mask;
  for (int i = 0; i < 16; i++) {
    mask.s6_addr[i] = 0;
  }
  for (int i = 0; i < len / 8; i++) {
    mask.s6_addr[i] = 0xFF;
  }
  for (int i = 0; i < len % 8; i++) {
    mask.s6_addr[len / 8] |= 0x80 >> i;
  }
  return mask;
}