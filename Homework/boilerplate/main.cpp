#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t in_addr_t;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern bool update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void genRipPack(uint32_t if_index, RipPacket* rip);
extern uint16_t checkSum(uint8_t * packet);
extern void printTable();

uint32_t change_endian(uint32_t a) {
  return (a >> 24) + ((a >> 16) & 0xff) * 0x100 + ((a >> 8) & 0xff) * 0x10000 + (a & 0xff) * 0x1000000;
}

uint32_t mask2len(uint32_t mask) {
  for (uint32_t i  = 0; i < 32; i++) {
    if (((mask + 1) >> i) & 0x1 == 1) {
      return i ;
    }
  }
  return 32;
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0102000a, 0x0104a8c0, 0x0103000a};

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i] & 0x00FFFFFF, // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 0,
      .time_stamp = 0
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // TODO: send complete routing table to every interface
      // ref. RFC2453 Section 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      for (int j = 0; j < 4; j++) {
        RipPacket resp;
          // TODO: fill resp
          genRipPack((uint32_t)j, &resp);
          resp.command = 2;

          // assemble
          // IP
          output[0] = 0x45;
          output[1] = 0x0; // type of sevice
          output[2] = 0x0;    // total length
          output[3] = 0x0;
          output[4] = 0x0;  // identification
          output[5] = 0x0;
          output[6] = 0x0; // flags
          output[7] = 0x0;
          output[8] = 0x1; // TTL
          output[9] = 0x11; // protocal
          output[10] = 0x0; // checksum
          output[11] = 0x0;
          output[12] = (addrs[j] >> 24) & 0xff; // src addr
          output[13] = (addrs[j] >> 16) & 0xff;
          output[14] = (addrs[j] >> 8) & 0xff;
          output[15] = addrs[j] & 0xff;
          output[16] = 0xe0; // dst addr
          output[17] = 0x00;
          output[18] = 0x00;
          output[19] = 0x09;

          // ...
          // UDP
          // port = 520
          output[20] = 0x02; // src port
          output[21] = 0x08;
          output[22] = 0x02; // dst port
          output[23] = 0x08;
          output[24] = 0x00; // length
          output[25] = 0x00;
          output[26] = 0x00; // checksum
          output[27] = 0x00;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // calc len for ip header and udp header
          uint16_t ip_len = rip_len + 20 + 8;
          uint16_t udp_len = rip_len + 8;
          output[2] = ip_len >> 8;
          output[3] = ip_len & 0xff;
          output[24] = udp_len >> 8;
          output[25] = udp_len & 0xff;
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          uint16_t checksum = checkSum(output);
          output[10] = checksum >> 8;
          output[11] = checksum & 0xff;
          // send it back
          macaddr_t mac_addr;
          mac_addr[0] = 0x01;
          mac_addr[1] = 0x00;
          mac_addr[2] = 0x5e;
          mac_addr[3] = 0x00;
          mac_addr[4] = 0x00;
          mac_addr[5] = 0x09;
          HAL_SendIPPacket(j, output, rip_len + 20 + 8, mac_addr);
      }
      printf("5s Timer\n");
      // TODO: print complete routing table to stdout/stderr
      printTable();
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
		src_addr = *(packet + 12) + (*(packet + 13)) * 0x100 + (*(packet + 14)) * 0x10000 + (*(packet + 15)) * 0x1000000;
		dst_addr = *(packet + 16) + (*(packet + 17)) * 0x100 + (*(packet + 18)) * 0x10000 + (*(packet + 19)) * 0x1000000;

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?
		if (dst_addr == 0x90000e0) {
			dst_is_me = true;
		}


		// 3a
    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // request
          RipPacket resp;
          // TODO: fill resp
          genRipPack(if_index, &resp);
          resp.command = 2;

          // assemble
          // IP
          output[0] = 0x45;
          output[1] = 0x0; // type of sevice
          output[2] = 0x0;    // total length
          output[3] = 0x0;
          output[4] = 0x0;  // identification
          output[5] = 0x0;
          output[6] = 0x0; // flags
          output[7] = 0x0;
          output[8] = 0x1; // TTL
          output[9] = 0x11; // protocal
          output[10] = 0x0; // checksum
          output[11] = 0x0;
          output[12] = (addrs[if_index] >> 24) & 0xff; // src addr
          output[13] = (addrs[if_index] >> 16) & 0xff;
          output[14] = (addrs[if_index] >> 8) & 0xff;
          output[15] = addrs[if_index] & 0xff;
          output[16] = *(packet + 12); // dst addr
          output[17] = *(packet + 13);
          output[18] = *(packet + 14);
          output[19] = *(packet + 15);

          // ...
          // UDP
          // port = 520
          output[20] = 0x02; // src port
          output[21] = 0x08;
          output[22] = 0x02; // dst port
          output[23] = 0x08;
          output[24] = 0x00; // length
          output[25] = 0x00;
          output[26] = 0x00; // checksum
          output[27] = 0x00;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          // calc len for ip header and udp header
          uint16_t ip_len = rip_len + 20 + 8;
          uint16_t udp_len = rip_len + 8;
          output[2] = ip_len >> 8;
          output[3] = ip_len & 0xff;
          output[24] = udp_len >> 8;
          output[25] = udp_len & 0xff;
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          uint16_t checksum = checkSum(output);
          output[10] = checksum >> 8;
          output[11] = checksum & 0xff;
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // response
          // TODO: use query and update
          bool has_updated = false;
          for (int i = 0; i < rip.numEntries; i++) {
            // update routing table
            RoutingTableEntry entry = {
              .addr = rip.entries[i].addr,
              .len = mask2len(rip.entries[i].mask),
              .if_index = if_index,
              .nexthop = src_addr,
              .metric = change_endian(change_endian(rip.entries[i].metric) + 1),
              .time_stamp = time
            };
            entry.addr = ((unsigned int)(entry.addr << entry.len)) >> entry.len;
            if (rip.entries[i].nexthop == 0) {
              entry.metric = 0x1000000;
            }
            if (entry.metric == 0x11000000) {
              update(false, entry);
            }
            else {
              if (update(true, entry)) {
                has_updated = true;
              }
            }
            
          }
          if (has_updated) {
            // print rounting table
            printTable();
          }
        }
      } else {
				// 3b
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(dst_addr, &nexthop, &dest_if)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
            // you can drop it
            printf("ARP not found for nexthop %x\n", nexthop);
          }
        } else {
          // not found
          // TODO(optional): send ICMP Host Unreachable
          printf("IP not found for src %x dst %x\n", src_addr, dst_addr);
        }
      }
    }
  }
  return 0;
}