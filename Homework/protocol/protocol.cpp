#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
	// TODO:
	// 判断总长度是否合法
	uint16_t total_length = ((uint16_t)*(packet + 2))  * 0x100 + (uint16_t)*(packet + 3);
	if ((uint32_t)total_length > len) {
		return false;
	}

	size_t header_len = (*(packet) & 0xf) * 4; // ip头长度

	uint8_t * rip = (uint8_t *)(packet + header_len + 8); // rip 信息起始位置

	int numEntries = 0;

	uint8_t command = *(rip++);
	uint8_t version = *(rip++);
	uint16_t zero = *(uint16_t*)rip;
	rip += 2;
	output->command = command;
	while (rip < packet + len) {	
		uint16_t family = (uint16_t)*rip * 0x100 + (uint16_t)*(rip + 1);
		rip += 2;
		uint16_t tag = (uint16_t)*rip * 0x100 + (uint16_t)*(rip + 1);
		rip += 2;

		uint32_t addr = *rip + (*(rip + 1)) * 0x100 + (*(rip + 2)) * 0x10000 + (*(rip + 3)) * 0x1000000;
		rip += 4;
		uint32_t netmask = *rip + (*(rip + 1)) * 0x100 + (*(rip + 2)) * 0x10000 + (*(rip + 3)) * 0x1000000;
		rip += 4;
		uint32_t nexthop = *rip + (*(rip + 1)) * 0x100 + (*(rip + 2)) * 0x10000 + (*(rip + 3)) * 0x1000000;
		rip += 4;
		uint32_t metric = *rip + (*(rip + 1)) * 0x100 + (*(rip + 2)) * 0x10000 + (*(rip + 3)) * 0x1000000;
		uint32_t metric_s = (uint32_t)*rip * 0x1000000 + (uint32_t)*(rip + 1) * 0x10000 + (uint32_t)*(rip + 2) * 0x100 + (uint32_t)*(rip + 3);
		rip += 4;

		if (zero != 0 || version != 2 || tag != 0) {
			return false;
		}
			
		if (!((command == 1 && family == 0)  ||  (command == 2 && family == 2))) {
			return false;
		}
			
		
		if (metric_s < 1 || metric_s > 16) {
			return false;
		}
			
		if ((netmask & (netmask + 1)) != 0) {
			return false;
		}
			
		output->entries[numEntries].addr = addr;
		output->entries[numEntries].mask = netmask;
		output->entries[numEntries].nexthop = nexthop;
		output->entries[numEntries].metric = metric;
		numEntries++;
	}

	output->numEntries = numEntries;
	
	return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
	// TODO:
	*(buffer++) = rip->command;
	*(buffer++) = 2; // version
	*(buffer++) = 0;
	*(buffer++) = 0; // zero

	for (int i = 0; i < rip->numEntries; i++)  {
		*(uint8_t*)(buffer + 1) = (rip->command == 1) ? 0 : 2; // family
		buffer += 2;
		*(uint16_t*)buffer = 0;	// tag
		buffer += 2;
		// addr
		*(buffer++) = rip->entries[i].addr & 0xff;
		*(buffer++) = (rip->entries[i].addr >> 8) & 0xff;
		*(buffer++) = (rip->entries[i].addr >> 16) & 0xff;
		*(buffer++) = (rip->entries[i].addr >> 24) & 0xff;

		// netmask
		*(buffer++) = rip->entries[i].mask & 0xff;
		*(buffer++) = (rip->entries[i].mask >> 8) & 0xff;
		*(buffer++) = (rip->entries[i].mask >> 16) & 0xff;
		*(buffer++) = (rip->entries[i].mask >> 24) & 0xff;

		// next hop
		*(buffer++) = rip->entries[i].nexthop & 0xff;
		*(buffer++) = (rip->entries[i].nexthop >> 8) & 0xff;
		*(buffer++) = (rip->entries[i].nexthop >> 16) & 0xff;
		*(buffer++) = (rip->entries[i].nexthop >> 24) & 0xff;

		// metric
		*(buffer++) = rip->entries[i].metric & 0xff;
		*(buffer++) = (rip->entries[i].metric >> 8) & 0xff;
		*(buffer++) = (rip->entries[i].metric >> 16) & 0xff;
		*(buffer++) = (rip->entries[i].metric >> 24) & 0xff;
	}	

	uint32_t length = 4 + rip->numEntries * 20;
	buffer = buffer - length;
	return length;
}
