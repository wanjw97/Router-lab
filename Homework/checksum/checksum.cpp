#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
	// TODO:
	uint32_t sum = 0; // 初始化校验和
	uint16_t * pos = (uint16_t*)packet; // 数组求和位置
	uint32_t calc_times = 0;
	size_t header_len = (*(packet) & 0xf) * 4;
	// 数组求和
	while(header_len > 1) {
		if (calc_times != 5)
			sum += *pos;
		header_len -= 2;
		pos ++;
		calc_times++;
	}
	// 考虑最后剩8位没加
	if (header_len == 1) {
		sum += *(packet + header_len - 1);
	}

	// 有溢出部分加到低位，直到没有溢出为止
	while (sum > 0xffff) {
		sum = (sum >> 16) + (sum & 0xffff);
	}

	uint16_t myCheckSum = (~(sum)) & 0xffff;

	return (myCheckSum == *(uint16_t*)(packet + 10));
}
