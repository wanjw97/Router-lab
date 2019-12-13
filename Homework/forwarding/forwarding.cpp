#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */

 uint16_t checkSum(uint8_t * packet) {
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
    return myCheckSum;
 }

bool forward(uint8_t *packet, size_t len) {
    // TODO:

	uint16_t myCheckSum = checkSum(packet);

	if (myCheckSum == *(uint16_t*)(packet + 10)){
        packet[8]--;
        uint16_t temp = checkSum(packet);
        packet[11] = temp >> 8;
        packet[10] = temp & 0xff;
        return true;
    } else {
        return false;
    }
}
