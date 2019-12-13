#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include "rip.h"
#include <stdio.h>

/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */

struct myNode{
  	RoutingTableEntry * entry;
  	myNode* next;
} ;

myNode* start = NULL;
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);

bool update(bool insert, RoutingTableEntry entry) {
	// TODO:
	if (insert) {
		// 插入
		myNode* temp = new myNode;
		RoutingTableEntry* entry_temp = new RoutingTableEntry;
		entry_temp->addr = entry.addr;
		entry_temp->len = entry.len;
		entry_temp->if_index = entry.if_index;
		entry_temp->nexthop = entry.nexthop;
		entry_temp->metric = entry.metric;
		entry_temp->time_stamp = entry.time_stamp;
		temp->entry = entry_temp;
		temp->next = NULL;
		if (start == NULL) {
			start = temp;
			return true;
		} else {
			myNode * temp2 = start;
			while(temp2 != NULL) {
				if (temp2->entry->addr == entry.addr && temp2->entry->len == entry.len && temp2->entry->metric > entry.metric) {
					// 替换
					temp2->entry->if_index = entry.if_index;
					temp2->entry->nexthop = entry.nexthop;
					temp2->entry->metric = entry.metric;
					temp2->entry->time_stamp = entry.time_stamp;
					return true;
					break;
				} else {
					temp2 = temp2->next;
				}
			}
			uint32_t* nhop, *iindex;
			if (!query(entry.addr, nhop, iindex)) {
				// 	添加
				temp->next = start;
				start = temp;
				return true;
			} else {
				// 不更新
				return false;
			}
		}
	} else {
		// 删除
		if (start->entry->addr == entry.addr && start->entry->len == entry.len) {
			myNode* del = start;
			start = start->next;
			delete del;
		} else {
			myNode * temp = start;
			myNode * next = temp->next;
			while (next != NULL) {
				if (next->entry->addr == entry.addr && next->entry->len == entry.len) {
					temp->next = next->next;
					delete next;
					break;
				} else {
					temp = next;
					next = next->next;
				}
			}
		}
	}
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
	// TODO:
	bool res = false;
	uint32_t len = 0;
	myNode* temp = start;
	while (temp != NULL) {
		if ((addr << (32 - temp->entry->len)) == ((temp->entry->addr) << (32 - temp->entry->len))) {
			if (temp->entry->len > len) {
				len = temp->entry->len;
				*nexthop = temp->entry->nexthop;
				*if_index = temp->entry->if_index;
				res = true;
			}
		}
		temp = temp->next;
	}
	return res;
}

/**
 * 构造rippacket结构体
 */
void genRipPack(uint32_t if_index, RipPacket* rip) {
	rip->numEntries = 0;
	rip->command = 0;
	myNode * temp = start;
	while (temp != NULL) {
		// 水平分割
		if (temp->entry->if_index != if_index) {
			rip->entries[rip->numEntries].addr = temp->entry->addr;
			rip->entries[rip->numEntries].nexthop = temp->entry->nexthop;
			rip->entries[rip->numEntries].mask = ((unsigned int)0xffffffff) >> (32 - temp->entry->len);
			rip->entries[rip->numEntries].metric =  temp->entry->metric;

			rip->numEntries++;
		}
		
		temp = temp->next;
	}
}

void printTable() {
	myNode * temp = start;
	while (temp != NULL) {
		printf("%d.%d.%d.%d/%d ", temp->entry->addr & 0xff, (temp->entry->addr >> 8) & 0xff, (temp->entry->addr >> 16) & 0xff, (temp->entry->addr >> 24) & 0xff, temp->entry->len);
		if (temp->entry->nexthop != 0) {
			printf("via %d.%d.%d.%d ", temp->entry->nexthop & 0xff, (temp->entry->nexthop >> 8) & 0xff, (temp->entry->nexthop >> 16) & 0xff, (temp->entry->nexthop >> 24) & 0xff);
		}
		printf("dev r2r%d ", temp->entry->if_index + 1);
		if (temp->entry->nexthop == 0) {
			printf("scope link");
		}
		printf("\n");
	}
}
