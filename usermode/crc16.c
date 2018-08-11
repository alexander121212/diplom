#include "crc16.h"

static inline unsigned short crc16_byte(unsigned short crc, const unsigned char data)
{
	return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

unsigned short crc16(unsigned short crc, unsigned char const *buffer, size_t len)
{
	while (len--) {
		crc = crc16_byte(crc, *buffer++);
	}

	return crc;
}
