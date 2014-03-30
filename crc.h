#ifndef __CRC_H__
#define __CRC_H__

#include <inttypes.h>

/* The width of the CRC calculation and result */
typedef uint32_t crc_t;

struct crc_poly {
	crc_t poly;
	crc_t poly_div;
	crc_t top_bit;

	size_t width;
	size_t pad_len;
	size_t shift_len;

	crc_t table[256];
};

void crc_init(struct crc_poly *crc_poly, const crc_t polynomial,
	      uint32_t width);
crc_t calc_crc_array(struct crc_poly *crc_poly, uint8_t const *msg, int n);
crc_t calc_crc_uint32_table(struct crc_poly *crc_poly, uint32_t data);
crc_t calc_crc_uint32_bitwise(struct crc_poly *crc_poly, uint32_t data);

#endif
