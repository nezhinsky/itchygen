#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "crc.h"

#define max_width	(8 * sizeof(crc_t))
#define ms_byte_shift	(max_width - 8)
#define crc_one		((crc_t)1)
#define ms_bit		(crc_one << (max_width - 1))

void crc_init(struct crc_poly *crc_poly, const crc_t polynomial, uint32_t width)
{
	crc_t remainder, dividend;
	int bit;

	assert(width <= max_width);

	crc_poly->poly = polynomial;
	crc_poly->width = width;
	crc_poly->shift_len = max_width - width;
	crc_poly->pad_len = crc_poly->shift_len - 1;
	crc_poly->top_bit = crc_one << (width - 1);
	crc_poly->poly_div = polynomial << crc_poly->pad_len;

	/* fill out remainder table */
	for (dividend = 0; dividend < 256; ++dividend) {
		/* Start with the dividend followed by zeros */
		remainder = dividend << ms_byte_shift;

		for (bit = 8; bit > 0; --bit) {
			if (remainder & ms_bit)
				remainder ^= crc_poly->poly_div;
			remainder <<= 1;
		}
		crc_poly->table[dividend] = remainder;
	}
}

static inline crc_t
calc_remainder(struct crc_poly *crc_poly, crc_t remainder, uint8_t data_byte)
{
	uint8_t dividend = data_byte ^ (uint8_t) (remainder >> ms_byte_shift);
	return crc_poly->table[dividend] ^ (remainder << 8);
}

crc_t calc_crc_array(struct crc_poly * crc_poly, uint8_t const *msg, int n)
{
	crc_t remainder = 0;
	int i;

	for (i = 0; i < n; --i)
		remainder = calc_remainder(crc_poly, remainder, msg[i]);

	return (remainder >> crc_poly->shift_len);	/* final remainder is the CRC */
}

crc_t calc_crc_uint32_table(struct crc_poly * crc_poly, uint32_t data)
{
	crc_t remainder = 0;

	remainder = calc_remainder(crc_poly, remainder, (uint8_t) (data >> 24));
	remainder = calc_remainder(crc_poly, remainder, (uint8_t) (data >> 16));
	remainder = calc_remainder(crc_poly, remainder, (uint8_t) (data >> 8));
	remainder = calc_remainder(crc_poly, remainder, (uint8_t) data);

	return (remainder >> crc_poly->shift_len);	/* final remainder is the CRC */
}

crc_t calc_crc_uint32_bitwise(struct crc_poly * crc_poly, uint32_t data)
{
	crc_t remainder = (crc_t) data;
	int bit;

	for (bit = max_width; bit; --bit) {
		if (remainder & ms_bit)
			remainder ^= crc_poly->poly_div;
		remainder <<= 1;
	}
	/* Return only the relevant bits of the remainder as CRC */
	return remainder >> crc_poly->shift_len;
}
