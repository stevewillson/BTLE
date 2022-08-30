/** @file btle_utility.h
 *
 * @brief header file for btle_utility.c
 *
 *
 */
#ifndef BTLE_UTILITY_H
#define BTLE_UTILITY_H

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *toupper_str(char *input_str, char *output_str);
void  octet_hex_to_bit(char *hex, char *bit);
void  int_to_bit(int n, uint8_t *bit);
void  uint32_to_bit_array(uint32_t uint32_in, uint8_t *bit);
void  byte_array_to_bit_array(uint8_t *byte_in, int num_byte, uint8_t *bit);
int   convert_hex_to_bit(char *hex, char *bit);
void  disp_bit(char *bit, int num_bit);
void  disp_bit_in_hex(char *bit, int num_bit);
void  disp_hex(uint8_t *hex, int num_hex);
void  disp_hex_in_bit(uint8_t *hex, int num_hex);

#endif /* BTLE_UTILITY_H */
       /*** end of file ***/
