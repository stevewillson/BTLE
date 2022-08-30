/** @file btle_utility.c
 *
 * @brief btle_utility.c provides utility functions for the btle program
 *
 *
 */

#include "../include/btle_utility.h"

char *
toupper_str(char *input_str, char *output_str)
{
    int len_str = strlen(input_str);
    int i;

    for (i = 0; i <= len_str; i++)
    {
        output_str[i] = toupper(input_str[i]);
    }

    return (output_str);
}

void
octet_hex_to_bit(char *hex, char *bit)
{
    char tmp_hex[3];

    tmp_hex[0] = hex[0];
    tmp_hex[1] = hex[1];
    tmp_hex[2] = 0;

    int n = strtol(tmp_hex, NULL, 16);

    bit[0] = 0x01 & (n >> 0);
    bit[1] = 0x01 & (n >> 1);
    bit[2] = 0x01 & (n >> 2);
    bit[3] = 0x01 & (n >> 3);
    bit[4] = 0x01 & (n >> 4);
    bit[5] = 0x01 & (n >> 5);
    bit[6] = 0x01 & (n >> 6);
    bit[7] = 0x01 & (n >> 7);
}

void
int_to_bit(int n, uint8_t *bit)
{
    bit[0] = 0x01 & (n >> 0);
    bit[1] = 0x01 & (n >> 1);
    bit[2] = 0x01 & (n >> 2);
    bit[3] = 0x01 & (n >> 3);
    bit[4] = 0x01 & (n >> 4);
    bit[5] = 0x01 & (n >> 5);
    bit[6] = 0x01 & (n >> 6);
    bit[7] = 0x01 & (n >> 7);
}

/*!
 * @brief convert a 32 bit uint to a bit array
 *
 * @param uint32_in 32 bit value
 * @param bit pointer to an array of 8 bit
 * values to store the bits of uint32_in
 *
 * @return void
 */
void
uint32_to_bit_array(uint32_t uint32_in, uint8_t *bit)
{
    uint32_t uint32_tmp = uint32_in;
    for (int i = 0; i < 32; i++)
    {
        bit[i]     = 0x01 & uint32_tmp;
        uint32_tmp = (uint32_tmp >> 1);
    }
}

void
byte_array_to_bit_array(uint8_t *byte_in, int num_byte, uint8_t *bit)
{
    int j;
    j = 0;
    for (int i = 0; i < num_byte * 8; i = i + 8)
    {
        int_to_bit(byte_in[j], bit + i);
        j++;
    }
}

int
convert_hex_to_bit(char *hex, char *bit)
{
    int num_hex = strlen(hex);
    while (hex[num_hex - 1] <= 32 || hex[num_hex - 1] >= 127)
    {
        num_hex--;
    }

    if (num_hex % 2 != 0)
    {
        printf("convert_hex_to_bit: Half octet is encountered! num_hex %d\n",
               num_hex);
        printf("%s\n", hex);
        return EXIT_FAILURE;
    }

    int num_bit = num_hex * 4;

    int i, j;
    for (i = 0; i < num_hex; i = i + 2)
    {
        j = i * 4;
        octet_hex_to_bit(hex + i, bit + j);
    }

    return (num_bit);
}

void
disp_bit(char *bit, int num_bit)
{
    int bit_val;
    for (int i = 0; i < num_bit; i++)
    {
        bit_val = bit[i];
        if (i % 8 == 0 && i != 0)
        {
            printf(" ");
        }
        else if (i % 4 == 0 && i != 0)
        {
            printf("-");
        }
        printf("%d", bit_val);
    }
    printf("\n");
}

void
disp_bit_in_hex(char *bit, int num_bit)
{
    int a;
    for (int i = 0; i < num_bit; i = i + 8)
    {
        a = bit[i] + bit[i + 1] * 2 + bit[i + 2] * 4 + bit[i + 3] * 8
            + bit[i + 4] * 16 + bit[i + 5] * 32 + bit[i + 6] * 64
            + bit[i + 7] * 128;
        // a = bit[i+7] + bit[i+6]*2 + bit[i+5]*4 + bit[i+4]*8 + bit[i+3]*16 +
        // bit[i+2]*32 + bit[i+1]*64 + bit[i]*128;
        printf("%02x", a);
    }
    printf("\n");
}

void
disp_hex(uint8_t *hex, int num_hex)
{
    for (int i = 0; i < num_hex; i++)
    {
        printf("%02x", hex[i]);
    }
    printf("\n");
}

void
disp_hex_in_bit(uint8_t *hex, int num_hex)
{
    int bit_val;

    for (int j = 0; j < num_hex; j++)
    {

        for (int i = 0; i < 8; i++)
        {
            bit_val = (hex[j] >> i) & 0x01;
            if (i == 4)
            {
                printf("-");
            }
            printf("%d", bit_val);
        }

        printf(" ");
    }

    printf("\n");
}
