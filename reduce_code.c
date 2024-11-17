#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <sys/uio.h>      // For struct iovec
#include <sys/syscall.h>  // For syscall numbers
#include <unistd.h>       // For syscall function
#include <stdio.h>        // For printf (optional)


#include <sys/mman.h>

#define GETU32(in_data) (((unsigned int)(in_data)[0] << 24) ^ \
						((unsigned int)(in_data)[1] << 16) ^ \
						((unsigned int)(in_data)[2] <<  8) ^ \
						((unsigned int)(in_data)[3] <<  0))

#define PUTU32(out_data, st) { (out_data)[0] = (unsigned char)((st) >> 24); \
							  (out_data)[1] = (unsigned char)((st) >> 16); \
							  (out_data)[2] = (unsigned char)((st) >>  8); \
							  (out_data)[3] = (unsigned char)((st) >>  0); }

static const unsigned int Te0[256] =
{
	0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
	0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
	0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
	0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
	0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
	0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
	0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
	0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
	0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
	0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
	0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
	0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
	0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
	0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
	0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
	0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
	0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
	0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
	0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
	0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
	0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
	0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
	0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
	0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
	0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
	0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
	0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
	0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
	0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
	0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
	0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
	0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
	0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
	0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
	0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
	0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
	0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
	0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
	0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
	0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
	0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
	0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
	0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
	0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
	0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
	0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
	0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
	0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
	0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
	0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
	0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
	0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
	0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
	0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
	0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
	0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
	0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
	0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
	0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
	0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
	0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
	0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
	0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
	0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
};

static const uint8_t Te4[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static const uint8_t Td4[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};
static const unsigned int rcon[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000
};

const char *base_name(const char *path) {
	const char *last_slash = strrchr(path, '/');
	return last_slash != NULL ? last_slash + 1 : path;
}

static uint8_t byte(uint32_t x, int n)
{
    return (uint8_t)(x >> (8 * n));
}

static uint32_t rotate(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static uint32_t setup_mix(const uint32_t temp) {
	return (Te4[byte(temp, 2)] << 24)
         ^ (Te4[byte(temp, 1)] << 16)
         ^ (Te4[byte(temp, 0)] << 8)
         ^  Te4[byte(temp, 3)];
}


static uint32_t setup_mix2(const uint32_t temp) {
	return rotate(Te0[Td4[byte(temp, 3)]], 0) ^ 
		rotate(Te0[Td4[byte(temp, 2)]], 8) ^ 
		rotate(Te0[Td4[byte(temp, 1)]], 16) ^ 
		rotate(Te0[Td4[byte(temp, 0)]], 24);
}

// This code is not used
uint32_t reverse(uint32_t value) {
	return ((value & 0x000000FF) << 24) |  // Move byte 0 to byte 3
           ((value & 0x0000FF00) << 8)  |  // Move byte 1 to byte 2
           ((value & 0x00FF0000) >> 8)  |  // Move byte 2 to byte 1
           ((value & 0xFF000000) >> 24);   // Move byte 3 to byte 0
}

// detect aes 256 encryption key
// fully rolled code
bool aes256_detect_encR(const uint32_t *data) {
	static uint32_t roundkey[60];
	memcpy(roundkey, data, 240);
	
	for (unsigned char index = 8; index < 60; index += 8) {
		roundkey[index] = roundkey[index - 8] ^ setup_mix(roundkey[index - 1]) ^ rcon[index / 8 - 1];
		if (roundkey[index] != data[index]) return false;
		roundkey[index + 1] = roundkey[index - 7] ^ roundkey[index];
		if (roundkey[index + 1] != data[index + 1]) return false;
		roundkey[index + 2] = roundkey[index - 6] ^ roundkey[index + 1];
		if (roundkey[index + 2] != data[index + 2]) return false;
		roundkey[index + 3] = roundkey[index - 5] ^ roundkey[index + 2];
		if (roundkey[index + 3] != data[index + 3]) return false;
		
		if (index == 56) {
			break;
		}
		
		roundkey[index + 4] = roundkey[index - 4] ^ setup_mix(rotate(roundkey[index + 3], 8));
		if (roundkey[index + 4] != data[index + 4]) return false;
		roundkey[index + 5] = roundkey[index - 3] ^ roundkey[index + 4];
		if (roundkey[index + 5] != data[index + 5]) return false;
		roundkey[index + 6] = roundkey[index - 2] ^ roundkey[index + 5];
		if (roundkey[index + 6] != data[index + 6]) return false;
		roundkey[index + 7] = roundkey[index - 1] ^ roundkey[index + 6];
		if (roundkey[index + 7] != data[index + 7]) return false;
	}
	
	return true;
}

// detect aes 256 encryption key 
// fully unrolled code
bool aes256_detect_encU(const unsigned int *data) {
	static uint32_t roundkey[60];
	
	roundkey[0] = data[0];
	roundkey[1] = data[1];
	roundkey[2] = data[2];
	roundkey[3] = data[3];
	roundkey[4] = data[4];
	roundkey[5] = data[5];
	roundkey[6] = data[6];
	roundkey[7] = data[7];
	
	roundkey[8] = roundkey[0] ^ setup_mix(roundkey[7]) ^ rcon[0];
	if (roundkey[8] != data[8]) return false;
	
	roundkey[9] = roundkey[1] ^ roundkey[8];
	if (roundkey[9] != data[9]) return false;
	
	roundkey[10] = roundkey[2] ^ roundkey[9];
	if (roundkey[10] != data[10]) return false;
	
	roundkey[11] = roundkey[3] ^ roundkey[10];
	if (roundkey[11] != data[11]) return false;
	
	roundkey[12] = roundkey[4] ^ setup_mix(rotate(roundkey[11], 8));
	if (roundkey[12] != data[12]) return false;
	
	roundkey[13] = roundkey[5] ^ roundkey[12];
	if (roundkey[13] != data[13]) return false;
	
	roundkey[14] = roundkey[6] ^ roundkey[13];
	if (roundkey[14] != data[14]) return false;
	
	roundkey[15] = roundkey[7] ^ roundkey[14];
	if (roundkey[15] != data[15]) return false;
	
	roundkey[16] = roundkey[8] ^ setup_mix(roundkey[15]) ^ rcon[1];
	if (roundkey[16] != data[16]) return false;
	
	roundkey[17] = roundkey[9] ^ roundkey[16];
	if (roundkey[17] != data[17]) return false;
	
	roundkey[18] = roundkey[10] ^ roundkey[17];
	if (roundkey[18] != data[18]) return false;
	
	roundkey[19] = roundkey[11] ^ roundkey[18];
	if (roundkey[19] != data[19]) return false;
	
	roundkey[20] = roundkey[12] ^ setup_mix(rotate(roundkey[19], 8));
	if (roundkey[20] != data[20]) return false;
	
	roundkey[21] = roundkey[13] ^ roundkey[20];
	if (roundkey[21] != data[21]) return false;
	
	roundkey[22] = roundkey[14] ^ roundkey[21];
	if (roundkey[22] != data[22]) return false;
	
	roundkey[23] = roundkey[15] ^ roundkey[22];
	if (roundkey[23] != data[23]) return false;
	
	roundkey[24] = roundkey[16] ^ setup_mix(roundkey[23]) ^ rcon[2];
	if (roundkey[24] != data[24]) return false;
	
	roundkey[25] = roundkey[17] ^ roundkey[24];
	if (roundkey[25] != data[25]) return false;
	
	roundkey[26] = roundkey[18] ^ roundkey[25];
	if (roundkey[26] != data[26]) return false;
	
	roundkey[27] = roundkey[19] ^ roundkey[26];
	if (roundkey[27] != data[27]) return false;
	
	roundkey[28] = roundkey[20] ^ setup_mix(rotate(roundkey[27], 8));
	if (roundkey[28] != data[28]) return false;
	
	roundkey[29] = roundkey[21] ^ roundkey[28];
	if (roundkey[29] != data[29]) return false;
	
	roundkey[30] = roundkey[22] ^ roundkey[29];
	if (roundkey[30] != data[30]) return false;
	
	roundkey[31] = roundkey[23] ^ roundkey[30];
	if (roundkey[31] != data[31]) return false;
	
	roundkey[32] = roundkey[24] ^ setup_mix(roundkey[31]) ^ rcon[3];
	if (roundkey[32] != data[32]) return false;
	
	roundkey[33] = roundkey[25] ^ roundkey[32];
	if (roundkey[33] != data[33]) return false;
	
	roundkey[34] = roundkey[26] ^ roundkey[33];
	if (roundkey[34] != data[34]) return false;
	
	roundkey[35] = roundkey[27] ^ roundkey[34];
	if (roundkey[35] != data[35]) return false;
	
	roundkey[36] = roundkey[28] ^ setup_mix(rotate(roundkey[35], 8));
	if (roundkey[36] != data[36]) return false;
	
	roundkey[37] = roundkey[29] ^ roundkey[36];
	if (roundkey[37] != data[37]) return false;
	
	roundkey[38] = roundkey[30] ^ roundkey[37];
	if (roundkey[38] != data[38]) return false;
	
	roundkey[39] = roundkey[31] ^ roundkey[38];
	if (roundkey[39] != data[39]) return false;
	
	roundkey[40] = roundkey[32] ^ setup_mix(roundkey[39]) ^ rcon[4];
	if (roundkey[40] != data[40]) return false;
	
	roundkey[41] = roundkey[33] ^ roundkey[40];
	if (roundkey[41] != data[41]) return false;
	
	roundkey[42] = roundkey[34] ^ roundkey[41];
	if (roundkey[42] != data[42]) return false;
	
	roundkey[43] = roundkey[35] ^ roundkey[42];
	if (roundkey[43] != data[43]) return false;
	
	roundkey[44] = roundkey[36] ^ setup_mix(rotate(roundkey[43], 8));
	if (roundkey[44] != data[44]) return false;
	
	roundkey[45] = roundkey[37] ^ roundkey[44];
	if (roundkey[45] != data[45]) return false;
	
	roundkey[46] = roundkey[38] ^ roundkey[45];
	if (roundkey[46] != data[46]) return false;
	
	roundkey[47] = roundkey[39] ^ roundkey[46];
	if (roundkey[47] != data[47]) return false;
	
	roundkey[48] = roundkey[40] ^ setup_mix(roundkey[47]) ^ rcon[5];
	if (roundkey[48] != data[48]) return false;
	
	roundkey[49] = roundkey[41] ^ roundkey[48];
	if (roundkey[49] != data[49]) return false;
	
	roundkey[50] = roundkey[42] ^ roundkey[49];
	if (roundkey[50] != data[50]) return false;
	
	roundkey[51] = roundkey[43] ^ roundkey[50];
	if (roundkey[51] != data[51]) return false;
	
	roundkey[52] = roundkey[44] ^ setup_mix(rotate(roundkey[51], 8));
	if (roundkey[52] != data[52]) return false;
	
	roundkey[53] = roundkey[45] ^ roundkey[52];
	if (roundkey[53] != data[53]) return false;
	
	roundkey[54] = roundkey[46] ^ roundkey[53];
	if (roundkey[54] != data[54]) return false;
	
	roundkey[55] = roundkey[47] ^ roundkey[54];
	if (roundkey[55] != data[55]) return false;
	
	roundkey[56] = roundkey[48] ^ setup_mix(roundkey[55]) ^ rcon[6];
	if (roundkey[56] != data[56]) return false;
	
	roundkey[57] = roundkey[49] ^ roundkey[56];
	if (roundkey[57] != data[57]) return false;
	
	roundkey[58] = roundkey[50] ^ roundkey[57];
	if (roundkey[58] != data[58]) return false;
	
	roundkey[59] = roundkey[51] ^ roundkey[58];
	if (roundkey[59] != data[59]) return false;
	
	return true;
}


bool aes256_detect_encF(const unsigned int *data) {
	static uint32_t roundkey[60];
	
	roundkey[0] = reverse(data[0]);
	roundkey[1] = reverse(data[1]);
	roundkey[2] = reverse(data[2]);
	roundkey[3] = reverse(data[3]);
	roundkey[4] = reverse(data[4]);
	roundkey[5] = reverse(data[5]);
	roundkey[6] = reverse(data[6]);
	roundkey[7] = reverse(data[7]);
	
	for (unsigned char index = 8; index < 60; index += 8) {
		roundkey[index] = roundkey[index - 8] ^ 
			(Te4[(roundkey[index - 1] >> 16) & 0xff] & 0xff000000) ^ 
			(Te4[(roundkey[index - 1] >>  8) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index - 1] >>  0) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index - 1] >> 24) & 0xff] & 0x000000ff) ^ rcon[index / 8 -1];
		roundkey[index + 1] = roundkey[index - 7] ^ roundkey[index];
		roundkey[index + 2] = roundkey[index - 6] ^ roundkey[index + 1];
		roundkey[index + 3] = roundkey[index - 5] ^ roundkey[index + 2];
		
		if (index == 56) {
			break;
		}
		
		roundkey[index + 4] = roundkey[index - 4] ^ 
			(Te4[(roundkey[index + 3] >> 24)] & 0xff000000) ^ 
			(Te4[(roundkey[index + 3] >> 16) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index + 3] >>  8) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index + 3] >>  0) & 0xff] & 0x000000ff);
		roundkey[index + 5] = roundkey[index - 3] ^ roundkey[index + 4];
		roundkey[index + 6] = roundkey[index - 2] ^ roundkey[index + 5];
		roundkey[index + 7] = roundkey[index - 1] ^ roundkey[index + 6];
	}
	
	for (int x = 0; x < 60; x++) {
		if (roundkey[x] != reverse(data[x])) {
			return false;
		}
	}
	
	return true;
}


// detect aes 256 decryption key 
// fully unroll code
bool aes256_detect_dec(const unsigned int *data) {
	static uint32_t roundkey[60];
	
	roundkey[0] = data[56];
	roundkey[1] = data[57];
	roundkey[2] = data[58];
	roundkey[3] = data[59];
	
	roundkey[4] = setup_mix2(data[52]);
	roundkey[5] = setup_mix2(data[53]);
	roundkey[6] = setup_mix2(data[54]);
	roundkey[7] = setup_mix2(data[55]);
	
	roundkey[8] = roundkey[0] ^ setup_mix(roundkey[7]) ^ rcon[0];
	if (roundkey[8] != setup_mix2(data[48])) return false;
	
	roundkey[9] = roundkey[1] ^ roundkey[8];
	if (roundkey[9] != setup_mix2(data[49])) return false;
	
	roundkey[10] = roundkey[2] ^ roundkey[9];
	if (roundkey[10] != setup_mix2(data[50])) return false;
	
	roundkey[11] = roundkey[3] ^ roundkey[10];
	if (roundkey[11] != setup_mix2(data[51])) return false;
	
	roundkey[12] = roundkey[4] ^ setup_mix(rotate(roundkey[11], 8));
	if (roundkey[12] != setup_mix2(data[44])) return false;
	
	roundkey[13] = roundkey[5] ^ roundkey[12];
	if (roundkey[13] != setup_mix2(data[45])) return false;
	
	roundkey[14] = roundkey[6] ^ roundkey[13];
	if (roundkey[14] != setup_mix2(data[46])) return false;
	
	roundkey[15] = roundkey[7] ^ roundkey[14];
	if (roundkey[15] != setup_mix2(data[47])) return false;
	
	roundkey[16] = roundkey[8] ^ setup_mix(roundkey[15]) ^ rcon[1];
	if (roundkey[16] != setup_mix2(data[40])) return false;
	
	roundkey[17] = roundkey[9] ^ roundkey[16];
	if (roundkey[17] != setup_mix2(data[41])) return false;
	
	roundkey[18] = roundkey[10] ^ roundkey[17];
	if (roundkey[18] != setup_mix2(data[42])) return false;
	
	roundkey[19] = roundkey[11] ^ roundkey[18];
	if (roundkey[19] != setup_mix2(data[43])) return false;
	
	roundkey[20] = roundkey[12] ^ setup_mix(rotate(roundkey[19], 8));
	if (roundkey[20] != setup_mix2(data[36])) return false;
	
	roundkey[21] = roundkey[13] ^ roundkey[20];
	if (roundkey[21] != setup_mix2(data[37])) return false;
	
	roundkey[22] = roundkey[14] ^ roundkey[21];
	if (roundkey[22] != setup_mix2(data[38])) return false;
	
	roundkey[23] = roundkey[15] ^ roundkey[22];
	if (roundkey[23] != setup_mix2(data[39])) return false;
	
	roundkey[24] = roundkey[16] ^ setup_mix(roundkey[23]) ^ rcon[2];
	if (roundkey[24] != setup_mix2(data[32])) return false;
	
	roundkey[25] = roundkey[17] ^ roundkey[24];
	if (roundkey[25] != setup_mix2(data[33])) return false;
	
	roundkey[26] = roundkey[18] ^ roundkey[25];
	if (roundkey[26] != setup_mix2(data[34])) return false;
	
	roundkey[27] = roundkey[19] ^ roundkey[26];
	if (roundkey[27] != setup_mix2(data[35])) return false;
	
	roundkey[28] = roundkey[20] ^ setup_mix(rotate(roundkey[27], 8));
	if (roundkey[28] != setup_mix2(data[28])) return false;
	
	roundkey[29] = roundkey[21] ^ roundkey[28];
	if (roundkey[29] != setup_mix2(data[29])) return false;
	
	roundkey[30] = roundkey[22] ^ roundkey[29];
	if (roundkey[30] != setup_mix2(data[30])) return false;
	
	roundkey[31] = roundkey[23] ^ roundkey[30];
	if (roundkey[31] != setup_mix2(data[31])) return false;
	
	roundkey[32] = roundkey[24] ^ setup_mix(roundkey[31]) ^ rcon[3];
	if (roundkey[32] != setup_mix2(data[24])) return false;
	
	roundkey[33] = roundkey[25] ^ roundkey[32];
	if (roundkey[33] != setup_mix2(data[25])) return false;
	
	roundkey[34] = roundkey[26] ^ roundkey[33];
	if (roundkey[34] != setup_mix2(data[26])) return false;
	
	roundkey[35] = roundkey[27] ^ roundkey[34];
	if (roundkey[35] != setup_mix2(data[27])) return false;
	
	roundkey[36] = roundkey[28] ^ setup_mix(rotate(roundkey[35], 8));
	if (roundkey[36] != setup_mix2(data[20])) return false;
	
	roundkey[37] = roundkey[29] ^ roundkey[36];
	if (roundkey[37] != setup_mix2(data[21])) return false;
	
	roundkey[38] = roundkey[30] ^ roundkey[37];
	if (roundkey[38] != setup_mix2(data[22])) return false;
	
	roundkey[39] = roundkey[31] ^ roundkey[38];
	if (roundkey[39] != setup_mix2(data[23])) return false;
	
	roundkey[40] = roundkey[32] ^ setup_mix(roundkey[39]) ^ rcon[4];
	if (roundkey[40] != setup_mix2(data[16])) return false;
	
	roundkey[41] = roundkey[33] ^ roundkey[40];
	if (roundkey[41] != setup_mix2(data[17])) return false;
	
	roundkey[42] = roundkey[34] ^ roundkey[41];
	if (roundkey[42] != setup_mix2(data[18])) return false;
	
	roundkey[43] = roundkey[35] ^ roundkey[42];
	if (roundkey[43] != setup_mix2(data[19])) return false;
	
	roundkey[44] = roundkey[36] ^ setup_mix(rotate(roundkey[43], 8));
	if (roundkey[44] != setup_mix2(data[12])) return false;
	
	roundkey[45] = roundkey[37] ^ roundkey[44];
	if (roundkey[45] != setup_mix2(data[13])) return false;
	
	roundkey[46] = roundkey[38] ^ roundkey[45];
	if (roundkey[46] != setup_mix2(data[14])) return false;
	
	roundkey[47] = roundkey[39] ^ roundkey[46];
	if (roundkey[47] != setup_mix2(data[15])) return false;
	
	roundkey[48] = roundkey[40] ^ setup_mix(roundkey[47]) ^ rcon[5];
	if (roundkey[48] != setup_mix2(data[8])) return false;
	
	roundkey[49] = roundkey[41] ^ roundkey[48];
	if (roundkey[49] != setup_mix2(data[9])) return false;
	
	roundkey[50] = roundkey[42] ^ roundkey[49];
	if (roundkey[50] != setup_mix2(data[10])) return false;
	
	roundkey[51] = roundkey[43] ^ roundkey[50];
	if (roundkey[51] != setup_mix2(data[11])) return false;
	
	roundkey[52] = roundkey[44] ^ setup_mix(rotate(roundkey[51], 8));
	if (roundkey[52] != setup_mix2(data[4])) return false;
	
	roundkey[53] = roundkey[45] ^ roundkey[52];
	if (roundkey[53] != setup_mix2(data[5])) return false;
	
	roundkey[54] = roundkey[46] ^ roundkey[53];
	if (roundkey[54] != setup_mix2(data[6])) return false;
	
	roundkey[55] = roundkey[47] ^ roundkey[54];
	if (roundkey[55] != setup_mix2(data[7])) return false;
	
	roundkey[56] = roundkey[48] ^ setup_mix(roundkey[55]) ^ rcon[6];
	if (roundkey[56] != data[0]) return false;
	
	roundkey[57] = roundkey[49] ^ roundkey[56];
	if (roundkey[57] != data[1]) return false;
	
	roundkey[58] = roundkey[50] ^ roundkey[57];
	if (roundkey[58] != data[2]) return false;
	
	roundkey[59] = roundkey[51] ^ roundkey[58];
	if (roundkey[59] != data[3]) return false;
	
    return true;
}

void find_keys(size_t addr, const uint8_t *buffer) {
	uint32_t *data = (uint32_t*)buffer;
	
	if (aes256_detect_dec(data)) {
		printf("[%p] Found AES-256 decryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)addr, data[56], data[57], data[58], data[59], setup_mix2(data[52]), setup_mix2(data[53]), setup_mix2(data[54]), setup_mix2(data[55]));
	} else if (aes256_detect_encU(data)) {
		printf("[%p] Found AES-256 encryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
	}
	
	/*
	if (aes256_detect_encU(data)) {
		printf("[%p] Found AES-256 encryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)addr, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
	} else if (aes256_detect_dec(data)) {
		printf("[%p] Found AES-256 decryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)addr, data[56], data[57], data[58], data[59], setup_mix2(data[52]), setup_mix2(data[53]), setup_mix2(data[54]), setup_mix2(data[55]));
	} */
	
	
	/*
	if (aes256_detect_encF(data)) {
		printf("[%p] Found AES-256 encryption key: 0x%08x%08x%08x%08x%08x%08x%08x%08x\n", address, reverse(data[0]), reverse(data[1]), reverse(data[2]), reverse(data[3]), reverse(data[4]), reverse(data[5]), reverse(data[6]), reverse(data[7]));
	} else if (aes256_detect_enc(data)) {
		printf("[%p] Found AES-256 encryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)address, data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
	} else if (aes256_detect_dec(data)) {
		printf("[%p] Found AES-256 decryption key: 0x%08X%08X%08X%08X%08X%08X%08X%08X\n", (void*)address, data[56], data[57], data[58], data[59], setup_mix2(data[52]), setup_mix2(data[53]), setup_mix2(data[54]), setup_mix2(data[55]));
	}*/
	
}

int main(int argc, const char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage ./%s <memory_image>\n", base_name(argv[0]));
		return EXIT_FAILURE;
	}
	
	clock_t start_time = clock();
	
	struct stat st;
	
	if (stat(argv[1], &st) != 0) {
		fprintf(stderr, "'%s' does not exist.\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "'%s' not an regular file!\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	int file = open(argv[1], O_RDONLY);
	
	if (file == -1) {
		fprintf(stderr, "Unable to open %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	if (file == -1) {
		fprintf(stderr, "Unable to open %s\n", argv[1]);
		return EXIT_FAILURE;
	}
	
	uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, file, 0);
	
	if (data == MAP_FAILED) {
		perror("mmap failed");
		close(file);
		return 1;
	}
	
	printf("[INFO] SEARCHING KEYS\n");
	
	uint8_t *ptr = data;
	uint32_t remaining = st.st_size;
	
	while (remaining--) {
		find_keys(ptr - data, ptr);
		ptr++;
	}
	
	if (munmap(data, st.st_size) == -1) {
		perror("munmap failed");
	}
	
	close(file);
	
	clock_t end_time = clock();
	double taken_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	
	const double MB = 1024.0 * 1024.0;
    printf("Processed %.2f MB, speed = %.2f MB/s, in %f seconds\n", st.st_size / MB, st.st_size / MB / taken_time, taken_time);
    
	return EXIT_SUCCESS;
}