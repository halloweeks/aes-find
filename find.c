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

#ifndef process_vm_readv
    #include <sys/syscall.h>
    #include <asm/unistd.h>
    
    ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags) {
        return syscall(__NR_process_vm_readv, pid, local_iov, liovcnt, remote_iov, riovcnt, flags);
    }
#endif

static const unsigned int Te4[256] =
{
	0x63636363U, 0x7c7c7c7cU, 0x77777777U, 0x7b7b7b7bU,
	0xf2f2f2f2U, 0x6b6b6b6bU, 0x6f6f6f6fU, 0xc5c5c5c5U,
	0x30303030U, 0x01010101U, 0x67676767U, 0x2b2b2b2bU,
	0xfefefefeU, 0xd7d7d7d7U, 0xababababU, 0x76767676U,
	0xcacacacaU, 0x82828282U, 0xc9c9c9c9U, 0x7d7d7d7dU,
	0xfafafafaU, 0x59595959U, 0x47474747U, 0xf0f0f0f0U,
	0xadadadadU, 0xd4d4d4d4U, 0xa2a2a2a2U, 0xafafafafU,
	0x9c9c9c9cU, 0xa4a4a4a4U, 0x72727272U, 0xc0c0c0c0U,
	0xb7b7b7b7U, 0xfdfdfdfdU, 0x93939393U, 0x26262626U,
	0x36363636U, 0x3f3f3f3fU, 0xf7f7f7f7U, 0xccccccccU,
	0x34343434U, 0xa5a5a5a5U, 0xe5e5e5e5U, 0xf1f1f1f1U,
	0x71717171U, 0xd8d8d8d8U, 0x31313131U, 0x15151515U,
	0x04040404U, 0xc7c7c7c7U, 0x23232323U, 0xc3c3c3c3U,
	0x18181818U, 0x96969696U, 0x05050505U, 0x9a9a9a9aU,
	0x07070707U, 0x12121212U, 0x80808080U, 0xe2e2e2e2U,
	0xebebebebU, 0x27272727U, 0xb2b2b2b2U, 0x75757575U,
	0x09090909U, 0x83838383U, 0x2c2c2c2cU, 0x1a1a1a1aU,
	0x1b1b1b1bU, 0x6e6e6e6eU, 0x5a5a5a5aU, 0xa0a0a0a0U,
	0x52525252U, 0x3b3b3b3bU, 0xd6d6d6d6U, 0xb3b3b3b3U,
	0x29292929U, 0xe3e3e3e3U, 0x2f2f2f2fU, 0x84848484U,
	0x53535353U, 0xd1d1d1d1U, 0x00000000U, 0xededededU,
	0x20202020U, 0xfcfcfcfcU, 0xb1b1b1b1U, 0x5b5b5b5bU,
	0x6a6a6a6aU, 0xcbcbcbcbU, 0xbebebebeU, 0x39393939U,
	0x4a4a4a4aU, 0x4c4c4c4cU, 0x58585858U, 0xcfcfcfcfU,
	0xd0d0d0d0U, 0xefefefefU, 0xaaaaaaaaU, 0xfbfbfbfbU,
	0x43434343U, 0x4d4d4d4dU, 0x33333333U, 0x85858585U,
	0x45454545U, 0xf9f9f9f9U, 0x02020202U, 0x7f7f7f7fU,
	0x50505050U, 0x3c3c3c3cU, 0x9f9f9f9fU, 0xa8a8a8a8U,
	0x51515151U, 0xa3a3a3a3U, 0x40404040U, 0x8f8f8f8fU,
	0x92929292U, 0x9d9d9d9dU, 0x38383838U, 0xf5f5f5f5U,
	0xbcbcbcbcU, 0xb6b6b6b6U, 0xdadadadaU, 0x21212121U,
	0x10101010U, 0xffffffffU, 0xf3f3f3f3U, 0xd2d2d2d2U,
	0xcdcdcdcdU, 0x0c0c0c0cU, 0x13131313U, 0xececececU,
	0x5f5f5f5fU, 0x97979797U, 0x44444444U, 0x17171717U,
	0xc4c4c4c4U, 0xa7a7a7a7U, 0x7e7e7e7eU, 0x3d3d3d3dU,
	0x64646464U, 0x5d5d5d5dU, 0x19191919U, 0x73737373U,
	0x60606060U, 0x81818181U, 0x4f4f4f4fU, 0xdcdcdcdcU,
	0x22222222U, 0x2a2a2a2aU, 0x90909090U, 0x88888888U,
	0x46464646U, 0xeeeeeeeeU, 0xb8b8b8b8U, 0x14141414U,
	0xdedededeU, 0x5e5e5e5eU, 0x0b0b0b0bU, 0xdbdbdbdbU,
	0xe0e0e0e0U, 0x32323232U, 0x3a3a3a3aU, 0x0a0a0a0aU,
	0x49494949U, 0x06060606U, 0x24242424U, 0x5c5c5c5cU,
	0xc2c2c2c2U, 0xd3d3d3d3U, 0xacacacacU, 0x62626262U,
	0x91919191U, 0x95959595U, 0xe4e4e4e4U, 0x79797979U,
	0xe7e7e7e7U, 0xc8c8c8c8U, 0x37373737U, 0x6d6d6d6dU,
	0x8d8d8d8dU, 0xd5d5d5d5U, 0x4e4e4e4eU, 0xa9a9a9a9U,
	0x6c6c6c6cU, 0x56565656U, 0xf4f4f4f4U, 0xeaeaeaeaU,
	0x65656565U, 0x7a7a7a7aU, 0xaeaeaeaeU, 0x08080808U,
	0xbabababaU, 0x78787878U, 0x25252525U, 0x2e2e2e2eU,
	0x1c1c1c1cU, 0xa6a6a6a6U, 0xb4b4b4b4U, 0xc6c6c6c6U,
	0xe8e8e8e8U, 0xddddddddU, 0x74747474U, 0x1f1f1f1fU,
	0x4b4b4b4bU, 0xbdbdbdbdU, 0x8b8b8b8bU, 0x8a8a8a8aU,
	0x70707070U, 0x3e3e3e3eU, 0xb5b5b5b5U, 0x66666666U,
	0x48484848U, 0x03030303U, 0xf6f6f6f6U, 0x0e0e0e0eU,
	0x61616161U, 0x35353535U, 0x57575757U, 0xb9b9b9b9U,
	0x86868686U, 0xc1c1c1c1U, 0x1d1d1d1dU, 0x9e9e9e9eU,
	0xe1e1e1e1U, 0xf8f8f8f8U, 0x98989898U, 0x11111111U,
	0x69696969U, 0xd9d9d9d9U, 0x8e8e8e8eU, 0x94949494U,
	0x9b9b9b9bU, 0x1e1e1e1eU, 0x87878787U, 0xe9e9e9e9U,
	0xcecececeU, 0x55555555U, 0x28282828U, 0xdfdfdfdfU,
	0x8c8c8c8cU, 0xa1a1a1a1U, 0x89898989U, 0x0d0d0d0dU,
	0xbfbfbfbfU, 0xe6e6e6e6U, 0x42424242U, 0x68686868U,
	0x41414141U, 0x99999999U, 0x2d2d2d2dU, 0x0f0f0f0fU,
	0xb0b0b0b0U, 0x54545454U, 0xbbbbbbbbU, 0x16161616U,
};

static const unsigned int Td0[256] =
{
	0x51f4a750U, 0x7e416553U, 0x1a17a4c3U, 0x3a275e96U,
	0x3bab6bcbU, 0x1f9d45f1U, 0xacfa58abU, 0x4be30393U,
	0x2030fa55U, 0xad766df6U, 0x88cc7691U, 0xf5024c25U,
	0x4fe5d7fcU, 0xc52acbd7U, 0x26354480U, 0xb562a38fU,
	0xdeb15a49U, 0x25ba1b67U, 0x45ea0e98U, 0x5dfec0e1U,
	0xc32f7502U, 0x814cf012U, 0x8d4697a3U, 0x6bd3f9c6U,
	0x038f5fe7U, 0x15929c95U, 0xbf6d7aebU, 0x955259daU,
	0xd4be832dU, 0x587421d3U, 0x49e06929U, 0x8ec9c844U,
	0x75c2896aU, 0xf48e7978U, 0x99583e6bU, 0x27b971ddU,
	0xbee14fb6U, 0xf088ad17U, 0xc920ac66U, 0x7dce3ab4U,
	0x63df4a18U, 0xe51a3182U, 0x97513360U, 0x62537f45U,
	0xb16477e0U, 0xbb6bae84U, 0xfe81a01cU, 0xf9082b94U,
	0x70486858U, 0x8f45fd19U, 0x94de6c87U, 0x527bf8b7U,
	0xab73d323U, 0x724b02e2U, 0xe31f8f57U, 0x6655ab2aU,
	0xb2eb2807U, 0x2fb5c203U, 0x86c57b9aU, 0xd33708a5U,
	0x302887f2U, 0x23bfa5b2U, 0x02036abaU, 0xed16825cU,
	0x8acf1c2bU, 0xa779b492U, 0xf307f2f0U, 0x4e69e2a1U,
	0x65daf4cdU, 0x0605bed5U, 0xd134621fU, 0xc4a6fe8aU,
	0x342e539dU, 0xa2f355a0U, 0x058ae132U, 0xa4f6eb75U,
	0x0b83ec39U, 0x4060efaaU, 0x5e719f06U, 0xbd6e1051U,
	0x3e218af9U, 0x96dd063dU, 0xdd3e05aeU, 0x4de6bd46U,
	0x91548db5U, 0x71c45d05U, 0x0406d46fU, 0x605015ffU,
	0x1998fb24U, 0xd6bde997U, 0x894043ccU, 0x67d99e77U,
	0xb0e842bdU, 0x07898b88U, 0xe7195b38U, 0x79c8eedbU,
	0xa17c0a47U, 0x7c420fe9U, 0xf8841ec9U, 0x00000000U,
	0x09808683U, 0x322bed48U, 0x1e1170acU, 0x6c5a724eU,
	0xfd0efffbU, 0x0f853856U, 0x3daed51eU, 0x362d3927U,
	0x0a0fd964U, 0x685ca621U, 0x9b5b54d1U, 0x24362e3aU,
	0x0c0a67b1U, 0x9357e70fU, 0xb4ee96d2U, 0x1b9b919eU,
	0x80c0c54fU, 0x61dc20a2U, 0x5a774b69U, 0x1c121a16U,
	0xe293ba0aU, 0xc0a02ae5U, 0x3c22e043U, 0x121b171dU,
	0x0e090d0bU, 0xf28bc7adU, 0x2db6a8b9U, 0x141ea9c8U,
	0x57f11985U, 0xaf75074cU, 0xee99ddbbU, 0xa37f60fdU,
	0xf701269fU, 0x5c72f5bcU, 0x44663bc5U, 0x5bfb7e34U,
	0x8b432976U, 0xcb23c6dcU, 0xb6edfc68U, 0xb8e4f163U,
	0xd731dccaU, 0x42638510U, 0x13972240U, 0x84c61120U,
	0x854a247dU, 0xd2bb3df8U, 0xaef93211U, 0xc729a16dU,
	0x1d9e2f4bU, 0xdcb230f3U, 0x0d8652ecU, 0x77c1e3d0U,
	0x2bb3166cU, 0xa970b999U, 0x119448faU, 0x47e96422U,
	0xa8fc8cc4U, 0xa0f03f1aU, 0x567d2cd8U, 0x223390efU,
	0x87494ec7U, 0xd938d1c1U, 0x8ccaa2feU, 0x98d40b36U,
	0xa6f581cfU, 0xa57ade28U, 0xdab78e26U, 0x3fadbfa4U,
	0x2c3a9de4U, 0x5078920dU, 0x6a5fcc9bU, 0x547e4662U,
	0xf68d13c2U, 0x90d8b8e8U, 0x2e39f75eU, 0x82c3aff5U,
	0x9f5d80beU, 0x69d0937cU, 0x6fd52da9U, 0xcf2512b3U,
	0xc8ac993bU, 0x10187da7U, 0xe89c636eU, 0xdb3bbb7bU,
	0xcd267809U, 0x6e5918f4U, 0xec9ab701U, 0x834f9aa8U,
	0xe6956e65U, 0xaaffe67eU, 0x21bccf08U, 0xef15e8e6U,
	0xbae79bd9U, 0x4a6f36ceU, 0xea9f09d4U, 0x29b07cd6U,
	0x31a4b2afU, 0x2a3f2331U, 0xc6a59430U, 0x35a266c0U,
	0x744ebc37U, 0xfc82caa6U, 0xe090d0b0U, 0x33a7d815U,
	0xf104984aU, 0x41ecdaf7U, 0x7fcd500eU, 0x1791f62fU,
	0x764dd68dU, 0x43efb04dU, 0xccaa4d54U, 0xe49604dfU,
	0x9ed1b5e3U, 0x4c6a881bU, 0xc12c1fb8U, 0x4665517fU,
	0x9d5eea04U, 0x018c355dU, 0xfa877473U, 0xfb0b412eU,
	0xb3671d5aU, 0x92dbd252U, 0xe9105633U, 0x6dd64713U,
	0x9ad7618cU, 0x37a10c7aU, 0x59f8148eU, 0xeb133c89U,
	0xcea927eeU, 0xb761c935U, 0xe11ce5edU, 0x7a47b13cU,
	0x9cd2df59U, 0x55f2733fU, 0x1814ce79U, 0x73c737bfU,
	0x53f7cdeaU, 0x5ffdaa5bU, 0xdf3d6f14U, 0x7844db86U,
	0xcaaff381U, 0xb968c43eU, 0x3824342cU, 0xc2a3405fU,
	0x161dc372U, 0xbce2250cU, 0x283c498bU, 0xff0d9541U,
	0x39a80171U, 0x080cb3deU, 0xd8b4e49cU, 0x6456c190U,
	0x7bcb8461U, 0xd532b670U, 0x486c5c74U, 0xd0b85742U,
};

static const unsigned int Td1[256] =
{
	0x5051f4a7U, 0x537e4165U, 0xc31a17a4U, 0x963a275eU,
	0xcb3bab6bU, 0xf11f9d45U, 0xabacfa58U, 0x934be303U,
	0x552030faU, 0xf6ad766dU, 0x9188cc76U, 0x25f5024cU,
	0xfc4fe5d7U, 0xd7c52acbU, 0x80263544U, 0x8fb562a3U,
	0x49deb15aU, 0x6725ba1bU, 0x9845ea0eU, 0xe15dfec0U,
	0x02c32f75U, 0x12814cf0U, 0xa38d4697U, 0xc66bd3f9U,
	0xe7038f5fU, 0x9515929cU, 0xebbf6d7aU, 0xda955259U,
	0x2dd4be83U, 0xd3587421U, 0x2949e069U, 0x448ec9c8U,
	0x6a75c289U, 0x78f48e79U, 0x6b99583eU, 0xdd27b971U,
	0xb6bee14fU, 0x17f088adU, 0x66c920acU, 0xb47dce3aU,
	0x1863df4aU, 0x82e51a31U, 0x60975133U, 0x4562537fU,
	0xe0b16477U, 0x84bb6baeU, 0x1cfe81a0U, 0x94f9082bU,
	0x58704868U, 0x198f45fdU, 0x8794de6cU, 0xb7527bf8U,
	0x23ab73d3U, 0xe2724b02U, 0x57e31f8fU, 0x2a6655abU,
	0x07b2eb28U, 0x032fb5c2U, 0x9a86c57bU, 0xa5d33708U,
	0xf2302887U, 0xb223bfa5U, 0xba02036aU, 0x5ced1682U,
	0x2b8acf1cU, 0x92a779b4U, 0xf0f307f2U, 0xa14e69e2U,
	0xcd65daf4U, 0xd50605beU, 0x1fd13462U, 0x8ac4a6feU,
	0x9d342e53U, 0xa0a2f355U, 0x32058ae1U, 0x75a4f6ebU,
	0x390b83ecU, 0xaa4060efU, 0x065e719fU, 0x51bd6e10U,
	0xf93e218aU, 0x3d96dd06U, 0xaedd3e05U, 0x464de6bdU,
	0xb591548dU, 0x0571c45dU, 0x6f0406d4U, 0xff605015U,
	0x241998fbU, 0x97d6bde9U, 0xcc894043U, 0x7767d99eU,
	0xbdb0e842U, 0x8807898bU, 0x38e7195bU, 0xdb79c8eeU,
	0x47a17c0aU, 0xe97c420fU, 0xc9f8841eU, 0x00000000U,
	0x83098086U, 0x48322bedU, 0xac1e1170U, 0x4e6c5a72U,
	0xfbfd0effU, 0x560f8538U, 0x1e3daed5U, 0x27362d39U,
	0x640a0fd9U, 0x21685ca6U, 0xd19b5b54U, 0x3a24362eU,
	0xb10c0a67U, 0x0f9357e7U, 0xd2b4ee96U, 0x9e1b9b91U,
	0x4f80c0c5U, 0xa261dc20U, 0x695a774bU, 0x161c121aU,
	0x0ae293baU, 0xe5c0a02aU, 0x433c22e0U, 0x1d121b17U,
	0x0b0e090dU, 0xadf28bc7U, 0xb92db6a8U, 0xc8141ea9U,
	0x8557f119U, 0x4caf7507U, 0xbbee99ddU, 0xfda37f60U,
	0x9ff70126U, 0xbc5c72f5U, 0xc544663bU, 0x345bfb7eU,
	0x768b4329U, 0xdccb23c6U, 0x68b6edfcU, 0x63b8e4f1U,
	0xcad731dcU, 0x10426385U, 0x40139722U, 0x2084c611U,
	0x7d854a24U, 0xf8d2bb3dU, 0x11aef932U, 0x6dc729a1U,
	0x4b1d9e2fU, 0xf3dcb230U, 0xec0d8652U, 0xd077c1e3U,
	0x6c2bb316U, 0x99a970b9U, 0xfa119448U, 0x2247e964U,
	0xc4a8fc8cU, 0x1aa0f03fU, 0xd8567d2cU, 0xef223390U,
	0xc787494eU, 0xc1d938d1U, 0xfe8ccaa2U, 0x3698d40bU,
	0xcfa6f581U, 0x28a57adeU, 0x26dab78eU, 0xa43fadbfU,
	0xe42c3a9dU, 0x0d507892U, 0x9b6a5fccU, 0x62547e46U,
	0xc2f68d13U, 0xe890d8b8U, 0x5e2e39f7U, 0xf582c3afU,
	0xbe9f5d80U, 0x7c69d093U, 0xa96fd52dU, 0xb3cf2512U,
	0x3bc8ac99U, 0xa710187dU, 0x6ee89c63U, 0x7bdb3bbbU,
	0x09cd2678U, 0xf46e5918U, 0x01ec9ab7U, 0xa8834f9aU,
	0x65e6956eU, 0x7eaaffe6U, 0x0821bccfU, 0xe6ef15e8U,
	0xd9bae79bU, 0xce4a6f36U, 0xd4ea9f09U, 0xd629b07cU,
	0xaf31a4b2U, 0x312a3f23U, 0x30c6a594U, 0xc035a266U,
	0x37744ebcU, 0xa6fc82caU, 0xb0e090d0U, 0x1533a7d8U,
	0x4af10498U, 0xf741ecdaU, 0x0e7fcd50U, 0x2f1791f6U,
	0x8d764dd6U, 0x4d43efb0U, 0x54ccaa4dU, 0xdfe49604U,
	0xe39ed1b5U, 0x1b4c6a88U, 0xb8c12c1fU, 0x7f466551U,
	0x049d5eeaU, 0x5d018c35U, 0x73fa8774U, 0x2efb0b41U,
	0x5ab3671dU, 0x5292dbd2U, 0x33e91056U, 0x136dd647U,
	0x8c9ad761U, 0x7a37a10cU, 0x8e59f814U, 0x89eb133cU,
	0xeecea927U, 0x35b761c9U, 0xede11ce5U, 0x3c7a47b1U,
	0x599cd2dfU, 0x3f55f273U, 0x791814ceU, 0xbf73c737U,
	0xea53f7cdU, 0x5b5ffdaaU, 0x14df3d6fU, 0x867844dbU,
	0x81caaff3U, 0x3eb968c4U, 0x2c382434U, 0x5fc2a340U,
	0x72161dc3U, 0x0cbce225U, 0x8b283c49U, 0x41ff0d95U,
	0x7139a801U, 0xde080cb3U, 0x9cd8b4e4U, 0x906456c1U,
	0x617bcb84U, 0x70d532b6U, 0x74486c5cU, 0x42d0b857U,
};

static const unsigned int Td2[256] =
{
	0xa75051f4U, 0x65537e41U, 0xa4c31a17U, 0x5e963a27U,
	0x6bcb3babU, 0x45f11f9dU, 0x58abacfaU, 0x03934be3U,
	0xfa552030U, 0x6df6ad76U, 0x769188ccU, 0x4c25f502U,
	0xd7fc4fe5U, 0xcbd7c52aU, 0x44802635U, 0xa38fb562U,
	0x5a49deb1U, 0x1b6725baU, 0x0e9845eaU, 0xc0e15dfeU,
	0x7502c32fU, 0xf012814cU, 0x97a38d46U, 0xf9c66bd3U,
	0x5fe7038fU, 0x9c951592U, 0x7aebbf6dU, 0x59da9552U,
	0x832dd4beU, 0x21d35874U, 0x692949e0U, 0xc8448ec9U,
	0x896a75c2U, 0x7978f48eU, 0x3e6b9958U, 0x71dd27b9U,
	0x4fb6bee1U, 0xad17f088U, 0xac66c920U, 0x3ab47dceU,
	0x4a1863dfU, 0x3182e51aU, 0x33609751U, 0x7f456253U,
	0x77e0b164U, 0xae84bb6bU, 0xa01cfe81U, 0x2b94f908U,
	0x68587048U, 0xfd198f45U, 0x6c8794deU, 0xf8b7527bU,
	0xd323ab73U, 0x02e2724bU, 0x8f57e31fU, 0xab2a6655U,
	0x2807b2ebU, 0xc2032fb5U, 0x7b9a86c5U, 0x08a5d337U,
	0x87f23028U, 0xa5b223bfU, 0x6aba0203U, 0x825ced16U,
	0x1c2b8acfU, 0xb492a779U, 0xf2f0f307U, 0xe2a14e69U,
	0xf4cd65daU, 0xbed50605U, 0x621fd134U, 0xfe8ac4a6U,
	0x539d342eU, 0x55a0a2f3U, 0xe132058aU, 0xeb75a4f6U,
	0xec390b83U, 0xefaa4060U, 0x9f065e71U, 0x1051bd6eU,
	0x8af93e21U, 0x063d96ddU, 0x05aedd3eU, 0xbd464de6U,
	0x8db59154U, 0x5d0571c4U, 0xd46f0406U, 0x15ff6050U,
	0xfb241998U, 0xe997d6bdU, 0x43cc8940U, 0x9e7767d9U,
	0x42bdb0e8U, 0x8b880789U, 0x5b38e719U, 0xeedb79c8U,
	0x0a47a17cU, 0x0fe97c42U, 0x1ec9f884U, 0x00000000U,
	0x86830980U, 0xed48322bU, 0x70ac1e11U, 0x724e6c5aU,
	0xfffbfd0eU, 0x38560f85U, 0xd51e3daeU, 0x3927362dU,
	0xd9640a0fU, 0xa621685cU, 0x54d19b5bU, 0x2e3a2436U,
	0x67b10c0aU, 0xe70f9357U, 0x96d2b4eeU, 0x919e1b9bU,
	0xc54f80c0U, 0x20a261dcU, 0x4b695a77U, 0x1a161c12U,
	0xba0ae293U, 0x2ae5c0a0U, 0xe0433c22U, 0x171d121bU,
	0x0d0b0e09U, 0xc7adf28bU, 0xa8b92db6U, 0xa9c8141eU,
	0x198557f1U, 0x074caf75U, 0xddbbee99U, 0x60fda37fU,
	0x269ff701U, 0xf5bc5c72U, 0x3bc54466U, 0x7e345bfbU,
	0x29768b43U, 0xc6dccb23U, 0xfc68b6edU, 0xf163b8e4U,
	0xdccad731U, 0x85104263U, 0x22401397U, 0x112084c6U,
	0x247d854aU, 0x3df8d2bbU, 0x3211aef9U, 0xa16dc729U,
	0x2f4b1d9eU, 0x30f3dcb2U, 0x52ec0d86U, 0xe3d077c1U,
	0x166c2bb3U, 0xb999a970U, 0x48fa1194U, 0x642247e9U,
	0x8cc4a8fcU, 0x3f1aa0f0U, 0x2cd8567dU, 0x90ef2233U,
	0x4ec78749U, 0xd1c1d938U, 0xa2fe8ccaU, 0x0b3698d4U,
	0x81cfa6f5U, 0xde28a57aU, 0x8e26dab7U, 0xbfa43fadU,
	0x9de42c3aU, 0x920d5078U, 0xcc9b6a5fU, 0x4662547eU,
	0x13c2f68dU, 0xb8e890d8U, 0xf75e2e39U, 0xaff582c3U,
	0x80be9f5dU, 0x937c69d0U, 0x2da96fd5U, 0x12b3cf25U,
	0x993bc8acU, 0x7da71018U, 0x636ee89cU, 0xbb7bdb3bU,
	0x7809cd26U, 0x18f46e59U, 0xb701ec9aU, 0x9aa8834fU,
	0x6e65e695U, 0xe67eaaffU, 0xcf0821bcU, 0xe8e6ef15U,
	0x9bd9bae7U, 0x36ce4a6fU, 0x09d4ea9fU, 0x7cd629b0U,
	0xb2af31a4U, 0x23312a3fU, 0x9430c6a5U, 0x66c035a2U,
	0xbc37744eU, 0xcaa6fc82U, 0xd0b0e090U, 0xd81533a7U,
	0x984af104U, 0xdaf741ecU, 0x500e7fcdU, 0xf62f1791U,
	0xd68d764dU, 0xb04d43efU, 0x4d54ccaaU, 0x04dfe496U,
	0xb5e39ed1U, 0x881b4c6aU, 0x1fb8c12cU, 0x517f4665U,
	0xea049d5eU, 0x355d018cU, 0x7473fa87U, 0x412efb0bU,
	0x1d5ab367U, 0xd25292dbU, 0x5633e910U, 0x47136dd6U,
	0x618c9ad7U, 0x0c7a37a1U, 0x148e59f8U, 0x3c89eb13U,
	0x27eecea9U, 0xc935b761U, 0xe5ede11cU, 0xb13c7a47U,
	0xdf599cd2U, 0x733f55f2U, 0xce791814U, 0x37bf73c7U,
	0xcdea53f7U, 0xaa5b5ffdU, 0x6f14df3dU, 0xdb867844U,
	0xf381caafU, 0xc43eb968U, 0x342c3824U, 0x405fc2a3U,
	0xc372161dU, 0x250cbce2U, 0x498b283cU, 0x9541ff0dU,
	0x017139a8U, 0xb3de080cU, 0xe49cd8b4U, 0xc1906456U,
	0x84617bcbU, 0xb670d532U, 0x5c74486cU, 0x5742d0b8U,
};

static const unsigned int Td3[256] =
{
	0xf4a75051U, 0x4165537eU, 0x17a4c31aU, 0x275e963aU,
	0xab6bcb3bU, 0x9d45f11fU, 0xfa58abacU, 0xe303934bU,
	0x30fa5520U, 0x766df6adU, 0xcc769188U, 0x024c25f5U,
	0xe5d7fc4fU, 0x2acbd7c5U, 0x35448026U, 0x62a38fb5U,
	0xb15a49deU, 0xba1b6725U, 0xea0e9845U, 0xfec0e15dU,
	0x2f7502c3U, 0x4cf01281U, 0x4697a38dU, 0xd3f9c66bU,
	0x8f5fe703U, 0x929c9515U, 0x6d7aebbfU, 0x5259da95U,
	0xbe832dd4U, 0x7421d358U, 0xe0692949U, 0xc9c8448eU,
	0xc2896a75U, 0x8e7978f4U, 0x583e6b99U, 0xb971dd27U,
	0xe14fb6beU, 0x88ad17f0U, 0x20ac66c9U, 0xce3ab47dU,
	0xdf4a1863U, 0x1a3182e5U, 0x51336097U, 0x537f4562U,
	0x6477e0b1U, 0x6bae84bbU, 0x81a01cfeU, 0x082b94f9U,
	0x48685870U, 0x45fd198fU, 0xde6c8794U, 0x7bf8b752U,
	0x73d323abU, 0x4b02e272U, 0x1f8f57e3U, 0x55ab2a66U,
	0xeb2807b2U, 0xb5c2032fU, 0xc57b9a86U, 0x3708a5d3U,
	0x2887f230U, 0xbfa5b223U, 0x036aba02U, 0x16825cedU,
	0xcf1c2b8aU, 0x79b492a7U, 0x07f2f0f3U, 0x69e2a14eU,
	0xdaf4cd65U, 0x05bed506U, 0x34621fd1U, 0xa6fe8ac4U,
	0x2e539d34U, 0xf355a0a2U, 0x8ae13205U, 0xf6eb75a4U,
	0x83ec390bU, 0x60efaa40U, 0x719f065eU, 0x6e1051bdU,
	0x218af93eU, 0xdd063d96U, 0x3e05aeddU, 0xe6bd464dU,
	0x548db591U, 0xc45d0571U, 0x06d46f04U, 0x5015ff60U,
	0x98fb2419U, 0xbde997d6U, 0x4043cc89U, 0xd99e7767U,
	0xe842bdb0U, 0x898b8807U, 0x195b38e7U, 0xc8eedb79U,
	0x7c0a47a1U, 0x420fe97cU, 0x841ec9f8U, 0x00000000U,
	0x80868309U, 0x2bed4832U, 0x1170ac1eU, 0x5a724e6cU,
	0x0efffbfdU, 0x8538560fU, 0xaed51e3dU, 0x2d392736U,
	0x0fd9640aU, 0x5ca62168U, 0x5b54d19bU, 0x362e3a24U,
	0x0a67b10cU, 0x57e70f93U, 0xee96d2b4U, 0x9b919e1bU,
	0xc0c54f80U, 0xdc20a261U, 0x774b695aU, 0x121a161cU,
	0x93ba0ae2U, 0xa02ae5c0U, 0x22e0433cU, 0x1b171d12U,
	0x090d0b0eU, 0x8bc7adf2U, 0xb6a8b92dU, 0x1ea9c814U,
	0xf1198557U, 0x75074cafU, 0x99ddbbeeU, 0x7f60fda3U,
	0x01269ff7U, 0x72f5bc5cU, 0x663bc544U, 0xfb7e345bU,
	0x4329768bU, 0x23c6dccbU, 0xedfc68b6U, 0xe4f163b8U,
	0x31dccad7U, 0x63851042U, 0x97224013U, 0xc6112084U,
	0x4a247d85U, 0xbb3df8d2U, 0xf93211aeU, 0x29a16dc7U,
	0x9e2f4b1dU, 0xb230f3dcU, 0x8652ec0dU, 0xc1e3d077U,
	0xb3166c2bU, 0x70b999a9U, 0x9448fa11U, 0xe9642247U,
	0xfc8cc4a8U, 0xf03f1aa0U, 0x7d2cd856U, 0x3390ef22U,
	0x494ec787U, 0x38d1c1d9U, 0xcaa2fe8cU, 0xd40b3698U,
	0xf581cfa6U, 0x7ade28a5U, 0xb78e26daU, 0xadbfa43fU,
	0x3a9de42cU, 0x78920d50U, 0x5fcc9b6aU, 0x7e466254U,
	0x8d13c2f6U, 0xd8b8e890U, 0x39f75e2eU, 0xc3aff582U,
	0x5d80be9fU, 0xd0937c69U, 0xd52da96fU, 0x2512b3cfU,
	0xac993bc8U, 0x187da710U, 0x9c636ee8U, 0x3bbb7bdbU,
	0x267809cdU, 0x5918f46eU, 0x9ab701ecU, 0x4f9aa883U,
	0x956e65e6U, 0xffe67eaaU, 0xbccf0821U, 0x15e8e6efU,
	0xe79bd9baU, 0x6f36ce4aU, 0x9f09d4eaU, 0xb07cd629U,
	0xa4b2af31U, 0x3f23312aU, 0xa59430c6U, 0xa266c035U,
	0x4ebc3774U, 0x82caa6fcU, 0x90d0b0e0U, 0xa7d81533U,
	0x04984af1U, 0xecdaf741U, 0xcd500e7fU, 0x91f62f17U,
	0x4dd68d76U, 0xefb04d43U, 0xaa4d54ccU, 0x9604dfe4U,
	0xd1b5e39eU, 0x6a881b4cU, 0x2c1fb8c1U, 0x65517f46U,
	0x5eea049dU, 0x8c355d01U, 0x877473faU, 0x0b412efbU,
	0x671d5ab3U, 0xdbd25292U, 0x105633e9U, 0xd647136dU,
	0xd7618c9aU, 0xa10c7a37U, 0xf8148e59U, 0x133c89ebU,
	0xa927eeceU, 0x61c935b7U, 0x1ce5ede1U, 0x47b13c7aU,
	0xd2df599cU, 0xf2733f55U, 0x14ce7918U, 0xc737bf73U,
	0xf7cdea53U, 0xfdaa5b5fU, 0x3d6f14dfU, 0x44db8678U,
	0xaff381caU, 0x68c43eb9U, 0x24342c38U, 0xa3405fc2U,
	0x1dc37216U, 0xe2250cbcU, 0x3c498b28U, 0x0d9541ffU,
	0xa8017139U, 0x0cb3de08U, 0xb4e49cd8U, 0x56c19064U,
	0xcb84617bU, 0x32b670d5U, 0x6c5c7448U, 0xb85742d0U,
};

static const unsigned int rcon[10] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1B000000, 0x36000000
};

ssize_t read_process_memory(pid_t pid, uintptr_t address, void *value, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = (void*)address;
    remote[0].iov_len = size;
    return process_vm_readv(pid, local, 1, remote, 1, 0);
}

pid_t find_pid(const char *process_name) {
    DIR *dir = opendir("/proc");
    struct dirent *entry = NULL;
    char cmdline_path[256];
    char cmdline[256];
    int fd;
    
    if (dir == NULL) {
        return -1;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0) || (entry->d_type != DT_DIR) || (strspn(entry->d_name, "0123456789") != strlen(entry->d_name))) {
            continue;
        }
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
        fd = open(cmdline_path, O_RDONLY);
        read(fd, cmdline, 256);
        close(fd);
        
        if (strstr(cmdline, process_name) != NULL) {
            closedir(dir);
            return atoi(entry->d_name);
        }
        
        /*
        if (strncmp(cmdline, process_name, strlen(process_name)) == 0) {
            closedir(dir);
            return atoi(entry->d_name);
        }
        */
    }
    closedir(dir);
    return -1;
}

uint8_t get_module_address(pid_t process_id, const char *module_name, unsigned long long *start_addr, unsigned long long *end_addr) {
    char filename[256];
    char line[1024];
    FILE *fp = NULL;
    uint8_t address_found = 0;
    unsigned long long start, end;
    unsigned char permission;
    
    snprintf(filename, sizeof(filename), "/proc/%d/maps", process_id);
    
    if (!(fp = fopen(filename, "r"))) {
        return 0;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module_name)) {
            if (sscanf(line, "%llx-%llx %c", &start, &end, &permission) == 3) {
                address_found = 1;
                *start_addr = start;
                *end_addr = end;
                break;
            }
        }
    }
    
    fclose(fp);
    return address_found;
}



bool aes128_detect_enc(const unsigned int *data) {
	unsigned int roundkey[44];
	
	roundkey[0] = data[0];
	roundkey[1] = data[1];
	roundkey[2] = data[2];
	roundkey[3] = data[3];
	
	for (unsigned char index = 4; index < 44; index += 4) {
		roundkey[index] = roundkey[index - 4] ^ 
			(Te4[(roundkey[index - 1] >> 16) & 0xff] & 0xff000000) ^ 
			(Te4[(roundkey[index - 1] >>  8) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index - 1] >>  0) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index - 1] >> 24) & 0xff] & 0x000000ff) ^ rcon[index / 4 - 1];
		roundkey[index + 1] = roundkey[index - 3] ^ roundkey[index];
		roundkey[index + 2] = roundkey[index - 2] ^ roundkey[index + 1];
		roundkey[index + 3] = roundkey[index - 1] ^ roundkey[index + 2];
	}
	
	for (int x = 0; x < 44; x++) {
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
}

bool aes128_detect_dec(const unsigned int *data) {
	unsigned int roundkey[44];
	
	roundkey[0] = data[40];
    roundkey[1] = data[41];
    roundkey[2] = data[42];
    roundkey[3] = data[43];
    
    
    for (unsigned char index = 4; index < 44; index += 4) {
		roundkey[index] = roundkey[index - 4] ^ 
			(Te4[(roundkey[index - 1] >> 16) & 0xff] & 0xff000000) ^ 
			(Te4[(roundkey[index - 1] >>  8) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index - 1] >>  0) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index - 1] >> 24) & 0xff] & 0x000000ff) ^ rcon[index / 4 - 1];
		roundkey[index + 1] = roundkey[index - 3] ^ roundkey[index];
		roundkey[index + 2] = roundkey[index - 2] ^ roundkey[index + 1];
		roundkey[index + 3] = roundkey[index - 1] ^ roundkey[index + 2];
	}
	
	unsigned int temp;
	
	// Next, invert the order of the round keys.
	for (unsigned char i = 0, j = 40; i < j; i += 4, j -= 4) {
		for (uint8_t k = 0; k < 4; k++) {
			temp = roundkey[i + k];
			roundkey[i + k] = roundkey[j + k];
			roundkey[j + k] = temp;
		}
	}
	
    // Finally, apply the inverse MixColumn transform to all round keys except the first and last.
    for (unsigned char index = 4; index < 40; index += 4) {
        roundkey[index] =
            Td0[Te4[(roundkey[index] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index] >>  0) & 0xff] & 0xff];
        roundkey[index + 1] =
            Td0[Te4[(roundkey[index + 1] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 1] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 1] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 1] >>  0) & 0xff] & 0xff];
        roundkey[index + 2] =
            Td0[Te4[(roundkey[index + 2] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 2] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 2] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 2] >>  0) & 0xff] & 0xff];
        roundkey[index + 3] =
            Td0[Te4[(roundkey[index + 3] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 3] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 3] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 3] >>  0) & 0xff] & 0xff];
    }
    
    for (int x = 0; x < 44; x++) {
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
}


bool aes192_detect_enc(const unsigned int *data) {
	unsigned int roundkey[52];
	
	roundkey[0] = data[0];
	roundkey[1] = data[1];
	roundkey[2] = data[2];
	roundkey[3] = data[3];
	roundkey[4] = data[4];
	roundkey[5] = data[5];
	
	for (unsigned char index = 6; index < 52; index += 6) {
		roundkey[index] = roundkey[index - 6] ^ 
			(Te4[(roundkey[index - 1] >> 16) & 0xff] & 0xff000000) ^ 
			(Te4[(roundkey[index - 1] >>  8) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index - 1] >>  0) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index - 1] >> 24) & 0xff] & 0x000000ff) ^ rcon[index / 6 - 1];
		roundkey[index + 1] = roundkey[index - 5] ^ roundkey[index];
		roundkey[index + 2] = roundkey[index - 4] ^ roundkey[index + 1];
		roundkey[index + 3] = roundkey[index - 3] ^ roundkey[index + 2];
		
		if (index == 48) {
			break;
		}
		
		roundkey[index + 4] = roundkey[index - 2] ^ roundkey[index + 3];
		roundkey[index + 5] = roundkey[index - 1] ^ roundkey[index + 4];
	}
	
	for (int x = 0; x < 52; x++) {
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
}

bool aes192_detect_dec(const unsigned int *data) {
	unsigned int roundkey[52];
	
	roundkey[0] = data[48];
	roundkey[1] = data[49];
	roundkey[2] = data[50];
	roundkey[3] = data[51];
	
	
	roundkey[4] = data[44];
	roundkey[5] = data[45];

	for (unsigned char index = 6; index < 52; index += 6) {
		roundkey[index] = roundkey[index - 6] ^ 
			(Te4[(roundkey[index - 1] >> 16) & 0xff] & 0xff000000) ^ 
			(Te4[(roundkey[index - 1] >>  8) & 0xff] & 0x00ff0000) ^ 
			(Te4[(roundkey[index - 1] >>  0) & 0xff] & 0x0000ff00) ^ 
			(Te4[(roundkey[index - 1] >> 24) & 0xff] & 0x000000ff) ^ rcon[index / 6 - 1];
		roundkey[index + 1] = roundkey[index - 5] ^ roundkey[index];
		roundkey[index + 2] = roundkey[index - 4] ^ roundkey[index + 1];
		roundkey[index + 3] = roundkey[index - 3] ^ roundkey[index + 2];
		
		if (index == 48) {
			break;
		}
		
		roundkey[index + 4] = roundkey[index - 2] ^ roundkey[index + 3];
		roundkey[index + 5] = roundkey[index - 1] ^ roundkey[index + 4];
	}
	
	unsigned int temp;
	
	// Next, invert the order of the round keys.
	for (uint8_t i = 0, j = 48; i < j; i += 4, j -= 4) {
		temp = roundkey[i + 0];
        roundkey[i + 0] = roundkey[j + 0];
        roundkey[j + 0] = temp;

        temp = roundkey[i + 1];
        roundkey[i + 1] = roundkey[j + 1];
        roundkey[j + 1] = temp;

        temp = roundkey[i + 2];
        roundkey[i + 2] = roundkey[j + 2];
        roundkey[j + 2] = temp;

        temp = roundkey[i + 3];
        roundkey[i + 3] = roundkey[j + 3];
        roundkey[j + 3] = temp;
	}
	
    // Finally, apply the inverse MixColumn transform to all round keys except the first and last.
    for (uint8_t index = 4; index < 48; index += 4) {
        roundkey[index] =
            Td0[Te4[(roundkey[index] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index] >>  0) & 0xff] & 0xff];
        roundkey[index + 1] =
            Td0[Te4[(roundkey[index + 1] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 1] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 1] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 1] >>  0) & 0xff] & 0xff];
        roundkey[index + 2] =
            Td0[Te4[(roundkey[index + 2] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 2] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 2] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 2] >>  0) & 0xff] & 0xff];
        roundkey[index + 3] =
            Td0[Te4[(roundkey[index + 3] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 3] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 3] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 3] >>  0) & 0xff] & 0xff];
    }
    
	for (int x = 0; x < 52; x++) {
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
}

bool aes256_detect_enc(const unsigned int *data) {
	unsigned int roundkey[60];
	
	roundkey[0] = data[0];
	roundkey[1] = data[1];
	roundkey[2] = data[2];
	roundkey[3] = data[3];
	roundkey[4] = data[4];
	roundkey[5] = data[5];;
	roundkey[6] = data[6];
	roundkey[7] = data[7];
	
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
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
}

bool aes256_detect_dec(const unsigned int *data) {
	unsigned int roundkey[60];
	
	roundkey[0] = data[52];
	roundkey[1] = data[53];
	roundkey[2] = data[54];
	roundkey[3] = data[55];
	roundkey[4] = data[56];
	roundkey[5] = data[57];
	roundkey[6] = data[58];
	roundkey[7] = data[59];
	
	/*
	roundkey[0] = data[56];
	roundkey[1] = data[57];
	roundkey[2] = data[58];
	roundkey[3] = data[59];
	roundkey[4] = data[52];
	roundkey[5] = data[53];
	roundkey[6] = data[54];
	roundkey[7] = data[55];
	*/
	
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
	
	unsigned int temp;
	
	// Next, invert the order of the round keys.
    for (unsigned char i = 0, j = 56; i < j; i += 4, j -= 4) {
        temp = roundkey[i + 0];
        roundkey[i + 0] = roundkey[j + 0];
        roundkey[j + 0] = temp;

        temp = roundkey[i + 1];
        roundkey[i + 1] = roundkey[j + 1];
        roundkey[j + 1] = temp;

        temp = roundkey[i + 2];
        roundkey[i + 2] = roundkey[j + 2];
        roundkey[j + 2] = temp;

        temp = roundkey[i + 3];
        roundkey[i + 3] = roundkey[j + 3];
        roundkey[j + 3] = temp;
    }

    // Finally, apply the inverse MixColumn transform to all round keys except the first and last.
    for (unsigned char index = 4; index < 56; index += 4) {
        roundkey[index] =
            Td0[Te4[(roundkey[index] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index] >>  0) & 0xff] & 0xff];
        roundkey[index + 1] =
            Td0[Te4[(roundkey[index + 1] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 1] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 1] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 1] >>  0) & 0xff] & 0xff];
        roundkey[index + 2] =
            Td0[Te4[(roundkey[index + 2] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 2] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 2] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 2] >>  0) & 0xff] & 0xff];
        roundkey[index + 3] =
            Td0[Te4[(roundkey[index + 3] >> 24) & 0xff] & 0xff] ^
            Td1[Te4[(roundkey[index + 3] >> 16) & 0xff] & 0xff] ^
            Td2[Te4[(roundkey[index + 3] >>  8) & 0xff] & 0xff] ^
            Td3[Te4[(roundkey[index + 3] >>  0) & 0xff] & 0xff];
    }
	
	for (int x = 0; x < 60; x++) {
		if (roundkey[x] != data[x]) {
			return false;
		}
	}
	
	return true;
} 

void find_keys(const unsigned long long address, const unsigned int *data) {
	if (aes128_detect_enc(data)) {
		printf("[%p] Found AES-128 encryption key: 0x", (void*)address);
		for (int index = 0; index < 4; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	} else if (aes128_detect_dec(data)) {
		printf("[%p] Found AES-128 decryption key: 0x", (void*)address);
		for (int index = 40; index < 44; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	}
	
	if (aes192_detect_enc(data)) {
		printf("[%p] Found AES-192 encryption key: 0x", (void*)address);
		for (int index = 0; index < 6; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	} else if (aes192_detect_dec(data)) {
		printf("[%p] Found AES-192 decryption key: 0x", (void*)address);
		for (int index = 46; index < 52; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	}
	
	if (aes256_detect_enc(data)) {
		printf("[%p] Found AES-256 encryption key: 0x", (void*)address);
		for (int index = 0; index < 8; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	} else if (aes256_detect_dec(data)) {
		printf("[%p] Found AES-256 decryption key: 0x", (void*)address);
		for (int index = 52; index < 60; index++) {
			printf("%X", data[index]);
		}
		printf("\n");
	}
}

int main(int argc, const char *argv[]) {
	const char* package = argv[1];
	const char* module = "[stack]"; // stack is store local variable 
	
	unsigned long long start = 0, end = 0;
	unsigned int data[60];
    
	pid_t pid = -1;
	
	printf("[INFO] Waiting for opening '%s' process\n", package);
	
	while (pid == -1) {
		pid = find_pid(package);
	}
	
	printf("[INFO] Process '%s' is now open pid %d\n", package, pid);
	
	printf("[INFO] Searching keys...\n");
	
	if (!get_module_address(pid, module, &start, &end)) {
		printf("[ERROR] Can't find module address\n");
		return 1;
	}
	
	unsigned long long address = start;
	unsigned long long remaining = end - start;
	
	clock_t t0, t1;
	double cpu_time_used;
	t0 = clock();
	
	while (remaining > 0) {
		if (read_process_memory(pid, address, &data, 240) == -1) {
			printf("[ERROR] Can't read memory at %p\n", (void*)&start);
			break;
		}
		
		find_keys(address, data);
		
		remaining--;
		address++;
	}
	
	t1 = clock();
	cpu_time_used = ((double) (t1 - t0)) / CLOCKS_PER_SEC;
	printf("[INFO] Process completed in %f seconds\n", cpu_time_used);
	return 0;
}