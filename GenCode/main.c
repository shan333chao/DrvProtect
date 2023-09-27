



/**
 * @file ntp_test.c
 * Copyright (c) 2018 Gaaagaa. All rights reserved.
 *
 * @author  : Gaaagaa
 * @date    : 2018-10-19
 * @version : 1.0.0.0
 * @brief   : 使用 NTP 协议获取网络时间戳的测试程序。
 */
#include  "ntpclient/ntp_client.h"
#include "aes.h"
 ////////////////////////////////////////////////////////////////////////////////

 

typedef struct _REG_VALID {
	ULONGLONG TIMESPAN;
	int DAYS;
	ULONGLONG CTIME;
}REG_VALID,*PREG_VALID;
 
 
 
int main(int argc, char* argv[])
{
 
	ULONG a = 2;
	ULONG b = 5;
	ULONG c = a - b;
	printf("Timestamp: %d \n", c);
	unsigned long long milliseconds = time(NULL);
	printf("Timestamp: %llu\n", milliseconds);

 
	REG_VALID reg = { 0 };
	reg.CTIME = milliseconds;
	reg.DAYS = 1;
	reg.TIMESPAN = milliseconds + reg.DAYS *  60 * 60 * 24;

	printf("Timestamp: %llu\n", reg.TIMESPAN); 


	struct AES_ctx ctx = { 0 };
	unsigned char key[] = "\xde\xad\xbe\xef\xca\xfe\xba\xbe\xde\xad\xbe\xef\xca\xfe\xba\xbe";
	unsigned char iv[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
	srand(time(NULL));
	for (size_t i = 0; i < sizeof(key); i++)
	{
		key[i] = rand() % 0x100;
		iv[i] = rand() % 0x100;
	}
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, (uint8_t*)&reg, sizeof(REG_VALID));
	PUCHAR encryptCode = malloc(sizeof(key)*2+ sizeof(REG_VALID));
	memcpy(encryptCode, key,sizeof(key));
	memcpy(encryptCode+ sizeof(key), &reg, sizeof(REG_VALID));
	memcpy(encryptCode + sizeof(key) + sizeof(reg), iv, sizeof(iv));
	for (size_t i = 0; i < sizeof(key)*2+ sizeof(reg); i++)
	{
		printf("%02x", encryptCode[i]);
	}
	printf("\t\n");
	getchar();
	return 0;
}
