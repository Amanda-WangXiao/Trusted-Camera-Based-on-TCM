/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004, 2005
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "tesi.h"
#include "cube_cafunc.h"
#define DIGEST_SIZE 32
#define PADDING_MODE RSA_PKCS1_PADDING

static char * password="my ca center";

#define ENTRY_COUNT 6

struct entry entries[ENTRY_COUNT] =
{
	{"countryName","CN"},
	{"stateOrProvinceName","BeiJing"},
	{"localityName","Chaoyang"},
	{"organizationName","bjut.edu.cn"},
	{"organizationalUnitName","CS Academy"},
	{"commonName","Test CA"},
};

int main( void )
{
	int ret;
	char			*function = "Tspi_TESI_Init";
	TSS_RESULT		result = 0;
	TSS_HKEY 		hCAKey;
	TSS_HKEY 		hSignKey;
	TSS_HKEY 		hReloadKey;
	TSS_HKEY 		hReloadPubKey;

	X509_REQ * cert_req;
	X509 * cert;
	
	char uuid[DIGEST_SIZE*2];
	char buf[4096];

	RSA * rsa;
	RSA * rsa1;
	RSA * rsa2;


	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	result=TESI_Local_ReloadWithAuth("ooo","sss");

	if ( result != TSS_SUCCESS )
	{
		printf("TESI_Local_Load Err!\n");
		return result;
	}

	int num=1024;
	result=TESI_Local_GetRandom(buf,num);
	if(result == TSS_SUCCESS)
		printf("Get %d Random num SUCCEED!\n",num);
	else
		return -EINVAL;
	
	RAND_seed(buf,num);
	
	rsa=Generate_RSA_Key();
	if(rsa==NULL)
	{
		printf("Generate RSA Key Failed!\n");
		return -EINVAL;
	}

	ret=Sign_RSA_file("hello.txt",rsa,"hello.sig");
	ret=Pubcrypt_RSA_file("hello.txt",rsa,"hello.crypt");

	WritePrivKey(rsa,"CA",password);
	WritePubKey(rsa,"CA");

	
	
//	RSA_free(rsa);

	result=ReadPubKey(&rsa1,"CA");
	if(result == TSS_SUCCESS)
		printf("read pubKey SUCCEED!\n");
	else
		return -EINVAL;
	
	result=Verify_RSA_file("hello.txt",rsa1,"hello.sig");

	if(result==TSS_SUCCESS)
	{
		printf("verify file succeed!\n");
	}
	else
	{
		printf("Verify file failed!\n");
	} 


//	RSA_free(rsa1);
	result=ReadPrivKey(&rsa2,"CA",password);
	if(result == TSS_SUCCESS)
		printf("read privkey  SUCCEED!\n");
	else
		return -EINVAL;
	ret=Privdecrypt_RSA_file("hello.crypt",rsa2,"hello1.txt");


	result=Create_X509_RSA_Cert("CA",6,entries,rsa1,rsa2);
	return result;
}
