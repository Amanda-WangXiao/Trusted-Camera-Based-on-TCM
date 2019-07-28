#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
 
#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "ex_module.h"
#include "sys_func.h"
#include "tcm_constants.h"
#include "tcm_structures.h"
#include "tcmfunc.h"
#include "tcm_cube_struct.h"
#include "tcm_key_manage.h"
#include "tcm_key_desc.h"
#include "tcm_pik_desc.h"
#include "pikcert_verify.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";

int pikcert_verify_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();
	if(ret!=0)
	{
		print_cubeerr("Init TCM_Lib error!\n");
		return ret;
	}
	// Read TCM's CA Pub Key
    	ret=TCM_ExLoadCAPubKey(capubkeyfile);
    	if(ret<0)
    	{
		printf("TCM_ExLoadCAPubKey failed!\n");
		return -EINVAL;	
    	}		

	// add yorself's module init func here
	return 0;
}
int pikcert_verify_start(void * sub_proc, void * para)
{
	int ret;
	void * recv_msg;
	int type;
	int subtype;
	// add yorself's module exec func here

	while(1)
	{
		usleep(time_val.tv_usec);
		ret=ex_module_recvmsg(sub_proc,&recv_msg);
		if(ret<0)
			continue;
		if(recv_msg==NULL)
			continue;
		type=message_get_type(recv_msg);
		subtype=message_get_subtype(recv_msg);
		if(!memdb_find_recordtype(type,subtype))
		{
			printf("message format (%d %d) is not registered!\n",
			message_get_type(recv_msg),message_get_subtype(recv_msg));
			continue;
		}
	
		if((type==TYPE(TCM_PIK_DESC))&&(subtype==SUBTYPE(TCM_PIK_DESC,PIKCERT)))
		{
			ret=proc_tcm_pikcert_verify(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_pikcert_verify(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	RECORD(TCM_PIK_DESC,PIKCERT)  * pik_cert;
	RECORD(TCM_KEY_DESC,VERIFY_DESC) verify_desc;
	
	void * new_msg;
	int blob_len;
	int info_len;
	void * tcm_key_template;

	char uuid[DIGEST_SIZE*2+1];

	printf("begin pikcert verify process!\n");

	// get pik_userinfo from message
	
	ret=message_get_record(recv_msg,&pik_cert,0);
	if(ret<0)
		return -EINVAL;
	if(pik_cert==NULL)
		return -EINVAL;
	
	// Init verify_desc 	
	Memset(&verify_desc,0,sizeof(verify_desc));

	// verify pik_cert's verify data
	
    	Memcpy(Buf,pik_cert->verifydata.userDigest,DIGEST_SIZE);
    	Memcpy(Buf+DIGEST_SIZE,pik_cert->verifydata.pubDigest,DIGEST_SIZE);
	
    	ret=TCM_ExCAPubKeyVerify(pik_cert->verifydata.signData,pik_cert->verifydata.signLen,
			Buf,DIGEST_SIZE*2);
    	if(ret!=0)
    	{
		printf("verify pik_cert's sign  failed!\n");
		verify_desc.result=1;
    	}
	else  // check userinfo and pikinfo's integrity
	{
		blob_len=memdb_output_blob(&pik_cert->userinfo,Buf,TYPE_PAIR(TCM_PIK_DESC,USERINFO));
		if(blob_len<0)
			return -EINVAL;
		vtcm_ex_sm3(digest,1,Buf,blob_len);
    		if(Memcmp(digest,pik_cert->verifydata.userDigest,DIGEST_SIZE)!=0)
    		{	
			print_cubeerr("check user info failed!\n");
			verify_desc.result=2;
    		}
		
		else
		{
			blob_len=memdb_output_blob(&pik_cert->pikpub.pubKey,Buf,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY));
			if(blob_len<0)
				return -EINVAL;
			vtcm_ex_sm3(digest,1,Buf,blob_len);
    			if(Memcmp(digest,pik_cert->verifydata.pubDigest,DIGEST_SIZE)!=0)
    			{	
				print_cubeerr("check pik pub failed!\n");
				verify_desc.result=2;
    			}
		}
	}

	blob_len=memdb_output_blob(pik_cert,Buf,TYPE_PAIR(TCM_PIK_DESC,PIKCERT));
	if(blob_len<0)
		return -EINVAL;
	vtcm_ex_sm3(verify_desc.object_uuid,1,Buf,blob_len);
	
	// build a message and send it 
	new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,PIKCERT),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,pik_cert);
	if(ret<0)
		return ret;

	ret=message_add_expand_data(new_msg,TYPE_PAIR(TCM_KEY_DESC,VERIFY_DESC),&verify_desc);
	if(ret<0)
		return ret;

	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

