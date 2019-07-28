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
#include "sessionkey_switch.h"
// add para lib_include
	BYTE Buf[DIGEST_SIZE*16];
RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset_get_byname (char * name);
RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset_get_byname (char * name);

int sessionkey_switch_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();

	// add yorself's module init func here
	return 0;
}
int sessionkey_switch_start(void * sub_proc, void * para)
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
			
		if( message_get_flag(recv_msg)&MSG_FLAG_CRYPT)
			proc_sessionkey_recover(sub_proc,recv_msg);
		else
			proc_sessionkey_gen(sub_proc,recv_msg);
	}
	return 0;
}

int proc_sessionkey_gen(void * sub_proc,void * recv_msg)
{
	int ret=0;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Namebuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(MESSAGE,SIZED_BINDATA) * key_blob;
	RECORD(MESSAGE,UUID_RECORD) * key_data;
	RECORD(MESSAGE,BASE_MSG) * user_name;
	void * new_msg;

	MSG_EXPAND * msg_expand;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) * pubkey;
        RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;

	BYTE * SessionKey;
	int key_len;
	int blob_len;

	char uuid[DIGEST_SIZE*2+1];
        
	printf("begin sessionkey generate!\n");

	// get receiver's remote keyset
	ret=message_get_define_expand(recv_msg,&msg_expand,TYPE_PAIR(MESSAGE,BASE_MSG));
	if(ret<0)
		return -EINVAL;
	if(msg_expand==NULL)
		return -EINVAL;

	user_name=msg_expand->expand;

	remote_keyset=remote_keyset_get_byname(user_name->message);
	if(remote_keyset==NULL)
		return -EINVAL;

	// get remote_keyset's bindkey

	Strcpy(Namebuf,"pubkey/");
	digest_to_uuid(remote_keyset->bindkey_uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	Strcat(Namebuf,uuid);
	
	pubkey=Talloc0(sizeof(*pubkey));
	if(pubkey==NULL)
		return -ENOMEM;
	ret=TCM_ExLoadTcmPubKey(pubkey,Namebuf);
	if(ret!=0)
		return -EINVAL;

	printf("get pubkey %s succeed!\n",Namebuf);
	// generate random data as session key and generate a (MESSAGE,UUID_RECORD) record to store it
	
	ret=TCM_GetRandom(DIGEST_SIZE,&SessionKey,&key_len);
	if(ret!=0)
		return ret;
	if(key_len!=DIGEST_SIZE)
		return -EINVAL;

	key_data=Talloc0(sizeof(*key_data));
	if(key_data==NULL)
		return -ENOMEM;
	Memcpy(key_data->uuid,SessionKey,DIGEST_SIZE);

	// Generate sessionkey_blob
	
	ret=TCM_ExSM2Encrypt(pubkey,Buf,&blob_len,SessionKey,key_len);
	if(ret!=0)
		return ret;

	key_blob=Talloc0(sizeof(*key_blob));
	if(key_blob==NULL)
		return -ENOMEM;
	key_blob->size=blob_len;
	key_blob->bindata=Talloc0(blob_len);
	if(key_blob->bindata==NULL)
		return -ENOMEM;
	Memcpy(key_blob->bindata,Buf,key_blob->size);
	
	// Output ekpub's desc and Data

//	new_msg=message_clone(recv_msg);	
	new_msg=recv_msg;	
	if(new_msg==NULL)
		return -EINVAL;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
	
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,UUID_RECORD),key_data);
	if(ret<0)
		return -EINVAL;
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),key_blob);
	if(ret<0)
		return -EINVAL;

	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}
int proc_sessionkey_recover(void * sub_proc,void * recv_msg)
{
	int ret=0;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Namebuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(MESSAGE,SIZED_BINDATA) * key_blob;
	RECORD(MESSAGE,UUID_RECORD) * key_data;
	RECORD(MESSAGE,BASE_MSG) * user_name;
	void * new_msg;

	MSG_EXPAND * msg_expand;
        RECORD(VTCM_IN_KEY,TCM_BIN_KEY) * tcmkey;
        RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;

	BYTE * SessionKey;
	int key_len;
	int blob_len;

	char uuid[DIGEST_SIZE*2+1];
        
	printf("begin sessionkey recover!\n");

	// remove 
	ret=message_remove_expand(recv_msg,TYPE_PAIR(MESSAGE,UUID_RECORD),&msg_expand);
	// get receiver's remote keyset
	ret=message_get_define_expand(recv_msg,&msg_expand,TYPE_PAIR(MESSAGE,BASE_MSG));
	if(ret<0)
		return -EINVAL;
	if(msg_expand==NULL)
		return -EINVAL;

	user_name=msg_expand->expand;

	local_keyset=local_keyset_get_byname(user_name->message);
	if(local_keyset==NULL)
		return -EINVAL;

	// get local_keyset's unbindkey

	Strcpy(Namebuf,"tcmkey/");
	digest_to_uuid(local_keyset->unbindkey_uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	Strcat(Namebuf,uuid);
	
	tcmkey=Talloc0(sizeof(*tcmkey));
	if(tcmkey==NULL)
		return -ENOMEM;
	ret=TCM_ExLoadTcmKey(tcmkey,Namebuf);
	if(ret!=0)
		return -EINVAL;
	printf("get tcmkey %s succeed!\n",Namebuf);

	// get sessionkey_blob
	ret=message_remove_expand(recv_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),&msg_expand);
	if(ret<0)
		return ret;
	if(msg_expand==NULL)
		return -EINVAL;
	key_blob=msg_expand->expand;
	
	// recover sessionkey 
	UINT32 authHandle;
	UINT32 keyHandle;
	UINT32 keyAuthHandle;

    	ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &authHandle);
    	if(ret!=0)
    	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	
    	ret=TCM_LoadKey(0x40000000,authHandle,tcmkey,&keyHandle);
   	if(ret!=0)
    	{
		printf("TCM_LoadKey failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_APCreate(TCM_ET_KEYHANDLE, keyHandle, "sss", &keyAuthHandle);
   	if(ret!=0)
    	{
		printf("TCM_APCreate %dfailed!\n",12);
		return -EINVAL;	
    	}	

    	ret=TCM_SM2Decrypt(keyHandle,keyAuthHandle,Buf,&key_len,key_blob->bindata,key_blob->size);
   	if(ret!=0)
    	{
		printf("TCM_SM2Decrypt%d failed!\n",ret);
		return -EINVAL;	
    	}	

    	ret=TCM_APTerminate(authHandle);
    	if(ret<0)
    	{
		printf("TCM_APTerminate %x failed!\n",authHandle);
		return -EINVAL;	
   	 }	
    	ret=TCM_APTerminate(keyAuthHandle);
    	if(ret!=0)
    	{
		printf("TCM_APTerminate %x failed!\n",keyAuthHandle);
		return -EINVAL;	
	}
    	ret=TCM_EvictKey(keyHandle);
    	if(ret!=0)
    	{
		printf("TCM_EvictKey %x failed!\n",keyHandle);
		return -EINVAL;	
    	}	
	
	if(key_len!=DIGEST_SIZE)
		return -EINVAL;

	key_data=Talloc0(sizeof(*key_data));
	if(key_data==NULL)
		return -ENOMEM;
	Memcpy(key_data->uuid,Buf,DIGEST_SIZE);

	// add keydata in message
	
	new_msg=recv_msg;	
	if(new_msg==NULL)
		return -EINVAL;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
	
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,UUID_RECORD),key_data);
	if(ret<0)
		return -EINVAL;
	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset_get_byname (char * name)
{
	int ret;
	RECORD(TCM_KEY_DESC,REMOTE_KEYSET ) * remote_keyset;
	DB_RECORD * db_record;
	char buf[DIGEST_SIZE];
	int i;
	Memset(buf,0,DIGEST_SIZE);
	Strncpy(buf,name,DIGEST_SIZE);
	
	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET),"user_name",buf);

	if(db_record==NULL)
		return NULL;
	return db_record->record;
}
RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset_get_byname (char * name)
{
	int ret;
	RECORD(TCM_KEY_DESC,LOCAL_KEYSET ) * local_keyset;
	DB_RECORD * db_record;
	char buf[DIGEST_SIZE];
	Memset(buf,0,DIGEST_SIZE);
	Strncpy(buf,name,DIGEST_SIZE);
	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),"user_name",buf);

	if(db_record==NULL)
		return NULL;
	return db_record->record;
}
