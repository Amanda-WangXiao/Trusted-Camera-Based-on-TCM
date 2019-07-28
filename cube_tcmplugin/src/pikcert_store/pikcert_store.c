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
#include "pikcert_store.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";

int pikcert_store_init(void * sub_proc, void * para)
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
int pikcert_store_start(void * sub_proc, void * para)
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
			ret=proc_tcm_pikcert_store(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_pikcert_store(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	BYTE user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	RECORD(TCM_PIK_DESC,PIKCERT)  * pik_cert;
	RECORD(TCM_KEY_DESC,VERIFY_DESC) * verify_desc;
	MSG_EXPAND * msg_expand;
	DB_RECORD * db_record;
	void * new_msg;
	int blob_len;
	int info_len;
	void * tcm_key_template;
	int isremote=1;

	char uuid[DIGEST_SIZE*2+1];

	printf("begin pikcert store!\n");

	// get this node's machine uuid and user name
        ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;

        ret=proc_share_data_getvalue("user_name",user_name);
	if(ret<0)
		return ret;

	// get pik_cert from message
	
	ret=message_get_record(recv_msg,&pik_cert,0);
	if(ret<0)
		return -EINVAL;
	if(pik_cert==NULL)
		return -EINVAL;

	// judget if it is local pik
	if(Memcmp(local_uuid,pik_cert->userinfo.node_uuid,DIGEST_SIZE)==0)
	{
		if(Strncmp(user_name,pik_cert->userinfo.username,DIGEST_SIZE)==0)
			isremote=0;
	}
	
	if(isremote)
	{
		//remote pik, need to create pikpub info,remote_keyset and save pikpub file
		RECORD(TCM_KEY_MANAGE,PUBLIC_KEY) * pikpub_info;		
		RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;		
		pikpub_info=Talloc0(sizeof(*pikpub_info));
		if(pikpub_info==NULL)
			return -ENOMEM;
		remote_keyset=Talloc0(sizeof(*remote_keyset));
		if(remote_keyset==NULL)
			return -ENOMEM;
		// Generate pikpub info record and save it
		Memcpy(pikpub_info->vtcm_uuid,pik_cert->userinfo.node_uuid,DIGEST_SIZE);	
		pikpub_info->key_usage=TCM_KEY_IDENTITY;
		pikpub_info->key_flags=TCM_ISVOLATILE|TCM_PCRIGNOREDONREAD;
		
		db_record=memdb_store(pikpub_info,TYPE_PAIR(TCM_KEY_MANAGE,PUBLIC_KEY),NULL);

		// store pikpub 	

		ret=memdb_output_blob(&pik_cert->pikpub,Buf,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
		if(ret<0)
			return -EINVAL;
		blob_len=ret;
		vtcm_ex_sm3(remote_keyset->pikpub_uuid,1,Buf,blob_len);
		digest_to_uuid(remote_keyset->pikpub_uuid,uuid);
		uuid[DIGEST_SIZE*2]=0;
		printf("pikcert_store: get pikpub's uuid is %s!\n",uuid);	
	
		Strcpy(NameBuf,"pubkey/");
		Strcat(NameBuf,uuid);

        	fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        	if(fd<0)
               		return fd;
        	write(fd,Buf,blob_len);
        	close(fd);
				
		// store cert
		ret=memdb_output_blob(pik_cert,Buf,TYPE_PAIR(TCM_PIK_DESC,PIKCERT));
		if(ret<0)
			return -EINVAL;
		blob_len=ret;
		vtcm_ex_sm3(remote_keyset->pikcert_uuid,1,Buf,blob_len);
		digest_to_uuid(remote_keyset->pikcert_uuid,uuid);
		uuid[DIGEST_SIZE*2]=0;
		printf("pikcert_store: get pikcert's uuid is %s!\n",uuid);	
	
		Strcpy(NameBuf,"cert/");
		Strcat(NameBuf,uuid);

        	fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        	if(fd<0)
               		return fd;
        	write(fd,Buf,blob_len);
        	close(fd);
				
		// fill the remote_keyset record
		Strncpy(remote_keyset->user_name,pik_cert->userinfo.username,DIGEST_SIZE);
		Memcpy(remote_keyset->node_uuid,pik_cert->userinfo.node_uuid,DIGEST_SIZE);	
		db_record=memdb_store(remote_keyset,TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET),NULL);

		// generate store notice message
		new_msg=message_create(TYPE_PAIR(MESSAGE,TYPES),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		RECORD(MESSAGE,TYPES) type_pair;
		type_pair.type=TYPE(TCM_KEY_MANAGE);
		type_pair.subtype=SUBTYPE(TCM_KEY_MANAGE,PUBLIC_KEY);
		message_add_record(new_msg,&type_pair);
//		type_pair.type=TYPE(TCM_KEY_DESC);
//		type_pair.subtype=SUBTYPE(TCM_KEY_DESC,REMOTE_KEYSET);
//		message_add_record(new_msg,&type_pair);
	}
	else
	{
		// local pik, need to create local_keyset ,pik info and store pik_cert
		//
		RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * pik_info;		
		RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;		
		local_keyset=Talloc0(sizeof(*local_keyset));
		if(local_keyset==NULL)
			return -ENOMEM;

		// find pik_info  	

		ret=memdb_output_blob(&pik_cert->pikpub,Buf,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
		if(ret<0)
			return -EINVAL;
		blob_len=ret;
		vtcm_ex_sm3(digest,1,Buf,blob_len);
		db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),"pubkey_uuid",digest);
		if(db_record==NULL)
		{
			print_cubeerr("pikcert_store: can't find local pik!\n");	
			return -EINVAL;
		}
		pik_info=db_record->record;
		Memcpy(local_keyset->pik_uuid,pik_info->uuid,DIGEST_SIZE);
				
		// store cert
		ret=memdb_output_blob(pik_cert,Buf,TYPE_PAIR(TCM_PIK_DESC,PIKCERT));
		if(ret<0)
			return -EINVAL;
		blob_len=ret;
		vtcm_ex_sm3(local_keyset->pikcert_uuid,1,Buf,blob_len);
		digest_to_uuid(local_keyset->pikcert_uuid,uuid);
		uuid[DIGEST_SIZE*2]=0;
		printf("pikcert_store: get pikcert's uuid is %s!\n",uuid);	
	
		Strcpy(NameBuf,"cert/");
		Strcat(NameBuf,uuid);

        	fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        	if(fd<0)
               		return fd;
        	write(fd,Buf,blob_len);
        	close(fd);
				
		// fill the remote_keyset record
		Strncpy(local_keyset->user_name,pik_cert->userinfo.username,DIGEST_SIZE);
		new_msg=message_create(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		message_add_record(new_msg,local_keyset);
		
/*
		//Memcpy(local_keyset->node_uuid,pik_cert->userinfo.node_uuid,DIGEST_SIZE);	
		db_record=memdb_store(local_keyset,TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),NULL);

		// generate store notice message
		new_msg=message_create(TYPE_PAIR(MESSAGE,TYPES),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		RECORD(MESSAGE,TYPES) type_pair;
		type_pair.type=TYPE(TCM_KEY_DESC);
		type_pair.subtype=SUBTYPE(TCM_KEY_DESC,LOCAL_KEYSET);
		message_add_record(new_msg,&type_pair);
*/
	}
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

