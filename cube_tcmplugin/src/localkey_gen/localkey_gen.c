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
#include "localkey_gen.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";

int localkey_gen_init(void * sub_proc, void * para)
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
int localkey_gen_start(void * sub_proc, void * para)
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
	
		if((type==TYPE(TCM_KEY_DESC))&&(subtype==SUBTYPE(TCM_KEY_DESC,LOCAL_KEYSET)))
		{
			ret=proc_tcm_localkey_gen(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_localkey_gen(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	BYTE user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;
	RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key;		
	MSG_EXPAND * msg_expand;
	DB_RECORD * db_record;
	void * new_msg;
	int blob_len;
	int info_len;
	void * tcm_key_template;

	int ifsignkeyexist=1;
	int ifbindkeyexist=1;

	char uuid[DIGEST_SIZE*2+1];

	printf("begin pikcert store!\n");

	// get this node's machine uuid and user name
        ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;

        ret=proc_share_data_getvalue("user_name",user_name);
	if(ret<0)
		return ret;

	// get local_keyset from message
	
	ret=message_get_record(recv_msg,&local_keyset,0);
	if(ret<0)
		return -EINVAL;
	if(local_keyset==NULL)
		return -EINVAL;

	if(Isemptyuuid(local_keyset->signkey_uuid))
		ifsignkeyexist=0;
	if(Isemptyuuid(local_keyset->unbindkey_uuid))
		ifbindkeyexist=0;

	ret=message_remove_expand(recv_msg,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),&msg_expand);
	if(ret<0)
		return ret;
	if(msg_expand == NULL)
		private_key=NULL;
	else
		private_key=msg_expand->expand;
	if(private_key!=NULL)
	{
		// store key in local_keyset
		
		if(private_key->key_usage == TCM_SM2KEY_SIGNING)
		{
			if(ifsignkeyexist==0)
			{
			// this is a key for sign
				Memcpy(local_keyset->signkey_uuid,private_key->uuid,DIGEST_SIZE);
				ifsignkeyexist=1;
			}
		}
		if(private_key->key_usage == TCM_SM2KEY_STORAGE)
		{
			if(ifbindkeyexist==0)
			{
			// this is a key for sign
				Memcpy(local_keyset->unbindkey_uuid,private_key->uuid,DIGEST_SIZE);
				ifbindkeyexist=1;
			}
		}

	}
	if( ifsignkeyexist && ifbindkeyexist)
	{
		db_record=memdb_store(local_keyset,TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),NULL);
		if(db_record==NULL)
			return -EINVAL;
		new_msg=message_gen_typesmsg(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		ret=ex_module_sendmsg(sub_proc,new_msg);
		return ret;
	}

	private_key=Talloc0(sizeof(*private_key));
	if(private_key==NULL)
		return -ENOMEM;	
		// prepare to generate signkey	
 	private_key->issmkwrapped=1;
	private_key->key_flags=TCM_ISVOLATILE|TCM_PCRIGNOREDONREAD;
	if(ifsignkeyexist==0)
	{	
		private_key->key_usage=TCM_SM2KEY_SIGNING;
	}
	else 
	{
		private_key->key_usage=TCM_SM2KEY_STORAGE;
	}

	// generate store notice message
	new_msg=message_create(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),NULL);
	if(new_msg==NULL)
		return -EINVAL;
	message_add_record(new_msg,local_keyset);
	message_add_expand_data(new_msg,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),private_key);
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

