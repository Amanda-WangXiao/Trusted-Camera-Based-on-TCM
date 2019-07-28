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
#include "remotekey_gen.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";

RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset_get (char * name);
int get_pubkey_from_privkey(BYTE * privkey_uuid,BYTE * pubkey_uuid);

int remotekey_gen_init(void * sub_proc, void * para)
{
	int ret;

	// add yorself's module init func here
	return 0;
}
int remotekey_gen_start(void * sub_proc, void * para)
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
	
		if((type==TYPE(MESSAGE))&&(subtype==SUBTYPE(MESSAGE,INSTANCE_INFO)))
		{
			ret=proc_tcm_remotekey_gen(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_remotekey_gen(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	BYTE user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	RECORD(MESSAGE,INSTANCE_INFO) * instance_info;
	RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;
	RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;
	RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key;		
	RECORD(MESSAGE,BASE_MSG) * receiver;		
	MSG_EXPAND * msg_expand;
	DB_RECORD * db_record;
	void * new_msg;
	int blob_len;
	int info_len;
	void * tcm_key_template;

	char uuid[DIGEST_SIZE*2+1];

	printf("begin remotekey generate !\n");


	// get local_keyset from message
	
	ret=message_get_record(recv_msg,&instance_info,0);
	if(ret<0)
		return -EINVAL;
	if(instance_info==NULL)
		return -EINVAL;

	local_keyset=local_keyset_get(instance_info->user_name);
	if(local_keyset==NULL)
		return -EINVAL;

	remote_keyset=Talloc0(sizeof(*remote_keyset));
	if(remote_keyset==NULL)
		return -ENOMEM;
	
	Strncpy(remote_keyset->user_name,local_keyset->user_name,DIGEST_SIZE);
	Memcpy(remote_keyset->node_uuid,instance_info->node_uuid,DIGEST_SIZE);
	Memcpy(remote_keyset->pikcert_uuid,local_keyset->pikcert_uuid,DIGEST_SIZE);
	
	// get pik, signkey and unbindkey's publickey uuid

	ret = get_pubkey_from_privkey(local_keyset->pik_uuid,remote_keyset->pikpub_uuid);
	if(ret<0)
	{
		print_cubeerr("get pik pub failed!\n");
		return ret;
	}

	ret = get_pubkey_from_privkey(local_keyset->signkey_uuid,remote_keyset->verifykey_uuid);
	if(ret<0)
	{
		print_cubeerr("get signkey  pub failed!\n");
		return ret;
	}

	ret = get_pubkey_from_privkey(local_keyset->signkey_uuid,remote_keyset->verifykey_uuid);
	if(ret<0)
	{
		print_cubeerr("get signkey  pub failed!\n");
		return ret;
	}

	ret = get_pubkey_from_privkey(local_keyset->unbindkey_uuid,remote_keyset->bindkey_uuid);
	if(ret<0)
	{
		print_cubeerr("get bindkey  pub failed!\n");
		return ret;
	}
		
	ret=message_get_define_expand(recv_msg,&msg_expand,TYPE_PAIR(MESSAGE,BASE_MSG));
	if(ret<0)
		return ret;
	receiver=msg_expand->expand;
		

	new_msg=message_create(TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET),NULL);
	if(new_msg==NULL)
		return -EINVAL;
	message_add_record(new_msg,remote_keyset);
	if(receiver!=NULL)
	{
		message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,BASE_MSG),receiver);
	}

	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset_get (char * name)
{
	int ret;
	RECORD(TCM_KEY_DESC,LOCAL_KEYSET ) * local_keyset;
	DB_RECORD * db_record;
	char buf[DIGEST_SIZE];
	int i;
	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),"user_name",name);
	if(db_record==NULL)
		return NULL;
	return db_record->record;
}

int get_pubkey_from_privkey(BYTE * privkey_uuid,BYTE * pubkey_uuid)
{

	RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key;		
	DB_RECORD * db_record;
	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),"uuid",privkey_uuid);
	if(db_record==NULL)
		return -EINVAL;
	private_key=db_record->record;
	Memcpy(pubkey_uuid,private_key->pubkey_uuid,DIGEST_SIZE);
	return 0;
}


/*
RECORD(TAC_KEY_DESC,LOCAL_KEYSET) * local_keyset_get (BYTE *uuid,char * name)
{
	int ret;
	RECORD(TAC_KEY_DESC,LOCAL_KEYSET ) * local_keyset;
	DB_RECORD * db_record;
	char buf[DIGEST_SIZE];
	int i;
	local_keyset=memdb_get_first_record(TYPE_PAIR(TAC_KEY_DESC,LOCAL_KEYSET));
	while(local_keyset!=NULL)
	{
		ret=0;
		if(uuid!=NULL)
		{
			if(Memcmp(uuid,local_keyset->node_uuid,DIGEST_SIZE)==0)
				ret=1;
			else
				ret=-1;
		}
		if(name!=NULL)
		{
			if(Strncmp(name,local_keyset->user_name,DIGEST_SIZE)==0)
			{
				if(ret==0)
					ret=1;
			}
			else
				ret=0;

		}
		if(ret==1)
			break;
		local_keyset=memdb_get_next_record(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET));
		
	}

	return local_keyset;
}
*/
