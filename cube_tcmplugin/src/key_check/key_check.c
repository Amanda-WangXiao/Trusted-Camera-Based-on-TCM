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
#include "key_check.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";
RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset_get (BYTE *uuid,char * name);

int key_check_init(void * sub_proc, void * para)
{
	int ret;
	return 0;
}
int key_check_start(void * sub_proc, void * para)
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
			ret=proc_keyset_check(sub_proc,recv_msg);
		}
		else
		{
			ret=proc_keyset_check_inexpand(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_keyset_check(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	char user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_PIK_DESC,USERINFO)  * userinfo;
	RECORD(MESSAGE,INSTANCE_INFO)  * instance_info;
        RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;
        RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;
	void * new_msg;
	int islocal=1;
	int find_keyset=0;

	char uuid[DIGEST_SIZE*2+1];
	DB_RECORD * db_record;
        
	printf("begin keyset check!\n");

	// get pik_userinfo from message
	
	ret=message_get_record(recv_msg,&instance_info,0);
	if(ret<0)
		return -EINVAL;
	if(instance_info==NULL)
		return -EINVAL;

	// get this node's machine uuid
        ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;

	// get this node's user name
        ret=proc_share_data_getvalue("user_name",user_name);
	if(ret<0)
		return ret;

	// judge if it is local user
	//
	if(Memcmp(local_uuid,instance_info->node_uuid,DIGEST_SIZE)!=0)
	{
		islocal=0;
	} 
	else if(Strncmp(user_name,instance_info->user_name,DIGEST_SIZE)!=0)
	{
		islocal=0;
	} 
	
	if(islocal==1)
	{
		printf("check local keyset!\n");
		db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),"user_name",instance_info->user_name);
		if(db_record != NULL)
		{
			find_keyset=1;
			local_keyset=db_record->record;
		}
	}
	else
	{
		printf("check remote keyset!\n");
		remote_keyset=remote_keyset_get(instance_info->node_uuid,instance_info->user_name);
		if(remote_keyset==NULL)
		{
			find_keyset=1;
		}
	}
	
	if((islocal==1)&&(find_keyset==0))
	{
		userinfo=Talloc0(sizeof(*userinfo));
		if(userinfo==NULL)
			return -ENOMEM;
		Strncpy(userinfo->username,instance_info->user_name,DIGEST_SIZE);
		Strcpy(userinfo->user_role,"user");	

		new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,USERINFO),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		ret=message_add_record(new_msg,userinfo);
		if(ret<0)
			return ret;
		ret=ex_module_sendmsg(sub_proc,new_msg);
	}

	new_msg=recv_msg;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
	if(find_keyset)
	{
		if(islocal)
		{
			ret=message_add_expand_data(new_msg,TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),local_keyset);
		}	
		else
		{
			ret=message_add_expand_data(new_msg,TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET),remote_keyset);
		}
	}	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	return ret;
}

int proc_keyset_check_inexpand(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	char user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_PIK_DESC,USERINFO)  * userinfo;
	RECORD(MESSAGE,INSTANCE_INFO)  * instance_info;
        RECORD(TCM_KEY_DESC,LOCAL_KEYSET) * local_keyset;
        RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;
	RECORD(MESSAGE,MODULE_STATE) * check_state;
	void * new_msg;
	int islocal=1;
	int find_keyset=0;

	char uuid[DIGEST_SIZE*2+1];
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;
        
	printf("begin keyset check!\n");

	// get pik_userinfo from message
	
	ret=message_remove_expand(recv_msg,TYPE_PAIR(MESSAGE,INSTANCE_INFO),&instance_info);
	if(ret<0)
		return -EINVAL;
	if(instance_info==NULL)
		return -EINVAL;

	// get this node's machine uuid
        ret=proc_share_data_getvalue("uuid",local_uuid);
	if(ret<0)
		return ret;

	// get this node's user name
        ret=proc_share_data_getvalue("user_name",user_name);
	if(ret<0)
		return ret;

	// judge if it is local user
	//
	if(Memcmp(local_uuid,instance_info->node_uuid,DIGEST_SIZE)!=0)
	{
		islocal=0;
	} 
	else if(Strncmp(user_name,instance_info->user_name,DIGEST_SIZE)!=0)
	{
		islocal=0;
	} 
	
	if(islocal==1)
	{
		printf("check local keyset!\n");
		db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,LOCAL_KEYSET),"user_name",instance_info->user_name);
		if(db_record != NULL)
		{
			find_keyset=1;
			local_keyset=db_record->record;
		}
	}
	else
	{
		printf("check remote keyset!\n");
		remote_keyset=remote_keyset_get(instance_info->node_uuid,instance_info->user_name);
		if(remote_keyset!=NULL)
		{
			find_keyset=1;
		}
	}
	
	if((islocal==1)&&(find_keyset==0))
	{
		userinfo=Talloc0(sizeof(*userinfo));
		if(userinfo==NULL)
			return -ENOMEM;
		Strncpy(userinfo->username,instance_info->user_name,DIGEST_SIZE);
		Strcpy(userinfo->user_role,"user");	

		new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,USERINFO),NULL);
		if(new_msg==NULL)
			return -EINVAL;
		ret=message_add_record(new_msg,userinfo);
		if(ret<0)
			return ret;
		ret=ex_module_sendmsg(sub_proc,new_msg);
	}

	new_msg=recv_msg;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);

	check_state=Talloc0(sizeof(*check_state));
	if(check_state==NULL)
		return -EINVAL;
	if(islocal)
		Strncpy(check_state->name,"local_keyset",DIGEST_SIZE);
	else	
		Strncpy(check_state->name,"remote_keyset",DIGEST_SIZE);

	if(find_keyset)
		check_state->state=1;
	else
		check_state->state=0;

	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,MODULE_STATE),check_state);
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	return ret;
}

RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset_get (BYTE *uuid,char * name)
{
	int ret;
	RECORD(TCM_KEY_DESC,REMOTE_KEYSET ) * remote_keyset;
	DB_RECORD * db_record;
	char buf[DIGEST_SIZE];
	int i;
	remote_keyset=memdb_get_first_record(TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET));
	while(remote_keyset!=NULL)
	{
		ret=0;
		if(uuid!=NULL)
		{
			if(Memcmp(uuid,remote_keyset->node_uuid,DIGEST_SIZE)==0)
				ret=1;
			else
				ret=-1;
		}
		if(name!=NULL)
		{
			if(Strncmp(name,remote_keyset->user_name,DIGEST_SIZE)==0)
			{
				if(uuid==NULL)
					ret=1;
			}
			else
				ret=0;

		}
		if(ret==1)
			break;
		remote_keyset=memdb_get_next_record(TYPE_PAIR(TCM_KEY_DESC,REMOTE_KEYSET));
		
	}

	return remote_keyset;
}
