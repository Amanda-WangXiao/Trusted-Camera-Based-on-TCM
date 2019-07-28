#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
 
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
#include "key_manage.h"
#include "login_struct.h"
// add para lib_include
int key_manage_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	return 0;
}
int key_manage_start(void * sub_proc, void * para)
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
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,REGISTER)))
		{
			ret=proc_keymanage_register(sub_proc,recv_msg);
		}
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,LOGIN)))
		{
			ret=proc_keymanage_login(sub_proc,recv_msg);
		}
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,RETURN)))
		{
			ret=proc_keymanage_return(sub_proc,recv_msg);
		}
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,SENDKEY)))
		{
			ret=proc_keymanage_sendkey(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_keymanage_register(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,REGISTER) * login_info;
	void * new_msg;
	
	ret=message_get_record(recv_msg,&login_info,0);
	if(ret<0)
		return ret;

	new_msg=message_clone(recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_keymanage_login(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,LOGIN) * login_info;
	RECORD(LOGIN_TEST,STATE) * client_state;
	void * new_msg;
	
	ret=message_get_record(recv_msg,&login_info,0);
	if(ret<0)
		return ret;

	DB_RECORD * db_record;

	db_record=memdb_find_first(TYPE_PAIR(LOGIN_TEST,STATE),"user_name",login_info->user_name);
	if(db_record==NULL)
	{
		client_state=Talloc0(sizeof(*client_state));
		client_state->user_name=dup_str(login_info->user_name,DIGEST_SIZE);
		proc_share_data_setvalue("user_name",login_info->user_name);
		db_record=memdb_store(client_state,TYPE_PAIR(LOGIN_TEST,STATE),login_info->user_name);
	}
	else
	{
		proc_share_data_setvalue("user_name",login_info->user_name);
	}
	
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,LOGIN),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,login_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_keymanage_return(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,RETURN) * login_return;
	RECORD(LOGIN_TEST,STATE) * client_state;
	RECORD(MESSAGE,INSTANCE_INFO) * instance_info;
	char user_name[DIGEST_SIZE];
	void * new_msg;
	
	BYTE local_uuid[DIGEST_SIZE];	
	char proc_name[DIGEST_SIZE];	

	ret=message_get_record(recv_msg,&login_return,0);
	if(ret<0)
		return ret;

	instance_info=Talloc0(sizeof(*instance_info));
	if(instance_info==NULL)
		return -ENOMEM;
	
	proc_share_data_getvalue("proc_name",instance_info->proc_name);
	proc_share_data_getvalue("user_name",instance_info->user_name);
	proc_share_data_getvalue("uuid",instance_info->node_uuid);

	DB_RECORD * db_record;

	db_record=memdb_find_byname(instance_info->user_name,TYPE_PAIR(LOGIN_TEST,STATE));
	if(db_record==NULL)
	{
		print_cubeerr("no such user!\n");
		return -EINVAL;
	}
	if(login_return->return_code ==1)
	{
   		printf("%s\n",login_return->return_info);
		client_state=db_record->record;
		client_state->curr_state=1;
	}
	else 
	{
   		printf("%s\n",login_return->return_info);
		client_state=db_record->record;
		client_state->curr_state=2;
	}
	
	memdb_store(client_state,TYPE_PAIR(LOGIN_TEST,STATE),client_state->user_name);
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,RETURN),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,login_return);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);

	new_msg=message_create(TYPE_PAIR(MESSAGE,INSTANCE_INFO),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,instance_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}
int proc_keymanage_sendkey(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,SENDKEY) * login_sendkey;
	RECORD(MESSAGE,INSTANCE_INFO) * instance_info;
	char user_name[DIGEST_SIZE];
	void * new_msg;
	
	BYTE local_uuid[DIGEST_SIZE];	
	char proc_name[DIGEST_SIZE];	

	ret=message_get_record(recv_msg,&login_sendkey,0);
	if(ret<0)
		return ret;

	instance_info=Talloc0(sizeof(*instance_info));
	if(instance_info==NULL)
		return -ENOMEM;
	
	proc_share_data_getvalue("proc_name",instance_info->proc_name);
	proc_share_data_getvalue("user_name",instance_info->user_name);
	proc_share_data_getvalue("uuid",instance_info->node_uuid);

	new_msg=message_create(TYPE_PAIR(MESSAGE,INSTANCE_INFO),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,instance_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}
