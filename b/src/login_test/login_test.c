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
#include "login_test.h"
#include "login_struct.h"
// add para lib_include
int login_test_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	return 0;
}
int login_test_start(void * sub_proc, void * para)
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
			ret=proc_login_register(sub_proc,recv_msg);
		}
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,LOGIN)))
		{
			ret=proc_login_login(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_login_register(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,REGISTER) * register_info;
	RECORD(LOGIN_TEST,RETURN) * return_info;
	void * new_msg;
	
	ret=message_get_record(recv_msg,&register_info,0);
	if(ret<0)
		return ret;
	DB_RECORD * db_record;

	db_record=memdb_store(register_info,TYPE_PAIR(LOGIN_TEST,REGISTER),NULL);
	if(db_record==NULL)
		return -EINVAL;

	return_info=Talloc0(sizeof(*return_info));
	if(return_info==NULL)
		return -ENOMEM;

	return_info->return_code=1;
	return_info->return_info=dup_str("register succeed!",0);
	
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,RETURN),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,return_info);
	if(ret<0)
		return ret;

	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,RETURN),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,return_info);
	if(ret<0)
		return ret;
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	// output message store type
	new_msg=message_gen_typesmsg(TYPE_PAIR(LOGIN_TEST,REGISTER),NULL);
	if(new_msg==NULL)
		return -EINVAL;
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	return ret;
}

int proc_login_login(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,REGISTER) * register_info;
	RECORD(LOGIN_TEST,LOGIN) * login_info;
	RECORD(LOGIN_TEST,RETURN) * return_info;
	void * new_msg;
	
	ret=message_get_record(recv_msg,&login_info,0);
	if(ret<0)
		return ret;

	return_info=Talloc0(sizeof(*return_info));
	if(return_info==NULL)
		return -ENOMEM;

	DB_RECORD * db_record;

	db_record=memdb_find_first(TYPE_PAIR(LOGIN_TEST,REGISTER),"user_name",login_info->user_name);
	if(db_record==NULL)
	{
		return_info->return_code=2;
		return_info->return_info=dup_str("no such user!\n",0);
	}
	else
	{
		register_info=db_record->record;

		if(Memcmp(login_info->passwd,register_info->passwd,DIGEST_SIZE)==0)
		{	
	
			return_info->return_code=1;
			return_info->return_info=dup_str("login succeed!\n",0);
		}
		else {	
			return_info->return_code=3;
			return_info->return_info=dup_str("password error!\n",0);
		}
	}
	
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,RETURN),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,return_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}
