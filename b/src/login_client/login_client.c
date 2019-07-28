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
#include "file_struct.h"
#include "login_client.h"
#include "login_struct.h"

int state=0; // 0 start
             // 1 register
             // 2 login
             // 3 send key
             // 4 send file
             // 5 log out
char Buf[DIGEST_SIZE*8];

// add para lib_include
int login_client_init(void * sub_proc, void * para)
{
	int ret;
	// add yorself's module init func here
	return 0;
}
int login_client_start(void * sub_proc, void * para)
{
	int ret;
	void * recv_msg;
	int type;
	int subtype;
	// add yorself's module exec func here

	proc_client_outputmsg(sub_proc,"choose option: register,login, sendkey, sendfile or log out");

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
		if((type==TYPE(MESSAGE))&&(subtype==SUBTYPE(MESSAGE,BASE_MSG)))
		{
			ret=proc_client_sendmsg(sub_proc,recv_msg);
			proc_client_outputmsg(sub_proc,"choose option: ");
		}
		if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,RETURN)))
		{
			ret=proc_client_return(sub_proc,recv_msg);
		}
		if((type==TYPE(FILE_TRANS))&&(subtype==SUBTYPE(FILE_TRANS,FILE_NOTICE)))
		{
			ret=proc_client_filenotice(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_client_outputmsg(void * sub_proc,char * msg)
{
	int ret;
	RECORD(MESSAGE,BASE_MSG) output_msg;
	void * new_msg;

	if(msg ==NULL)
		return 0;
	output_msg.message=dup_str(msg,0);
	new_msg=message_create(TYPE_PAIR(MESSAGE,BASE_MSG),NULL);
	message_add_record(new_msg,&output_msg);
	
	ex_module_sendmsg(sub_proc,new_msg);
	return 0;
}

int proc_client_sendmsg(void * sub_proc, void * recv_msg)
{
	int ret;
	RECORD(MESSAGE,BASE_MSG) * input_msg;
	int offset;
	int totallen;
		
	ret = message_get_record(recv_msg,&input_msg,0);
	if(ret<0)
		return ret;
	totallen=Strlen(input_msg->message);	

	ret = Getfiledfromstr(Buf,input_msg->message,' ',totallen+1);
	offset=ret;

	if(Strcmp(Buf,"register")==0)
	{
		ret= proc_send_register(sub_proc,input_msg->message+offset);
	}
	else if(Strcmp(Buf,"login")==0)
	{
		ret= proc_send_login(sub_proc,input_msg->message+offset);
	}
	else if(Strcmp(Buf,"sendkey")==0)
	{
		ret= proc_send_key(sub_proc,input_msg->message+offset);
	}
	else if(Strcmp(Buf,"sendfile")==0)
	{
		ret= proc_send_file(sub_proc,input_msg->message+offset);
	}
	
	return ret;
}

int proc_send_register(void * sub_proc,char * str)
{
	int ret;
	RECORD(LOGIN_TEST,REGISTER) login_info;
	void * new_msg;
	int offset;
	Memset(&login_info,0,sizeof(login_info));

	ret = Getfiledfromstr(Buf,str,' ',DIGEST_SIZE*8);
	if(ret<=0)
		return -EINVAL;
	offset=ret;
	login_info.user_name=dup_str(Buf,0);
	ret=Getfiledfromstr(Buf,str+offset,' ',DIGEST_SIZE*8);
	offset+=ret;
	if(ret<=0)
		return -EINVAL;	
	Strncpy(login_info.passwd,Buf,DIGEST_SIZE);

	ret=Getfiledfromstr(Buf,str+offset,' ',DIGEST_SIZE*8);
	if(ret>0)
	{
		login_info.user_info =dup_str(Buf,ret);
	}
	
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,REGISTER),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,&login_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_send_login(void * sub_proc,char * str)
{
	int ret;
	RECORD(LOGIN_TEST,LOGIN) login_info;
	RECORD(LOGIN_TEST,STATE) * client_state;
	void * new_msg;
	
	int offset;
	Memset(&login_info,0,sizeof(login_info));
	proc_share_data_getvalue("uuid",login_info.machine_uuid);
	proc_share_data_getvalue("proc_name",login_info.proc_name);

	ret = Getfiledfromstr(Buf,str,' ',DIGEST_SIZE*8);
	if(ret<=0)
		return -EINVAL;
	offset=ret;
	login_info.user_name=dup_str(Buf,0);
	ret=Getfiledfromstr(Buf,str+offset,' ',DIGEST_SIZE*8);
	offset+=ret;
	if(ret<=0)
		return -EINVAL;	
	Strncpy(login_info.passwd,Buf,DIGEST_SIZE);

	DB_RECORD * db_record;

	db_record=memdb_find_first(TYPE_PAIR(LOGIN_TEST,STATE),"user_name",login_info.user_name);
	if(db_record==NULL)
	{
		client_state=Talloc0(sizeof(*client_state));
		client_state->user_name=dup_str(login_info.user_name,DIGEST_SIZE);
		proc_share_data_setvalue("user_name",login_info.user_name);
		db_record=memdb_store(client_state,TYPE_PAIR(LOGIN_TEST,STATE),login_info.user_name);
	}
	else
	{
		proc_share_data_setvalue("user_name",login_info.user_name);
	}
	
	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,LOGIN),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,&login_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_send_key(void * sub_proc,char * str)
{
	int ret;
	RECORD(LOGIN_TEST,SENDKEY) send_key;
	RECORD(MESSAGE,BASE_MSG) user_info;
	void * new_msg;
	
	int offset;
	Memset(&send_key,0,sizeof(send_key));

	ret = Getfiledfromstr(Buf,str,' ',DIGEST_SIZE*8);
	if(ret<=0)
		return -EINVAL;
	user_info.message=dup_str(Buf,0);
	Strncpy(send_key.receiver,Buf,DIGEST_SIZE);

	proc_share_data_getvalue("user_name",Buf);

	send_key.user_name=dup_str(Buf,0);

	proc_share_data_getvalue("uuid",send_key.node_uuid);

	new_msg=message_create(TYPE_PAIR(LOGIN_TEST,SENDKEY),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,&send_key);
	if(ret<0)
		return ret;
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,BASE_MSG),&user_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	return 0;
}

int proc_send_file(void * sub_proc,char * str)
{
	int ret;
	RECORD(FILE_TRANS,REQUEST) file_request;
	RECORD(MESSAGE,BASE_MSG) user_info;
	void * new_msg;
	
	int offset;
	Memset(&file_request,0,sizeof(file_request));

	ret = Getfiledfromstr(Buf,str,' ',DIGEST_SIZE*8);
	if(ret<=0)
		return -EINVAL;
	offset=ret;
	file_request.filename=dup_str(Buf,0);
	ret=Getfiledfromstr(Buf,str+offset,' ',DIGEST_SIZE*8);
	offset+=ret;
	if(ret<=0)
		return -EINVAL;	

	user_info.message=dup_str(Buf,0);

	new_msg=message_create(TYPE_PAIR(FILE_TRANS,REQUEST),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,&file_request);
	if(ret<0)
		return ret;
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,BASE_MSG),&user_info);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	
	return ret;
}

int proc_client_return(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(LOGIN_TEST,RETURN) * login_return;
	RECORD(LOGIN_TEST,STATE) * client_state;
	char user_name[DIGEST_SIZE];
	void * new_msg;
	
	ret=message_get_record(recv_msg,&login_return,0);
	if(ret<0)
		return ret;
	proc_share_data_getvalue("user_name",user_name);

	DB_RECORD * db_record;

	db_record=memdb_find_byname(user_name,TYPE_PAIR(LOGIN_TEST,STATE));
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
	return ret;
}
int proc_client_filenotice(void * sub_proc,void * recv_msg)
{
	int ret;
	RECORD(FILE_TRANS,FILE_NOTICE) * file_notice;
	char user_name[DIGEST_SIZE];
	
	ret=message_get_record(recv_msg,&file_notice,0);
	if(ret<0)
		return ret;

	if(file_notice->result==0)
	{
		printf("file %s exists!\n",file_notice->filename);
	}
	else if(file_notice->result==1)
	{
		printf("file %s get succeed!\n",file_notice->filename);
	}
	
	return ret;
}
