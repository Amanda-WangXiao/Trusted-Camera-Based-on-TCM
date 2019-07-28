#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "data_type.h"
#include "alloc.h"
#include "memfunc.h"
#include "basefunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"
#include "file_struct.h"
#include "transfer.h"
#include "login_struct.h"


int proc_dispatch(void * sub_proc,void * message);

int transfer_init(void * sub_proc,void * para)
{
	int ret;
	// add youself's plugin init func here
	return 0;
}

int transfer_start(void * sub_proc,void * para)
{
	int ret;
	void * recv_msg;
	int i;
	int type;
	int subtype;


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
			ret=proc_transfer_transrecord(sub_proc,recv_msg);
			continue;
		}
		if((type==TYPE(MESSAGE))&&(subtype==SUBTYPE(MESSAGE,CONN_ACKI)))
		{
			ret=proc_transfer_getnodeinfo(sub_proc,recv_msg);
		}
		else if((type==TYPE(LOGIN_TEST))&&(subtype==SUBTYPE(LOGIN_TEST,LOGIN)))
		{
			ret=proc_transfer_getuserinfo(sub_proc,recv_msg);
		}
		else if((type==TYPE(FILE_TRANS))&&(subtype==SUBTYPE(FILE_TRANS,FILE_DATA)))
		{
			ret=proc_transfer_transfile(sub_proc,recv_msg);
		}
	}

	return 0;
};

int proc_transfer_getnodeinfo(void * sub_proc,void * recv_msg)
{
	int ret;

	RECORD(MESSAGE,CONN_ACKI) * client_acki;
	RECORD(LOGIN_TEST,SERVER_STATE) * server_state;
	BYTE proc_uuid[DIGEST_SIZE];
	
	DB_RECORD * db_record;

	ret=message_get_record(recv_msg,&client_acki,0);
	if(ret<0)
		return ret;
	if(client_acki==NULL)
		return -EINVAL;	
	comp_proc_uuid(client_acki->uuid,client_acki->client_process,proc_uuid);

	db_record=memdb_find(proc_uuid,TYPE_PAIR(LOGIN_TEST,SERVER_STATE));
	if(db_record==NULL)
	{
		server_state=Talloc0(sizeof(*server_state));
		server_state->user_name=NULL;
		Strncpy(server_state->proc_name,client_acki->client_process,DIGEST_SIZE);
		Memcpy(server_state->node_uuid,client_acki->uuid,DIGEST_SIZE);
		Memcpy(server_state->addr,proc_uuid,DIGEST_SIZE);
		server_state->curr_state=LOGIN_STATE_WAIT;	
		db_record=memdb_store(server_state,TYPE_PAIR(LOGIN_TEST,SERVER_STATE),NULL);
		if(db_record==NULL)
			return -EINVAL;
	
	}
	else
	{
		server_state=db_record->record;
		server_state->user_name=NULL;
		server_state->curr_state=LOGIN_STATE_WAIT;
		db_record=memdb_store(server_state,TYPE_PAIR(LOGIN_TEST,SERVER_STATE),NULL);
		if(db_record==NULL)
			return -EINVAL;
	}
	return 0;
}

int proc_transfer_getuserinfo(void * sub_proc,void * recv_msg)
{
	int ret;

	RECORD(LOGIN_TEST,LOGIN) * login_info;
	RECORD(LOGIN_TEST,SERVER_STATE) * server_state;
	BYTE proc_uuid[DIGEST_SIZE];
	
	DB_RECORD * db_record;

	ret=message_get_record(recv_msg,&login_info,0);
	if(ret<0)
		return ret;
	if(login_info==NULL)
		return -EINVAL;	
	
	comp_proc_uuid(login_info->machine_uuid,login_info->proc_name,proc_uuid);
	db_record=memdb_find(proc_uuid,TYPE_PAIR(LOGIN_TEST,SERVER_STATE));
	if(db_record==NULL)
		return -EINVAL;

	server_state=db_record->record;

	server_state->user_name=dup_str(login_info->user_name,0);
	server_state->curr_state=LOGIN_STATE_LOGIN;	

	db_record=memdb_store(server_state,TYPE_PAIR(LOGIN_TEST,SERVER_STATE),NULL);
	if(db_record==NULL)
		return -EINVAL;
	return 0;
}

int proc_transfer_transfile(void * sub_proc,void * recv_msg)
{
	int ret;

	RECORD(MESSAGE,BASE_MSG) * user_info;
	RECORD(LOGIN_TEST,SERVER_STATE) * server_state;
	BYTE proc_uuid[DIGEST_SIZE];
	
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;
	void * new_msg;

        ret=message_get_define_expand(recv_msg,&msg_expand,TYPE_PAIR(MESSAGE,BASE_MSG));
        if(ret<0)
                return ret;
        if(msg_expand==NULL)
                return -EINVAL;

        user_info=msg_expand->expand;

	db_record=memdb_find_first(TYPE_PAIR(LOGIN_TEST,SERVER_STATE),"user_name",user_info->message);
        if(db_record==NULL)
        {
                printf("user %s has not logined yet!\n",user_info->message);
                return -EINVAL;
        }

	server_state=db_record->record;
	comp_proc_uuid(server_state->node_uuid,server_state->proc_name,proc_uuid);

        new_msg=message_clone(recv_msg);
        if(new_msg==NULL)
                return -EINVAL;
        ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,UUID_RECORD),proc_uuid);
        if(ret<0)
                return ret;
        ex_module_sendmsg(sub_proc,new_msg);
	return 0;
}
int proc_transfer_transrecord(void * sub_proc,void * recv_msg)
{
	int ret;

	RECORD(MESSAGE,BASE_MSG) * user_info;
	RECORD(LOGIN_TEST,SERVER_STATE) * server_state;
	BYTE proc_uuid[DIGEST_SIZE];
	
	DB_RECORD * db_record;
	MSG_EXPAND * msg_expand;
	void * new_msg;

        ret=message_get_define_expand(recv_msg,&msg_expand,TYPE_PAIR(MESSAGE,BASE_MSG));
        if(ret<0)
                return ret;
        if(msg_expand==NULL)
                return -EINVAL;

        user_info=msg_expand->expand;

	db_record=memdb_find_first(TYPE_PAIR(LOGIN_TEST,SERVER_STATE),"user_name",user_info->message);
        if(db_record==NULL)
        {
                printf("user %s has not logined yet!\n",user_info->message);
                return -EINVAL;
        }

	server_state=db_record->record;
	comp_proc_uuid(server_state->node_uuid,server_state->proc_name,proc_uuid);

        new_msg=message_clone(recv_msg);
        if(new_msg==NULL)
                return -EINVAL;
        ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,UUID_RECORD),proc_uuid);
        if(ret<0)
                return ret;
        ex_module_sendmsg(sub_proc,new_msg);
	return 0;
}
