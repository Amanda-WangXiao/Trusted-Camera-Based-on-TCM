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
#include "file_struct.h"
#include "tcm_constants.h"
#include "tcm_structures.h"
#include "tcmfunc.h"
#include "tcm_cube_struct.h"
#include "tcm_key_manage.h"
#include "tcm_key_desc.h"
#include "tcm_pik_desc.h"
#include "remotekey_send.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";
char * cert_dir="cert/";
char * tcmkey_dir="tcmkey/";
char * pubkey_dir="pubkey/";

RECORD(FILE_TRANS,REQUEST) * get_uuidfile_request (char * dir,BYTE * uuid);

int remotekey_send_init(void * sub_proc, void * para)
{
	int ret;

	// add yorself's module init func here
	return 0;
}
int remotekey_send_start(void * sub_proc, void * para)
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
	
		if((type==TYPE(TCM_KEY_DESC))&&(subtype==SUBTYPE(TCM_KEY_DESC,REMOTE_KEYSET)))
		{
			ret=proc_tcm_remotekey_send(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_remotekey_send(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	BYTE user_name[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	RECORD(TCM_KEY_DESC,REMOTE_KEYSET) * remote_keyset;
	RECORD(FILE_TRANS,REQUEST) * file_req;		
	RECORD(MESSAGE,BASE_MSG) * receiver;		
	MSG_EXPAND * msg_expand;
	void * new_msg;

	printf("begin remotekey send !\n");


	// get remote_keyset from message
	
	ret=message_get_record(recv_msg,&remote_keyset,0);
	if(ret<0)
		return -EINVAL;
	if(remote_keyset==NULL)
		return -EINVAL;
	// send remote_keyset
	new_msg=recv_msg;
	if(new_msg==NULL)
		return -EINVAL;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
	ret=ex_module_sendmsg(sub_proc,new_msg);
	if(ret<0)
		return ret;


	// prepare pikpub, pikcert, verifykey and bindkey send

	new_msg=message_create(TYPE_PAIR(FILE_TRANS,REQUEST),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	file_req=get_uuidfile_request("cert/",remote_keyset->pikcert_uuid);

	if(file_req!=NULL)
		message_add_record(new_msg,file_req);

	file_req=get_uuidfile_request("pubkey/",remote_keyset->verifykey_uuid);

	if(file_req!=NULL)
		message_add_record(new_msg,file_req);

	file_req=get_uuidfile_request("pubkey/",remote_keyset->bindkey_uuid);

	if(file_req!=NULL)
		message_add_record(new_msg,file_req);

	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

RECORD(FILE_TRANS,REQUEST *) get_uuidfile_request(char * dir,BYTE * uuid)
{
	int ret;
	RECORD(FILE_TRANS,REQUEST) * file_req;
	BYTE Namebuf[DIGEST_SIZE*4];
	char uuid_str[DIGEST_SIZE*2+1];
	Memset(Namebuf,0,DIGEST_SIZE);
	
	if(Memcmp(Namebuf,uuid,DIGEST_SIZE)==0)
		return NULL;

	if(Strnlen(dir,DIGEST_SIZE*2)>=DIGEST_SIZE*2)
	{
		print_cubeerr("file dir %sToo long!\n",dir);
		return -EINVAL;
	}
	Strncpy(Namebuf,dir,DIGEST_SIZE*2);	
	digest_to_uuid(uuid,uuid_str);
	uuid_str[DIGEST_SIZE*2]=0;
	Strcat(Namebuf,uuid_str);

	file_req=Talloc0(sizeof(*file_req));
	if(file_req==NULL)
		return -ENOMEM;
	Memcpy(file_req->uuid,uuid,DIGEST_SIZE);
	file_req->filename=dup_str(Namebuf,DIGEST_SIZE*4);
	
	return file_req;
}
