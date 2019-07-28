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
#include "ekpub_store.h"
// add para lib_include
int ekpub_store_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
//	ret=TCM_LibInit();
	// add yorself's module init func here
	return 0;
}
int ekpub_store_start(void * sub_proc, void * para)
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
	
		if((type==TYPE(TCM_KEY_DESC))&&(subtype==SUBTYPE(TCM_KEY_DESC,EK_DESC)))
		{
			ret=proc_ekpub_store(sub_proc,recv_msg);
		}
	
	}
	return 0;
}

int proc_ekpub_store(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*16];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_KEY_DESC,EK_DESC)  * ek_desc;
	RECORD(MESSAGE,SIZED_BINDATA) * ek_blob;
	void * new_msg;
	int key_len;
	char uuid[DIGEST_SIZE*2+1];

	printf("begin ekey  pub store!\n");


	// read ek pub from tcm 
	ret=message_get_record(recv_msg,&ek_desc,0);
	if(ret<0)
		return ret;

	DB_RECORD * record;
	MSG_EXPAND *expand;

	message_remove_expand(recv_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),&expand);
	record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,EK_DESC),"uuid",ek_desc->uuid);
	if(record!=NULL)
	{
		printf("ek already stored!\n");
		ex_module_sendmsg(sub_proc,recv_msg);
		return 0;
	}
			
	memdb_store(ek_desc,TYPE_PAIR(TCM_KEY_DESC,EK_DESC),NULL);
	
	ek_blob=expand->expand;
	
	digest_to_uuid(ek_desc->uuid,uuid);
	printf("get ekpub's uuid is %s!\n",uuid);	

	// Output ekpub's keyfile and write it
	Strcpy(NameBuf,"ekpub/");
	Strcat(NameBuf,uuid);

        fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        if(fd<0)
                return fd;
        write(fd,ek_blob->bindata,ek_blob->size);
        close(fd);

	ret=ex_module_sendmsg(sub_proc,recv_msg);

	return ret;
}

