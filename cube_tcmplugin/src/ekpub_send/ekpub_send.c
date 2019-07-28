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
#include "ekpub_send.h"
// add para lib_include
int ekpub_send_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();

	// add yorself's module init func here
	return 0;
}
int ekpub_send_start(void * sub_proc, void * para)
{
	int ret;
	void * recv_msg;
	int type;
	int subtype;
	// add yorself's module exec func here
	sleep(1);
	proc_get_ekpub(sub_proc,NULL);

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
	/*
		if((type==TYPE(TCM_KEY_MANAGE))&&(subtype==SUBTYPE(TCM_KEY_MANAGE,PRIVATE_KEY)))
		{
			ret=proc_create_tcmkey(sub_proc,recv_msg);
		}
	*/
	}
	return 0;
}

int proc_get_ekpub(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*16];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_KEY_DESC,EK_DESC)  ek_desc;
	RECORD(MESSAGE,SIZED_BINDATA) ek_blob;
	void * new_msg;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) tcm_ekpub;
	int key_len;
	void * tcm_key_template;

	char uuid[DIGEST_SIZE*2+1];
        

	printf("begin ekey  pub create!\n");

	// get this node's machine uuid
        ret=proc_share_data_getvalue("uuid",ek_desc.node_uuid);
	if(ret<0)
		return ret;

	// get this node's hostname
	
	ret=gethostname(ek_desc.node_name,DIGEST_SIZE);
	if(ret!=0)
		Memset(ek_desc.node_name,0,DIGEST_SIZE);


	// read ek pub from tcm 
	result=TCM_ReadPubek(&tcm_ekpub);
	if(result!=0)
	{
		printf("TCM_ReadPubek failed!\n");
		return -EINVAL;
	}

	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	key_len=struct_2_blob(&tcm_ekpub,Buf,tcm_key_template);
	if(key_len<0)
		return key_len;
	calculate_context_sm3(Buf,key_len,ek_desc.uuid);
	digest_to_uuid(ek_desc.uuid,NameBuf);
	printf("get ekpub's uuid is %s!\n",NameBuf);	

	// Output ekpub's desc and Data

	new_msg=message_create(TYPE_PAIR(TCM_KEY_DESC,EK_DESC),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,&ek_desc);
	if(ret<0)
		return ret;
	
	ek_blob.size=key_len;
	ek_blob.bindata=Talloc0(key_len);
	if(ek_blob.bindata==NULL)
		return -ENOMEM;
	Memcpy(ek_blob.bindata,Buf,ek_blob.size);

	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),&ek_blob);
	if(ret<0)
		return -EINVAL;

	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

