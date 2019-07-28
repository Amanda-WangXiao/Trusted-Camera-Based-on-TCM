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
#include "tcm_key_manage.h"
#include "tcmfunc.h"
#include "tcm_cube_struct.h"
#include "create_key.h"
// add para lib_include
int _create_tcmkey( RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key,
	RECORD(TCM_KEY_MANAGE,PUBLIC_KEY) * public_key);

int create_key_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();

	// add yorself's module init func here
	return 0;
}
int create_key_start(void * sub_proc, void * para)
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
		if((type==TYPE(TCM_KEY_MANAGE))&&(subtype==SUBTYPE(TCM_KEY_MANAGE,PRIVATE_KEY)))
		{
			ret=proc_create_tcmkey(sub_proc,recv_msg);
		}
		else
		{
			ret=proc_create_tcmkey_inexpand(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_create_tcmkey(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	UINT32 result;
	RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key;
	RECORD(TCM_KEY_MANAGE,PUBLIC_KEY) * public_key;
	void * new_msg;

	// get private key input
	ret=message_get_record(recv_msg,&private_key,0);
	if(ret<0)
		return ret;


	printf("begin tcm key create!\n");

	// set private_key's vtcm_uuid value
        ret=proc_share_data_getvalue("uuid",private_key->vtcm_uuid);
	if(ret<0)
		return ret;

	public_key=Talloc0(sizeof(*public_key));
	if(public_key==NULL)
		return -ENOMEM;
	
	ret=_create_tcmkey(private_key,public_key);
	if(ret!=0)
		return -EINVAL;

	DB_RECORD * db_record;
	db_record=memdb_store(private_key,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),NULL);
	if(db_record==NULL)
		return -EINVAL;

	db_record=memdb_store(public_key,TYPE_PAIR(TCM_KEY_MANAGE,PUBLIC_KEY),NULL);
	if(db_record==NULL)
		return -EINVAL;

	new_msg=message_create(TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),recv_msg);	
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,private_key);
	if(ret<0)
		return ret;
	ret=ex_module_sendmsg(sub_proc,new_msg);

	RECORD(MESSAGE,TYPES) types_pair;
	new_msg=message_create(TYPE_PAIR(MESSAGE,TYPES),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	types_pair.type=TYPE(TCM_KEY_MANAGE);
	types_pair.subtype=SUBTYPE(TCM_KEY_MANAGE,PRIVATE_KEY);

	ret=message_add_record(new_msg,&types_pair);
	if(ret<0)
		return ret;
	types_pair.type=TYPE(TCM_KEY_MANAGE);
	types_pair.subtype=SUBTYPE(TCM_KEY_MANAGE,PUBLIC_KEY);

	ret=message_add_record(new_msg,&types_pair);
	if(ret<0)
		return ret;
	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

int proc_create_tcmkey_inexpand(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	UINT32 result;
	RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key;
	RECORD(TCM_KEY_MANAGE,PUBLIC_KEY) * public_key;
	void * new_msg;
	MSG_EXPAND * msg_expand;

	// get private key input
	ret=message_remove_expand(recv_msg,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),&msg_expand);
	if(ret<0)
		return ret;
	private_key=msg_expand->expand;

	printf("begin tcm key create!\n");

	// set private_key's vtcm_uuid value
        ret=proc_share_data_getvalue("uuid",private_key->vtcm_uuid);
	if(ret<0)
		return ret;

	public_key=Talloc0(sizeof(*public_key));
	if(public_key==NULL)
		return -ENOMEM;
	
	ret=_create_tcmkey(private_key,public_key);
	if(ret!=0)
		return -EINVAL;

	DB_RECORD * db_record;
	db_record=memdb_store(private_key,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),NULL);
	if(db_record==NULL)
		return -EINVAL;

	db_record=memdb_store(public_key,TYPE_PAIR(TCM_KEY_MANAGE,PUBLIC_KEY),NULL);
	if(db_record==NULL)
		return -EINVAL;

	new_msg=recv_msg;

	if(new_msg==NULL)
		return -EINVAL;
	message_set_flag(new_msg,message_get_flag(new_msg) | MSG_FLAG_FOLLOW);
	ret=message_add_expand_data(new_msg,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),private_key);
	if(ret<0)
		return ret;
	ret=ex_module_sendmsg(sub_proc,new_msg);

	RECORD(MESSAGE,TYPES) types_pair;
	new_msg=message_create(TYPE_PAIR(MESSAGE,TYPES),NULL);	
	if(new_msg==NULL)
		return -EINVAL;
	types_pair.type=TYPE(TCM_KEY_MANAGE);
	types_pair.subtype=SUBTYPE(TCM_KEY_MANAGE,PRIVATE_KEY);

	ret=message_add_record(new_msg,&types_pair);
	if(ret<0)
		return ret;
	types_pair.type=TYPE(TCM_KEY_MANAGE);
	types_pair.subtype=SUBTYPE(TCM_KEY_MANAGE,PUBLIC_KEY);

	ret=message_add_record(new_msg,&types_pair);
	if(ret<0)
		return ret;
	ret=ex_module_sendmsg(sub_proc,new_msg);

	return ret;
}

int _create_tcmkey( RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * private_key,
	RECORD(TCM_KEY_MANAGE,PUBLIC_KEY) * public_key)
{
	int ret;
	UINT32 result;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	

	BYTE Buf[DIGEST_SIZE*16];
	BYTE NameBuf[DIGEST_SIZE*4];
	TCM_AUTHHANDLE authhandle; 
        RECORD(VTCM_IN_KEY, TCM_BIN_KEY) *tcm_privkey;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) *tcm_pubkey;
	int key_len;
	char uuid[DIGEST_SIZE*2+1];
	
	tcm_privkey=Talloc0(sizeof(*tcm_privkey));
	if(tcm_privkey==NULL)
		return -ENOMEM;
	tcm_pubkey=Talloc0(sizeof(*tcm_pubkey));
	if(tcm_pubkey==NULL)
		return -ENOMEM;
	// build smk 's authsession 
	result=TCM_APCreate(TCM_ET_SMK,0,"sss",&authhandle);
	if(result!=0)
	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;
	}
	if(private_key->issmkwrapped)
		// create key and return TCM_KEY struct
		result=TCM_CreateWrapKey(tcm_privkey,0x40000000,authhandle,private_key->key_usage,private_key->key_flags,"sss");
	else
		return -EINVAL;
	if(result!=0)
	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;
	}

	printf("Create key succeed!\n");	
        usleep(50*1000);
	
	// Output TCM_KEY Data to file and compute its uuid

	void * tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_KEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	key_len=struct_2_blob(tcm_privkey,Buf,tcm_key_template);
	if(key_len<0)
		return key_len;
	vtcm_ex_sm3(private_key->uuid,1,Buf,key_len);
	digest_to_uuid(private_key->uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	printf("create key's uuid is %s!\n",uuid);	

	Strcpy(NameBuf,"tcmkey/");
	Strcat(NameBuf,uuid);

        fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        if(fd<0)
                return fd;
        write(fd,Buf,key_len);
        close(fd);

	// Output TCM_PUBKEY Data to file and compute its uuid
	
	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_KEY_PARMS));
	ret=struct_clone(&tcm_privkey->algorithmParms,&tcm_pubkey->algorithmParms,tcm_key_template);
	if(ret<0)
		return -EINVAL;

	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY));
	ret=struct_clone(&tcm_privkey->pubKey,&tcm_pubkey->pubKey,tcm_key_template);
	if(ret<0)
		return -EINVAL;
	
	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	key_len=struct_2_blob(tcm_pubkey,Buf,tcm_key_template);
	if(key_len<0)
		return key_len;
	vtcm_ex_sm3(private_key->pubkey_uuid,1,Buf,key_len);
	digest_to_uuid(private_key->pubkey_uuid,uuid);
	printf("create pubkey's uuid is %s!\n",uuid);	

	Strcpy(NameBuf,"pubkey/");
	Strcat(NameBuf,uuid);

        fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        if(fd<0)
                return fd;
        write(fd,Buf,key_len);
        close(fd);


	// Build public_key struct and store it

	Memcpy(public_key->uuid,private_key->pubkey_uuid,DIGEST_SIZE);
	Memcpy(public_key->vtcm_uuid,private_key->vtcm_uuid,DIGEST_SIZE);
	public_key->ispubek=0;
	public_key->key_usage=private_key->key_usage;
	public_key->key_flags=private_key->key_flags;
	Memcpy(public_key->prikey_uuid,private_key->uuid,DIGEST_SIZE);

	// Output TCM_PUBKEY Data to file and compute its uuid

	result=TCM_APTerminate(authhandle);
	if(result!=0)
	{
		printf("TCM_APTerminate failed!\n");
		return -EINVAL;
	}
	return 0;
}
