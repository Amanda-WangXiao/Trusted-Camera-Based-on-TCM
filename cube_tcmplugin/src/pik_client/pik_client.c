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
#include "pik_client.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";

int pik_client_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();
	if(ret!=0)
	{
		print_cubeerr("Init TCM_Lib error!\n");
		return ret;
	}

	// Read TCM's CA Pub Key
    	ret=TCM_ExLoadCAPubKey(capubkeyfile);
    	if(ret<0)
    	{
		printf("TCM_ExLoadCAPubKey failed!\n");
		return -EINVAL;	
    	}		

	// add yorself's module init func here
	return 0;
}
int pik_client_start(void * sub_proc, void * para)
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
	
		if((type==TYPE(TCM_PIK_DESC))&&(subtype==SUBTYPE(TCM_PIK_DESC,USERINFO)))
		{
			ret=proc_tcm_makeidentity(sub_proc,recv_msg);
		}
		if((type==TYPE(TCM_PIK_DESC))&&(subtype==SUBTYPE(TCM_PIK_DESC,CADATA)))
		{
			ret=proc_tcm_activateidentity(sub_proc,recv_msg);
		}
	
	}
	return 0;
}

int proc_tcm_makeidentity(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_PIK_DESC,USERINFO)  * pik_userinfo;
	RECORD(MESSAGE,SIZED_BINDATA) req_blob;
        RECORD(VTCM_IN_KEY,TCM_BIN_KEY) tcm_pik;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) tcm_pikpub;
        RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) tcm_pik_info;
	void * new_msg;
	int key_len;
	void * tcm_key_template;

    	UINT32 smkHandle;
    	UINT32 ownerHandle;
    	UINT32 keyHandle;
    	UINT32 keyAuthHandle;
	char uuid[DIGEST_SIZE*2+1];
	DB_RECORD * db_record;
        

	printf("begin pik makeidentity!\n");

	// get pik_userinfo from message
	
	ret=message_get_record(recv_msg,&pik_userinfo,0);
	if(ret<0)
		return -EINVAL;
	if(pik_userinfo==NULL)
		return -EINVAL;

	// get this node's machine uuid
        ret=proc_share_data_getvalue("uuid",pik_userinfo->node_uuid);
	if(ret<0)
		return ret;

	// get this node's hostname
	
	ret=gethostname(pik_userinfo->node_name,DIGEST_SIZE);
	if(ret!=0)
		Memset(pik_userinfo->node_name,0,DIGEST_SIZE);

	// build tcm session
    	ret=TCM_APCreate(TCM_ET_OWNER, NULL, "ooo", &ownerHandle);
    	printf("ownerHandle is : %x\n",ownerHandle);
    	if(ret<0)
    	{
		print_cubeerr("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &smkHandle);
    	printf("smkHandle is : %x\n",smkHandle);
    	if(ret<0)
    	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	

	int userinfolen;
    	BYTE * req;
    	int reqlen;	
	// get userinfo blob 

	tcm_key_template=memdb_get_template(TYPE_PAIR(TCM_PIK_DESC,USERINFO));
	if(tcm_key_template==NULL)
		return -EINVAL;
	userinfolen=struct_2_blob(pik_userinfo,Buf,tcm_key_template);
	if(userinfolen<0)
		return userinfolen;

	db_record=memdb_store(pik_userinfo,TYPE_PAIR(TCM_PIK_DESC,USERINFO),NULL);
	if(db_record==NULL)
		return -EINVAL;
	// do makeidentity   
    	ret = TCM_MakeIdentity(ownerHandle, smkHandle,
		userinfolen,Buf,"kkk",
		&tcm_pik, &req, &reqlen);
    	if(ret<0)
    	{
		print_cubeerr("TCM_MakeIdentity failed!\n");
		return -EINVAL;	
    	}

	// build an expand message record for req data
	req_blob.size=reqlen;
	req_blob.bindata=req;	

	// terminate session	
    	ret=TCM_APTerminate(ownerHandle);
    	if(ret<0)
    	{
		print_cubeerr("TCM_APTerminate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_APTerminate(smkHandle);
    	if(ret<0)
    	{
		print_cubeerr("TCM_APTerminate failed!\n");
		return -EINVAL;	
	}
	
	// generate TCM pik info ,left pubkey_uuid for fill
/*	
	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_KEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	key_len=struct_2_blob(&tcm_pik,Buf,tcm_key_template);
*/
	Memset(&tcm_pik_info,0,sizeof(tcm_pik_info));
	Memcpy(tcm_pik_info.vtcm_uuid,local_uuid,DIGEST_SIZE);
	tcm_pik_info.issmkwrapped=1;
	tcm_pik_info.key_usage=TCM_KEY_IDENTITY;
	tcm_pik_info.key_flags=TCM_ISVOLATILE|TCM_PCRIGNOREDONREAD;

	// BYTE Buf[DIGEST_SIZE*16];
	// BYTE NameBuf[DIGEST_SIZE*4];
	// char uuid[DIGEST_SIZE*2+1]; 
	key_len=memdb_output_blob(&tcm_pik,Buf,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_KEY));
	if(key_len<0)
		return key_len;
	calculate_context_sm3(Buf,key_len,tcm_pik_info.uuid);

	// store pik file
	digest_to_uuid(tcm_pik_info.uuid,uuid); // digest turn to 64 char string
	uuid[DIGEST_SIZE*2]=0;
	printf("get pik's uuid is %s!\n",uuid);	

	Strcpy(NameBuf,"tcmkey/");
	Strcat(NameBuf,uuid);

        fd=open(NameBuf,O_CREAT|O_WRONLY,0666);
        if(fd<0)
                return fd;
        write(fd,Buf,key_len);
        close(fd);

	// Get pikpub from pik 
	//
	ret=TCM_ExGetPubkeyFromTcmkey(&tcm_pikpub,&tcm_pik);
	if(ret!=0)
	{
		print_cubeerr("Get Pubpik failed!\n");
		return -EINVAL;
	}

	
	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	key_len=struct_2_blob(&tcm_pikpub,Buf,tcm_key_template);
	if(key_len<0)
		return key_len;
	calculate_context_sm3(Buf,key_len,tcm_pik_info.pubkey_uuid);
	db_record=memdb_store(&tcm_pik_info,TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),NULL);

	// build a message and send it 
	new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,USERINFO),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,pik_userinfo);
	if(ret<0)
		return ret;
	
	ret=message_add_expand_data(new_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),&req_blob);
	if(ret<0)
		return -EINVAL;
	ret=message_add_expand_data(new_msg,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY),&tcm_pikpub);
	if(ret<0)
		return -EINVAL;

	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

int proc_tcm_activateidentity(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE Buf[DIGEST_SIZE*32];
	BYTE NameBuf[DIGEST_SIZE*4];
	BYTE KeyBuf[DIGEST_SIZE*4];
	BYTE digest[DIGEST_SIZE];
	UINT32 result;
	DB_RECORD * db_record;
	RECORD(TCM_PIK_DESC,USERINFO)  * pik_userinfo;
	RECORD(TCM_PIK_DESC,CADATA)  * pik_cadata;
	RECORD(TCM_PIK_DESC,PIKCERT)  * pik_cert;
        RECORD(VTCM_IN_KEY,TCM_BIN_KEY) tcm_pik;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) tcm_pikpub;
        RECORD(TCM_KEY_MANAGE,PRIVATE_KEY) * tcm_pik_info;
    	TCM_SYMMETRIC_KEY symmkey;
	void * new_msg;
	int key_len;
	void * tcm_key_template;

    	UINT32 smkHandle;
    	UINT32 ownerHandle;
    	UINT32 keyHandle;
    	UINT32 keyAuthHandle;
	char uuid[DIGEST_SIZE*2+1];
        

	printf("begin pik activateidentity!\n");

	// get pik cadata from message
	
	ret=message_get_record(recv_msg,&pik_cadata,0);
	if(ret<0)
		return -EINVAL;
	if(pik_cadata==NULL)
		return -EINVAL;
	
	// find pikinfo record
	
	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_MANAGE,PRIVATE_KEY),"pubkey_uuid",pik_cadata->pikpub_uuid);
	if(db_record==NULL)
	{
		print_cubeerr("can't find pik record!\n");
		return -EINVAL;
	}
	tcm_pik_info=db_record->record;	
	
	// get pik file name
	digest_to_uuid(tcm_pik_info->uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	printf("get pik's uuid is %s!\n",uuid);	
	Strcpy(NameBuf,"tcmkey/");
	Strcat(NameBuf,uuid);
	ret=TCM_ExLoadTcmKey(&tcm_pik,NameBuf);
	if(ret!=0)
	{
		print_cubeerr("Load TCMKey from file failed!\n");
		return ret;
	}
	// Load pik to TCM 
    	ret=TCM_APCreate(TCM_ET_SMK, NULL, "sss", &smkHandle);
    	printf("smkHandle is : %x\n",smkHandle);
    	if(ret<0)
    	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	
    	ret=TCM_LoadKey(0x40000000,smkHandle,&tcm_pik,&keyHandle);
    	if(ret!=0)
    	{
		print_cubeerr("TCM_LoadKey failed!\n");
		return ret;	
    	}	
    	ret=TCM_APTerminate(smkHandle);
    	if(ret!=0)
    	{
		printf("TCM_APTerminate failed!\n");
		return ret;	
	}

	// do the activateidentity 
    	ret=TCM_APCreate(TCM_ET_OWNER, NULL, "ooo", &ownerHandle);
    	printf("ownerHandle is : %x\n",ownerHandle);
    	if(ret<0)
    	{
		print_cubeerr("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_APCreate(TCM_ET_KEYHANDLE,keyHandle, "kkk", &keyAuthHandle);
    	printf("pikHandle is : %x\n",keyAuthHandle);
    	if(ret!=0)
    	{
		printf("TCM_APCreate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_ActivateIdentity(keyHandle,keyAuthHandle,ownerHandle,
		pik_cadata->symmkey_len,pik_cadata->symmkey,&symmkey,"ooo","kkk");	
    	if(ret!=0)
    	{
		printf("TCM_ActivateIdentity failed!\n");
		return -EINVAL;	
    	}	
    	ret=TCM_APTerminate(ownerHandle);
    	if(ret<0)
    	{
		printf("TCM_APTerminate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_APTerminate(keyAuthHandle);
    	if(ret<0)
    	{
		printf("TCM_APTerminate failed!\n");
		return -EINVAL;	
    	}	

    	ret=TCM_EvictKey(keyHandle);
   	if(ret<0)
    	{
		printf("TCM_APTerminate failed!\n");
		return -EINVAL;	
    	}	

    	// decrypt cert blob
    	int blobsize;
    	BYTE * cert;
    	int certsize;

    	ret=TCM_ExSymmkeyDecrypt(&symmkey,pik_cadata->cert,pik_cadata->certlen,&cert,&certsize);
    	if(ret!=0)
    	{
		printf("decrypt cert blob file error!\n");
		return -EINVAL;	
    	}

	int offset;
	for(offset=0;cert[offset]==0;offset++)
	{
		if((offset>=16)|| (offset>=certsize))
		{
			print_cubeerr("cert data failed!\n");
			return -EINVAL;
		}
	}

	// build pik cert, it is organized by userinfo, pubkey and  ca_conts
	//
	pik_cert=Talloc0(sizeof(*pik_cert));
	if(pik_cert==NULL)
		return -ENOMEM;
	
	tcm_key_template=memdb_get_template(TYPE_PAIR(TCM_PIK_DESC,VERIFYDATA));
	if(tcm_key_template==NULL)
		return -EINVAL;
	ret=blob_2_struct(cert+offset,&pik_cert->verifydata,tcm_key_template);
	if(ret<0)
		return -EINVAL;
	
	db_record=memdb_find(pik_cadata->userinfo_uuid,TYPE_PAIR(TCM_PIK_DESC,USERINFO));
	if(db_record==NULL)
	{
		print_cubeerr("can't find user info data!\n");
		return -EINVAL;
	}
	
	pik_userinfo=db_record->record;

	tcm_key_template=memdb_get_template(TYPE_PAIR(TCM_PIK_DESC,USERINFO));
	if(tcm_key_template==NULL)
		return -EINVAL;
	ret=struct_clone(pik_userinfo,&pik_cert->userinfo,tcm_key_template);
	if(ret<0)
		return -EINVAL;

	ret=TCM_ExGetPubkeyFromTcmkey(&tcm_pikpub,&tcm_pik);
	if(ret!=0)
	{
		print_cubeerr("Get Pubpik failed!\n");
		return -EINVAL;
	}
	tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
	if(tcm_key_template==NULL)
		return -EINVAL;
	ret=struct_clone(&tcm_pikpub,&pik_cert->pikpub,tcm_key_template);
	if(ret<0)
		return -EINVAL;

	// build a message and send it 
	new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,PIKCERT),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,pik_cert);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}
