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
#include "pik_casign.h"
#include "tcm_error.h"
// add para lib_include
//
TCM_PUBKEY * pubek;
char * capubkeyfile="CApub.key";
char * caprikeyfile="CApri.key";

int pik_casign_init(void * sub_proc, void * para)
{
	int ret;
	// Init Tcm Func
	ret=TCM_LibInit();
	if(ret!=0)
	{
		print_cubeerr("Init TCM_Lib error!\n");
		return ret;
	}
	// Read TCM's CA Pri Key
    	ret=TCM_ExLoadCAPriKey(caprikeyfile);
    	if(ret!=0)
    	{
		printf("TCM_ExLoadCAPriKey failed!\n");
		return -EINVAL;	
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
int pik_casign_start(void * sub_proc, void * para)
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
			ret=proc_tcm_casign(sub_proc,recv_msg);
		}
	}
	return 0;
}

int proc_tcm_casign(void * sub_proc,void * recv_msg)
{
	int ret=0;
	int fd;

	BYTE local_uuid[DIGEST_SIZE];	
	
	BYTE Buf[DIGEST_SIZE*32];
	BYTE CertBuf[DIGEST_SIZE*16];
	BYTE SymmkeyBuf[DIGEST_SIZE*16];
	BYTE NameBuf[DIGEST_SIZE*4];
	UINT32 result;
	RECORD(TCM_PIK_DESC,USERINFO)  * pik_userinfo;
	RECORD(TCM_PIK_DESC,CADATA)  * pik_cadata;
	RECORD(MESSAGE,SIZED_BINDATA) * req_blob;
	RECORD(MESSAGE,SIZED_BINDATA) active_blob;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) * tcm_ekpub;
        RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) * tcm_pikpub;
	void * new_msg;
	int key_len;
	int info_len;
	void * tcm_key_template;

	char uuid[DIGEST_SIZE*2+1];
        MSG_EXPAND * expand;

	printf("begin ca sign process!\n");

	// get pik_userinfo from message
	
	ret=message_get_record(recv_msg,&pik_userinfo,0);
	if(ret<0)
		return -EINVAL;
	if(pik_userinfo==NULL)
		return -EINVAL;
	

	// get TCM_pikpub from expand data
	ret=message_remove_expand(recv_msg,TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY),&expand);
	if(ret<0)
		return ret;
	if(expand==NULL)
		return -EINVAL;
	tcm_pikpub=expand->expand;
	
	// get req_blob from expand data
	ret=message_remove_expand(recv_msg,TYPE_PAIR(MESSAGE,SIZED_BINDATA),&expand);
	if(ret<0)
		return ret;
	if(expand==NULL)
		return -EINVAL;
	req_blob=expand->expand;

	
	// find ekpub by vtcm_uuid and load it
	DB_RECORD * db_record;

	db_record=memdb_find_first(TYPE_PAIR(TCM_KEY_DESC,EK_DESC),"node_uuid",pik_userinfo->node_uuid);		
	if(db_record==NULL)
	{
		print_cubeerr("Can't find node's ek!\n");
		return -EINVAL;
	}
	RECORD(TCM_KEY_DESC,EK_DESC) * ek_desc=db_record->record;
	digest_to_uuid(ek_desc->uuid,uuid);
	uuid[DIGEST_SIZE*2]=0;
	Strcpy(NameBuf,"ekpub/");
	Strcat(NameBuf,uuid);

	tcm_ekpub=Talloc0(sizeof(*tcm_ekpub));
	if(tcm_ekpub==NULL)
		return -ENOMEM;
	ret=TCM_ExLoadTcmPubKey(tcm_ekpub,NameBuf);
	if(ret!=0)
	{
		printf("Load TCM Pubkey failed!\n");
		return ret;
	}

	// alloc pik_cadata struct
	pik_cadata=Talloc0(sizeof(*pik_cadata));
	if(pik_cadata==NULL)
		return -ENOMEM;

	// get userinfo's blob and write its digest to pik_cadata->userinfo_uuid
	
	tcm_key_template=memdb_get_template(TYPE_PAIR(TCM_PIK_DESC,USERINFO));
	if(tcm_key_template==NULL)
		return -EINVAL;
	info_len=struct_2_blob(pik_userinfo,Buf,tcm_key_template);
	if(info_len<0)
		return info_len;

	vtcm_ex_sm3(pik_cadata->userinfo_uuid,1,Buf,info_len);

	// verify pik's req	

    	ret=TCM_ExCAPikReqVerify(tcm_pikpub,Buf,info_len,
		req_blob->bindata,req_blob->size);
    	if(ret<0)
    	{
		printf("verify pik req error!\n");
		return TCM_BAD_SIGNATURE;	
    	}

	// do the CA sign and generate cadata			 
    	BYTE * cert;
    	int certlen;
    	BYTE * symmkeyblob;
    	int symmkeybloblen;	 

    	ret= TCM_ExCAPikCertSign(tcm_ekpub,tcm_pikpub, Buf,info_len,
		&cert,&certlen,&symmkeyblob,&symmkeybloblen);
    	if(ret<0)
    	{
		printf("CA sign cert failed!\n");
		return TCM_BAD_SIGNATURE;	
        }

        tcm_key_template=memdb_get_template(TYPE_PAIR(VTCM_IN_KEY,TCM_BIN_PUBKEY));
        if(tcm_key_template==NULL)
                return -EINVAL;
        key_len=struct_2_blob(tcm_pikpub,Buf,tcm_key_template);
        if(key_len<0)
                return key_len;
        vtcm_ex_sm3(pik_cadata->pikpub_uuid,1,Buf,key_len);

	pik_cadata->certlen=certlen;
	pik_cadata->cert=cert;
	pik_cadata->symmkey=symmkeyblob;
	pik_cadata->symmkey_len=symmkeybloblen;

	// send pikdata message 

	// build a message and send it 
	new_msg=message_create(TYPE_PAIR(TCM_PIK_DESC,CADATA),recv_msg);
	if(new_msg==NULL)
		return -EINVAL;
	ret=message_add_record(new_msg,pik_cadata);
	if(ret<0)
		return ret;
	
	ret=ex_module_sendmsg(sub_proc,new_msg);
	return ret;
}

