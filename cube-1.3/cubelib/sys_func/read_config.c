#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sem.h>
#include <dlfcn.h>
#include <stdarg.h> 

#include "data_type.h"
#include "alloc.h"
#include "json.h"
#include "memfunc.h"
#include "struct_deal.h"
#include "crypto_func.h"
#include "basefunc.h"
#include "memdb.h"
#include "message.h"
#include "connector.h"
#include "ex_module.h"
#include "sys_func.h"

struct timeval time_val={0,1*100};
static char * err_file="cube_err.log";
static char * audit_file="cube_audit.log";
struct timeval first_time={0,0};
struct timeval debug_time;

int audit_file_init()
{
	int fd;
    	fd =open(audit_file,O_CREAT|O_RDWR|O_TRUNC,0666);
	if(fd<0)
		return fd;
	
    	close(fd);
    	fd =open(err_file,O_CREAT|O_RDWR|O_TRUNC,0666);
	if(fd<0)
		return fd;
    	close(fd);
	return 0;
}

int print_cubeerr(char * format,...)
{
	int fd;
	int len;
	int ret;
	char buffer[DIGEST_SIZE*32];
  	va_list args;
  	va_start (args, format);
  	vsprintf (buffer,format, args);
  	va_end (args);
	len=Strnlen(buffer,DIGEST_SIZE*32);
	
	fd=open(err_file,O_WRONLY|O_APPEND);
	if(fd<0)
		return -EINVAL;
	ret=write(fd,buffer,len);
	return ret;
}

int print_cubeaudit(char * format,...)
{
	int fd;
	int len;
	int ret;
	char buffer[DIGEST_SIZE*32];
	int offset=0;
  	va_list args;

        gettimeofday( &debug_time, NULL );
        if(first_time.tv_sec==0)
        {
                first_time.tv_sec=debug_time.tv_sec;
                first_time.tv_usec=debug_time.tv_usec;
                sprintf(buffer,"time: 0.0 :");
        }
        else
        {
                debug_time.tv_sec-=first_time.tv_sec;
                if(debug_time.tv_usec<first_time.tv_usec)
                        debug_time.tv_usec+=1000000-first_time.tv_usec;
                else
                        debug_time.tv_usec-=first_time.tv_usec;

                sprintf(buffer,"time: %d.%6.6d :",debug_time.tv_sec,debug_time.tv_usec);
        }
        offset=Strlen(buffer);

        va_start (args, format);
        vsprintf (buffer+offset,format, args);
        va_end (args);
        len=Strnlen(buffer,DIGEST_SIZE*32);
        buffer[len++]='\n';

	fd=open(audit_file,O_WRONLY|O_APPEND);
	if(fd<0)
		return -EINVAL;
	ret=write(fd,buffer,len);
	close(fd);
	return ret;
}

int debug_message(void * msg,char * info)
{
        char Buf[256];
        int offset;
        MSG_HEAD * msg_head;
        Buf[128]=0;
        Strncpy(Buf,info,128);
        offset=Strlen(Buf);
        msg_head=message_get_head(msg);

        sprintf(Buf+offset," message %x type %s to %s",*((UINT32 *)msg_head->nonce),message_get_typestr(msg),message_get_receiver(msg));
        print_cubeaudit("%s",Buf);
        return 0;

}

char *  get_temp_filename(char * tag )
{
	char buf[128];
	int len;
	pid_t pid=getpid();
	sprintf(buf,"/tmp/temp.%d",pid);
	len=strlen(buf);
	if(tag!= NULL)
	{
		len+=strlen(tag);
		if(strlen(tag)+strlen(tag)>=128)
			return -EINVAL;
		strcat(buf,tag);
	}
	char * tempbuf = Talloc(len+1);
	if(tempbuf==NULL)
		return -EINVAL;
	memcpy(tempbuf,buf,len+1);
	return tempbuf;
}
	
int convert_machine_uuid(char * uuidstr,BYTE * uuid)
{
	int i=0;
	int j=0;
	int len;
	int hflag=0;
	BYTE digit_value;
	char digit;
	BYTE *temp;

	
	len=Strlen(uuidstr);
	if(len<0)
		return 0;	
	if(len>DIGEST_SIZE*2)
		return -EINVAL;
	
	temp=Talloc0(DIGEST_SIZE);
	if(temp==NULL)
		return -ENOMEM;

	for(i=0;i<len;i++)
	{
		digit=uuidstr[i];
		if((digit>='0') &&(digit<='9'))
			digit_value= digit-'0';
		else if((digit>='a') &&(digit<='f'))
			digit_value= digit-'a'+10;
		else if((digit>='A') &&(digit<='F'))
			digit_value =digit-'A'+10;
		else
			continue;
		if(hflag==0)
		{
			temp[j]=digit_value;
			hflag=1;
		}
		else
		{
			temp[j]=(temp[j++]<<4)+digit_value;
			hflag=0;
		}
	}
	calculate_context_sm3(temp,DIGEST_SIZE,uuid);
	Free(temp);
	return DIGEST_SIZE;
}

int get_local_uuid(BYTE * uuid)
{
	FILE *fi,*fo;
	int i=0,j=0;
	char *s,ch;
	int len;
	int ret;

	char uuidstr[DIGEST_SIZE*2];
	
	char cmd[128];
	char *tempfile1,*tempfile2;
	char filename[DIGEST_SIZE*4];
	char *libpath;

	tempfile1=get_temp_filename(".001");
	if((tempfile1==NULL) || IS_ERR(tempfile1)) 
		return tempfile1;

	sprintf(cmd,"dmidecode | grep UUID | awk '{print $2}' > %s",tempfile1);
	ret=system(cmd);

	fi=fopen(tempfile1,"r");
	memset(uuidstr,0,DIGEST_SIZE*2);
	len=fread(uuidstr,1,36,fi);
	sprintf(cmd,"rm -f %s",tempfile1);
	ret=system(cmd);

	if(len==0)
	{
		libpath=getenv("CUBE_SYS_PLUGIN");
		if(libpath==NULL)
			return 0;	
		Strncpy(filename,libpath,DIGEST_SIZE*3);
		Strcat(filename,"/uuid");
		fi=fopen(filename,"r");
		memset(uuidstr,0,DIGEST_SIZE);
		len=fread(uuidstr,1,36,fi);
		if(len<=0)
			return 0;
	}

	len=convert_machine_uuid(uuidstr,uuid);
	return len;
}

int read_json_node(int fd, void ** node)
{
	int ret;

	int readlen;
	int leftlen;
	int json_offset;

	void * root_node;
	char json_buffer[4097];

	readlen=read(fd,json_buffer,4096);
	if(readlen<0)
		return -EIO;

	if(readlen<2)
	{
		*node=NULL;
		return 0;
	}

	json_buffer[readlen]=0;

	ret=json_solve_str(&root_node,json_buffer);
	if(ret<0)
	{
		print_cubeerr("solve json str error!\n");
		return -EINVAL;
	}
	leftlen=readlen-ret;

	lseek(fd,-leftlen,SEEK_CUR);	
	*node=root_node;
	return ret;
}

int read_json_file(char * file_name)
{
	int ret;

	int fd;
	int readlen;
	int leftlen;
	int json_offset;

	int struct_no=0;
	void * root_node;
	void * findlist;
	void * memdb_template ;
	BYTE uuid[DIGEST_SIZE];
	char json_buffer[4096];

	fd=open(file_name,O_RDONLY);
	if(fd<0)
		return fd;

	ret=read_json_node(fd,&root_node);
	if(ret>0)
	{
		while(root_node!=NULL)
		{
			ret=memdb_read_desc(root_node,uuid);
			if(ret<0)
			{	
				print_cubeerr("read %d record format from %s failed!\n",struct_no,file_name);
				break;
			}
			struct_no++;
			ret=read_json_node(fd,&root_node);
			if(ret<0)
			{
				print_cubeerr("read %d record json node from %s failed!\n",struct_no,file_name);
				break;
			}
			if(ret<32)
				break;
		}
	}
	close(fd);
	return struct_no;
}

int read_record_file(char * record_file)
{
	int type,subtype;
	void * head_node;
	void * record_node;	
	void * elem_node;	
	int fd;
	int ret;
	void * record_template;
	int count=0;
	fd=open(record_file,O_RDONLY);
	if(fd<0)
		return -EIO;
	ret=read_json_node(fd,&head_node);
	if(ret<0)
		return -EINVAL;
	if(head_node==NULL)
		return -EINVAL;
	elem_node=json_find_elem("type",head_node);
	if(elem_node==NULL)
	{
		close(fd);
		return -EINVAL;
	}
	type=memdb_get_typeno(json_get_valuestr(elem_node));
	if(type<=0)
	{
		close(fd);
		return -EINVAL;
	} 			
	elem_node=json_find_elem("subtype",head_node);
	if(elem_node==NULL)
	{
		close(fd);
		return -EINVAL;
	}
	subtype=memdb_get_subtypeno(type,json_get_valuestr(elem_node));
	if(subtype<=0)
	{
		close(fd);
		return -EINVAL;
	} 
	record_template=memdb_get_template(type,subtype);
	if(record_template==NULL)
	{
		close(fd);
		return -EINVAL;
	}		
	
	ret=read_json_node(fd,&record_node);
	int record_size=struct_size(record_template);	
	void * record=NULL;

	while(ret>0)
	{
		if(record==NULL)
			record=Talloc(record_size);
		if(record_node!=NULL)
		{
			ret=json_2_struct(record_node,record,record_template);
			if(ret>=0)
			{
				char * record_name=NULL;
				void * temp_node=json_find_elem("name",record_node);
				if(temp_node!=NULL)
					record_name=json_get_valuestr(temp_node);
				ret=memdb_store(record,type,subtype,record_name);
				if(ret>=0)
				{
					record=NULL;
					count++;
				}
				
			}
		}	
		ret=read_json_node(fd,&record_node);
	}
	close(fd);
	return count; 	
}

union semun
{
    int val;
    struct semid_ds *buf;
    unsigned short *arry;
};
int set_semvalue(int sem_id,int value)
{
    /* 用于初始化信号量，在使用信号量前必须这样做 */
    union semun sem_union;
 
    sem_union.val = value;
    if(semctl(sem_id, 0, SETVAL, sem_union) == -1)
    {
        return 0;
    }
    return 1;
}
 
void del_semvalue(int sem_id)
{
    /* 删除信号量 */
    union semun sem_union;
 
    if(semctl(sem_id, 0, IPC_RMID, sem_union) == -1)
    {
         fprintf(stderr, "Failed to delete semaphore\n");
    }
}

int semaphore_p(int sem_id,int value)
{
    /* 对信号量做减1操作，即等待P（sv）*/
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = -value;//P()
    sem_b.sem_flg = SEM_UNDO;
    if(semop(sem_id, &sem_b, 1) == -1)
    {
        printf("semaphore_p failed\n");
        return 0;
    }
    return 1;
}
 
int semaphore_v(int sem_id,int value)
{
    /* 这是一个释放操作，它使信号量变为可用，即发送信号V（sv）*/
    struct sembuf sem_b;
    sem_b.sem_num = 0;
    sem_b.sem_op = value;//V()
    sem_b.sem_flg = SEM_UNDO;
    if(semop(sem_id, &sem_b, 1) == -1)
    {
        fprintf(stderr, "semaphore_v failed\n");
        return 0;
    }
    return 1;
}
