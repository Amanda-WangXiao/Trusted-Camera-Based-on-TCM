#ifndef WEBSOCKET_CHANNEL_FUNC_H
#define WEBSOCKET_CHANNEL_FUNC_H


enum proc_conn_state
{
	PROC_CONN_START=0x1000,
	PROC_CONN_SYNC,
	PROC_CONN_ACKSEND,
	PROC_CONN_ACKRECV,
	PROC_CONN_CHANNELBUILD,
	PROC_CONN_FAIL,
};

static NAME2VALUE conn_state_list[]=
{
	{"start",PROC_CONN_START},
	{"sync",PROC_CONN_SYNC},
	{"acksend",PROC_CONN_ACKSEND},
	{"ackrecv",PROC_CONN_ACKRECV},
	{"channelbuild",PROC_CONN_CHANNELBUILD},
	{"fail",PROC_CONN_FAIL},
	{NULL,0}
};

int proc_conn_start(void * this_proc,void * para);
int proc_conn_accept(void * this_proc,void * msg,void * conn);
int proc_conn_sync(void * this_proc,void * msg,void * conn);
int proc_conn_acksend(void * this_proc,void * msg,void * conn);
int proc_conn_channelbuild(void * this_proc,void * msg,void * conn);

int websocket_channel_init(void * sub_proc,void * para);
int websocket_channel_start(void * sub_proc,void * para);

struct ws_init_para
{
	char * ws_addr;
	int ws_port;	
	char * channel_name;
}__attribute__((packed));

#endif
