enum enum_cube_manage {
	TYPE(LOGIN_TEST)=0x3100
};
enum enum_login_state
{
	LOGIN_STATE_WAIT=0x01,
	LOGIN_STATE_LOGIN,
	LOGIN_STATE_ERR
};

enum subtype_login_test {
	SUBTYPE(LOGIN_TEST,REGISTER)=0x1,
	SUBTYPE(LOGIN_TEST,LOGIN),
	SUBTYPE(LOGIN_TEST,SENDKEY),
	SUBTYPE(LOGIN_TEST,STATE),
	SUBTYPE(LOGIN_TEST,SERVER_STATE),
	SUBTYPE(LOGIN_TEST,RETURN)
};
typedef struct login_test_register{
	char * user_name;
	char passwd[32];
	char * user_info;
	BYTE nonce[32];
}__attribute__((packed)) RECORD(LOGIN_TEST,REGISTER);

typedef struct login_test_login{
	char * user_name;
	char passwd[32];
	char proc_name[32];
	BYTE machine_uuid[32];
	BYTE nonce[32];
}__attribute__((packed)) RECORD(LOGIN_TEST,LOGIN);

typedef struct login_test_sendkey{
	char * user_name;
	BYTE node_uuid[32];
	char receiver[32];
}__attribute__((packed)) RECORD(LOGIN_TEST,SENDKEY);

typedef struct login_test_state{
	char * user_name;
	char proc_name[32];
	BYTE node_uuid[32];
	UINT32 curr_state;
	char * user_info;
}__attribute__((packed)) RECORD(LOGIN_TEST,STATE);

typedef struct login_test_server_state{
	char * user_name;
	BYTE node_uuid[32];
	char proc_name[32];
	BYTE addr[32];
	UINT32 curr_state;
}__attribute__((packed)) RECORD(LOGIN_TEST,SERVER_STATE);

typedef struct login_test_return{
	UINT32 return_code;
	char * return_info;
}__attribute__((packed)) RECORD(LOGIN_TEST,RETURN);

