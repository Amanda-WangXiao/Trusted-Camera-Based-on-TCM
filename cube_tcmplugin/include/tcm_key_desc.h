enum dtype_tcm_key_desc {
	TYPE(TCM_KEY_DESC)=0x3300
};
enum subtype_tcm_key_desc {
	SUBTYPE(TCM_KEY_DESC,EK_DESC)=0x1,
	SUBTYPE(TCM_KEY_DESC,PIK_DESC),
	SUBTYPE(TCM_KEY_DESC,VERIFY_DESC),
	SUBTYPE(TCM_KEY_DESC,LOCAL_KEYSET),
	SUBTYPE(TCM_KEY_DESC,REMOTE_KEYSET),
	SUBTYPE(TCM_KEY_DESC,KEYCERT_DESC),
	SUBTYPE(TCM_KEY_DESC,QUOTE_DESC),
	SUBTYPE(TCM_KEY_DESC,SIGNKEY_DESC),
	SUBTYPE(TCM_KEY_DESC,BINDKEY_DESC)
};

typedef struct tcm_key_desc_ek_desc{
	BYTE uuid[32];
	BYTE node_uuid[32];
	char node_name[32];
}__attribute__((packed)) RECORD(TCM_KEY_DESC,EK_DESC);

typedef struct tcm_key_desc_pik_desc{
	BYTE uuid[32];
	BYTE node_uuid[32];
	char user_name[32];
	BYTE cert_uuid[32];
}__attribute__((packed)) RECORD(TCM_KEY_DESC,PIK_DESC);

typedef struct tcm_key_desc_verify_desc{
	int result;  // 0-success, 1-sign verify failed, 2-hash compare failed 
	BYTE object_uuid[32];
	BYTE verifykey_uuid[32]; // all zero means use capubkey
}__attribute__((packed)) RECORD(TCM_KEY_DESC,VERIFY_DESC);

typedef struct tcm_key_desc_local_keyset{
	char user_name[32];   
	BYTE pik_uuid[32];
	BYTE pikcert_uuid[32];
	BYTE signkey_uuid[32]; 
	BYTE unbindkey_uuid[32]; 
}__attribute__((packed)) RECORD(TCM_KEY_DESC,LOCAL_KEYSET);

typedef struct tcm_key_desc_remote_keyset{
	char user_name[32];   
	BYTE node_uuid[32];
	BYTE pikpub_uuid[32];
	BYTE pikcert_uuid[32];
	BYTE verifykey_uuid[32]; 
	BYTE bindkey_uuid[32]; 
}__attribute__((packed)) RECORD(TCM_KEY_DESC,REMOTE_KEYSET);

typedef struct tcm_key_desc_keycert_desc{
	BYTE uuid[32];   
	BYTE node_uuid[32];
	BYTE pikpub_uuid[32];
	BYTE key_uuid[32];
	BYTE external_data[32]; 
}__attribute__((packed)) RECORD(TCM_KEY_DESC,KEYCERT_DESC);

typedef struct tcm_key_desc_quote_desc{
	BYTE uuid[32];   
	BYTE node_uuid[32];
	BYTE pikpub_uuid[32];
	TCM_PCR_SELECTION pcr_select;
	BYTE external_data[32]; 
}__attribute__((packed)) RECORD(TCM_KEY_DESC,QUOTE_DESC);

enum dtype_tcm_entity_desc {
	TYPE(TCM_ENTITY_DESC)=0x3310
};
enum subtype_tcm_entity_desc {
	SUBTYPE(TCM_ENTITY_DESC,USER_DESC)=0x1,
	SUBTYPE(TCM_ENTITY_DESC,NODE_DESC),
	SUBTYPE(TCM_ENTITY_DESC,PIK_REQUEST_DESC),
	SUBTYPE(TCM_ENTITY_DESC,PIK_CERT_DESC)
};
typedef struct tcm_key_desc_user_desc{
	char user_name[32];
}__attribute__((packed)) RECORD(TCM_ENTITY_DESC,USER_DESC);

