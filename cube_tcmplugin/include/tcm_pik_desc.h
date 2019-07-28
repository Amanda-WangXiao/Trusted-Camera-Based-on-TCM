enum dtype_tcm_pik_desc {
	TYPE(TCM_PIK_DESC)=0x3320
};
enum subtype_tcm_pik_desc {
	SUBTYPE(TCM_PIK_DESC,USERINFO)=0x1,
	SUBTYPE(TCM_PIK_DESC,CADATA),
	SUBTYPE(TCM_PIK_DESC,VERIFYDATA),
	SUBTYPE(TCM_PIK_DESC,PIKCERT),
	SUBTYPE(TCM_PIK_DESC,PCRQUOTE),
	SUBTYPE(TCM_PIK_DESC,KEYCERTIFY)
};
typedef struct tcm_pik_desc_userinfo{
	char username[32];
	char user_role[32];
	BYTE node_uuid[32];
	char node_name[32];
	char * describe;
}__attribute__((packed)) RECORD(TCM_PIK_DESC,USERINFO);

typedef struct tcm_pik_desc_cadata{
	BYTE userinfo_uuid[DIGEST_SIZE];
	BYTE pikpub_uuid[DIGEST_SIZE];
	int certlen;
	BYTE * cert;
	int symmkey_len;
	BYTE * symmkey;
}__attribute__((packed)) RECORD(TCM_PIK_DESC,CADATA);

typedef struct tcm_pik_desc_verifydata{
	BYTE payload;
	BYTE userDigest[DIGEST_SIZE];
	BYTE pubDigest[DIGEST_SIZE];
	int signLen;
	BYTE * signData;
}__attribute__((packed)) RECORD(TCM_PIK_DESC,VERIFYDATA);

typedef struct tcm_pik_desc_pikcert{
	RECORD(TCM_PIK_DESC,USERINFO) userinfo;
	TCM_PUBKEY pikpub;
	RECORD(TCM_PIK_DESC,VERIFYDATA) verifydata;
}__attribute__((packed)) RECORD(TCM_PIK_DESC,PIKCERT);
