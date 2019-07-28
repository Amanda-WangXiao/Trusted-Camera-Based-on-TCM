enum enum_cube_manage {
	TYPE(TCM_KEY_MANAGE)=0x3200
};
enum subtype_tcm_key_manage {
	SUBTYPE(TCM_KEY_MANAGE,PRIVATE_KEY)=0x1,
	SUBTYPE(TCM_KEY_MANAGE,PUBLIC_KEY)
};
typedef struct tcm_manage_private_key{
	BYTE uuid[32];
	BYTE vtcm_uuid[32];
	BYTE issmkwrapped;
	UINT32 key_usage;
	UINT32 key_flags;
	BYTE pcrinfo_uuid[32];
	BYTE wrapkey_uuid[32];
	BYTE pubkey_uuid[32];
}__attribute__((packed)) RECORD(TCM_KEY_MANAGE,PRIVATE_KEY);

typedef struct tcm_manage_public_key{
	BYTE uuid[32];
	BYTE vtcm_uuid[32];
	BYTE ispubek;
	UINT32 key_usage;
	UINT32 key_flags;
	BYTE pcrinfo_uuid[32];
	BYTE prikey_uuid[32];
}__attribute__((packed)) RECORD(TCM_KEY_MANAGE,PUBLIC_KEY);

