enum dtype_vtcm_in_cap {
	TYPE(VTCM_IN_CAP)=0x2003
};
enum subtype_vtcm_in_cap {
	SUBTYPE(VTCM_IN_CAP,TCM_CAP_VERSION_STRUCT)=0x1,
	SUBTYPE(VTCM_IN_CAP,TCM_CAP_VERSION_INFO),
	SUBTYPE(VTCM_IN_CAP,TCM_CAP_DIGEST)
};
typedef struct tcm_version_struct{
	BYTE major;
	BYTE minor;
	BYTE revMajor;
	BYTE revMinor;
}__attribute__((packed)) RECORD(VTCM_IN_CAP,TCM_CAP_VERSION_STRUCT);

typedef struct tcm_cap_version_info{
	UINT16 tag;
	RECORD(VTCM_IN_CAP,TCM_CAP_VERSION_STRUCT) version;
	UINT16 specLevel;
	BYTE errataRev;
	BYTE tcmVendorID[4];
	UINT16 vendorSpecificSize;
	BYTE * vendorSpecific;
}__attribute__((packed)) RECORD(VTCM_IN_CAP,TCM_CAP_VERSION_INFO);

typedef struct tcm_digest{
	BYTE digest[32];
}__attribute__((packed)) RECORD(VTCM_IN_CAP,TCM_CAP_DIGEST);

enum dtype_vtcm_in_key {
	TYPE(VTCM_IN_KEY)=0x2004
};
enum subtype_vtcm_in_key {
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_KEY_PARMS)=0x1,
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_PUBKEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_RSA_KEY_PARMS),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_SM2_ASYMKEY_PARMS),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_SYMMETRIC_KEY_PARMS),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_STORE_ASYMKEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_STORE_SYMKEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_STORE_PRIVKEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_KEY),
	SUBTYPE(VTCM_IN_KEY,TCM_BIN_SYMMETRIC_KEY)
};
typedef struct tcm_key_parms{
	UINT32 algorithmID;
	UINT16 encScheme;
	UINT16 sigScheme;
	UINT32 parmSize;
	BYTE * parms;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS);

typedef struct tcm_key_store_pubkey{
	UINT32 keyLength;
	BYTE * key;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY);

typedef struct tcm_key_pubkey{
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) algorithmParms;
	RECORD(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY) pubKey;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY);

typedef struct tcm_rsa_key_parms{
	UINT32 keyLength;
	UINT32 numPrimes;
	UINT32 exponentSize;
	BYTE * exponent;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_RSA_KEY_PARMS);

typedef struct tcm_sm2_asymkey_parameters{
	UINT32 keyLength;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_SM2_ASYMKEY_PARMS);

typedef struct tcm_symmetric_key_parms{
	UINT32 keyLength;
	UINT32 blockSize;
	UINT32 ivSize;
	BYTE * IV;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_SYMMETRIC_KEY_PARMS);

typedef struct tcm_store_asymkey{
	BYTE payload;
	BYTE usageAuth[32];
	BYTE migrationAuth[32];
	RECORD(VTCM_IN_CAP,TCM_CAP_DIGEST) pubDataDigest;
	RECORD(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY) privKey;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_STORE_ASYMKEY);

typedef struct tcm_store_symkey{
	BYTE payload;
	BYTE usageAuth[32];
	BYTE migrationAuth[32];
	UINT16 size;
	BYTE * data;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_STORE_SYMKEY);

typedef struct tcm_key_store_privkey{
	UINT32 keyLength;
	BYTE * key;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_STORE_PRIVKEY);

typedef struct tcm_key{
	RECORD(VTCM_IN_CAP,TCM_CAP_VERSION_STRUCT) ver;
	UINT16 keyUsage;
	UINT32 keyFlags;
	BYTE authDataUsage;
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) algorithmParms;
	UINT32 PCRInfoSize;
	BYTE * PCRInfo;
	RECORD(VTCM_IN_KEY,TCM_BIN_STORE_PUBKEY) pubKey;
	UINT32 encDataSize;
	BYTE * encData;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_KEY);

typedef struct tcm_key_symmetric_key{
	UINT32 algId;
	UINT16 encScheme;
	UINT16 size;
	BYTE * data;
}__attribute__((packed)) RECORD(VTCM_IN_KEY,TCM_BIN_SYMMETRIC_KEY);

enum dtype_vtcm_identity {
	TYPE(VTCM_IDENTITY)=0x2009
};
enum subtype_vtcm_identity {
	SUBTYPE(VTCM_IDENTITY,TCM_IDENTITY_CONTENTS)=0x1,
	SUBTYPE(VTCM_IDENTITY,TCM_IDENTITY_REQ),
	SUBTYPE(VTCM_IDENTITY,TCM_PEK_REQ),
	SUBTYPE(VTCM_IDENTITY,TCM_IDENTITY_PROOF),
	SUBTYPE(VTCM_IDENTITY,TCM_PEK_PROOF),
	SUBTYPE(VTCM_IDENTITY,TCM_ASYM_CA_CONTENTS),
	SUBTYPE(VTCM_IDENTITY,TCM_STRUCT_VER),
	SUBTYPE(VTCM_IDENTITY,TCM_SYMMETRIC_KEY)
};
typedef struct tcm_identity_contents{
	UINT32 ver;
	UINT32 ordinal;
	RECORD(VTCM_IN_CAP,TCM_CAP_DIGEST) labelPrivCADigest;
	RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) identityPubKey;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_IDENTITY_CONTENTS);

typedef struct tcm_identity_req{
	UINT32 AsymSize;
	UINT32 SymSize;
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) asymAlgorithm;
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) symAlgorithm;
	BYTE * AsymBlob;
	BYTE * SymBlob;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_IDENTITY_REQ);

typedef struct tcm_pek_req{
	UINT32 AsymSize;
	UINT32 SymSize;
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) asymAlgorithm;
	RECORD(VTCM_IN_KEY,TCM_BIN_KEY_PARMS) symAlgorithm;
	BYTE * AsymBlob;
	BYTE * SymBlob;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_PEK_REQ);

typedef struct tcm_identity_proof{
	UINT32 Ver;
	UINT32 LabelSize;
	UINT32 IdentityBindingSize;
	UINT32 EndorsementSize;
	RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) IdentityKey;
	BYTE * LabelArea;
	BYTE * IdentityBinding;
	BYTE * EndorsementCredential;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_IDENTITY_PROOF);

typedef struct tcm_pek_proof{
	UINT32 Ver;
	UINT32 LabelSize;
	UINT32 EndorsementSize;
	RECORD(VTCM_IN_KEY,TCM_BIN_PUBKEY) IdentityKey;
	BYTE * LabelArea;
	BYTE * EndorsementCredential;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_PEK_PROOF);

typedef struct tcm_asym_ca_contents{
	RECORD(VTCM_IN_KEY,TCM_BIN_SYMMETRIC_KEY) sessionKey;
	BYTE idDigest[32];
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_ASYM_CA_CONTENTS);

typedef struct tcm_struct_ver{
	BYTE major;
	BYTE minor;
	BYTE revMajor;
	BYTE revMinor;
}__attribute__((packed)) RECORD(VTCM_IDENTITY,TCM_STRUCT_VER);

