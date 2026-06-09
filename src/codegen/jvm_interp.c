#ifndef JVM_INTERP_H
#include "jvm_interp.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ===== Dynamic key derivation ===== */
int64_t __runtime_master_key = 0;

static uint32_t __crc32_bytes(const unsigned char *data, int len) {
    uint32_t crc = 0xFFFFFFFF;
    for (int i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

void __init_runtime_key(void) {
    /* Compile-time salt (unique per build, defined in generated code) */
    extern const uint64_t __compile_salt;

    /* Master key = hash of salt. Each build produces different salt -> different key.
       If binary is patched and anti-debug detects it, __ad_die() is called anyway. */
    uint64_t mk = __compile_salt;
    mk ^= mk >> 33;
    mk *= 0xFF51AFD7ED558CCDULL;
    mk ^= mk >> 33;
    mk *= 0xC4CEB9FE1A85EC53ULL;
    mk ^= mk >> 33;

    __runtime_master_key = (int64_t)mk;
}

/* ===== Macros ===== */
#define RU8(c,p)  ((uint8_t)(c)[(p)])
#define RU16(c,p) ((uint16_t)(((uint8_t)(c)[(p)]<<8)|(uint8_t)(c)[(p)+1]))
#define RI16(c,p) ((int16_t)RU16(c,p))
#define RU32(c,p) ((uint32_t)(((uint32_t)(c)[(p)]<<24)|((uint32_t)(c)[(p)+1]<<16)|((uint32_t)(c)[(p)+2]<<8)|(uint32_t)(c)[(p)+3]))
#define RI32(c,p) ((int32_t)RU32(c,p))

#define PUSH_I(v) do{stk[sp].i=(jint)(v);sp++;}while(0)
#define PUSH_J(v) do{stk[sp].j=(jlong)(v);sp+=2;}while(0)
#define PUSH_F(v) do{stk[sp].f=(jfloat)(v);sp++;}while(0)
#define PUSH_D(v) do{stk[sp].d=(jdouble)(v);sp+=2;}while(0)
#define PUSH_L(v) do{stk[sp].l=(jobject)(v);sp++;}while(0)
#define POP_I()   (sp--,stk[sp].i)
#define POP_J()   (sp-=2,stk[sp].j)
#define POP_F()   (sp--,stk[sp].f)
#define POP_D()   (sp-=2,stk[sp].d)
#define POP_L()   (sp--,stk[sp].l)
#define CHK() do{if((*env)->ExceptionCheck(env))goto _exc;}while(0)

/* ===== Descriptor helpers ===== */
static int _parse_args(const char *d, char *t, int mx) {
    int n=0; const char *p=d;
    if(*p!='(')return 0; p++;
    while(*p&&*p!=')'&&n<mx){
        switch(*p){
        case'B':case'C':case'S':case'I':case'Z':t[n++]='I';p++;break;
        case'J':t[n++]='J';p++;break;
        case'F':t[n++]='F';p++;break;
        case'D':t[n++]='D';p++;break;
        case'L':t[n++]='L';while(*p&&*p!=';')p++;if(*p)p++;break;
        case'[':t[n++]='L';p++;while(*p=='[')p++;
            if(*p=='L'){while(*p&&*p!=';')p++;if(*p)p++;}else if(*p)p++;break;
        default:t[n++]='I';p++;break;
        }
    }
    return n;
}
static char _ret_ch(const char *d){const char *p=strchr(d,')');return p?*(p+1):'V';}

/* ===== Resolution (cached permanently) ===== */
static inline jclass _cls(JNIEnv *env, const JvmCpEntry *cp, JvmResolved *res, uint16_t idx, uint32_t cp_count) {
    if (idx>=cp_count) return NULL;
    if (res[idx].clazz) return res[idx].clazz;
    const char *name = NULL;
    if (cp[idx].tag==JVM_CP_CLASS) name=cp[idx].data.cls.name;
    else if (cp[idx].tag>=JVM_CP_FIELDREF && cp[idx].tag<=JVM_CP_IFACEREF) name=cp[idx].data.ref.class_name;
    if (!name) return NULL;
    jclass c = (*env)->FindClass(env, name);
    if (c) { res[idx].clazz = (jclass)(*env)->NewGlobalRef(env, c); (*env)->DeleteLocalRef(env, c); }
    return res[idx].clazz;
}
static inline jfieldID _fid(JNIEnv *env, const JvmCpEntry *cp, JvmResolved *res, uint16_t idx, uint32_t cp_count, int is_static) {
    if (idx>=cp_count) return NULL;
    if (res[idx].field_id) return res[idx].field_id;
    jclass c = _cls(env, cp, res, idx, cp_count);
    if (!c) return NULL;
    if (is_static) res[idx].field_id = (*env)->GetStaticFieldID(env, c, cp[idx].data.ref.name, cp[idx].data.ref.descriptor);
    else res[idx].field_id = (*env)->GetFieldID(env, c, cp[idx].data.ref.name, cp[idx].data.ref.descriptor);
    return res[idx].field_id;
}
static inline jmethodID _mid(JNIEnv *env, const JvmCpEntry *cp, JvmResolved *res, uint16_t idx, uint32_t cp_count, int is_static) {
    if (idx>=cp_count) return NULL;
    if (res[idx].method_id) return res[idx].method_id;
    jclass c = _cls(env, cp, res, idx, cp_count);
    if (!c) return NULL;
    if (is_static) res[idx].method_id = (*env)->GetStaticMethodID(env, c, cp[idx].data.ref.name, cp[idx].data.ref.descriptor);
    else res[idx].method_id = (*env)->GetMethodID(env, c, cp[idx].data.ref.name, cp[idx].data.ref.descriptor);
    return res[idx].method_id;
}

/* ===== Main interpreter ===== */
#ifdef __GNUC__
__attribute__((flatten,hot))
#endif
jvalue jvm_interpret(JNIEnv *env, const JvmMethodCtx *ctx,
                     const jvalue *args, uint16_t arg_count, JvmRetType ret_type) {
    jvalue result; memset(&result,0,sizeof(result));
    const uint8_t *ca = ctx->code_attr;
    const JvmCpEntry *cp = ctx->cp;
    uint32_t cpc = ctx->cp_count;
    JvmResolved *res = ctx->resolved;

    uint16_t max_stack = RU16(ca,0);
    uint16_t max_locals = RU16(ca,2);
    uint32_t code_len = RU32(ca,4);
    const uint8_t *c = ca + 8;
    uint32_t exc_off = 8 + code_len;
    uint16_t exc_count = (exc_off+2<=ctx->code_attr_len) ? RU16(ca,exc_off) : 0;
    const uint8_t *exc_tbl = ca + exc_off + 2;

    /* Use small stack buffers to avoid overflow during deep recursion */
    jvalue stk_buf[16], loc_buf[8];
    jvalue *stk = (max_stack<=16) ? stk_buf : (jvalue*)malloc((max_stack+4)*sizeof(jvalue));
    jvalue *loc = (max_locals<=8) ? loc_buf : (jvalue*)malloc((max_locals+4)*sizeof(jvalue));
    if (stk!=stk_buf) memset(stk,0,(max_stack+4)*sizeof(jvalue));
    else memset(stk_buf,0,sizeof(stk_buf));
    if (loc!=loc_buf) memset(loc,0,(max_locals+4)*sizeof(jvalue));
    else memset(loc_buf,0,sizeof(loc_buf));

    for(int i=0;i<arg_count&&i<max_locals;i++) loc[i]=args[i];
    uint16_t sp=0; uint32_t pc=0;
    (void)ret_type;

    /* Request large local ref capacity for methods with loops */
    if ((*env)->EnsureLocalCapacity(env, 65536) < 0) {
        (*env)->ExceptionClear(env);
    }

    /* Pre-cache StringBuilder for string concat optimization */
    static jclass _sb_cls = NULL;
    static jmethodID _sb_init=NULL, _sb_app_s=NULL, _sb_app_i=NULL, _sb_app_j=NULL, _sb_app_o=NULL, _sb_ts=NULL;
    if (!_sb_cls) {
        _sb_cls = (*env)->NewGlobalRef(env, (*env)->FindClass(env, "java/lang/StringBuilder"));
        _sb_init = (*env)->GetMethodID(env, _sb_cls, "<init>", "()V");
        _sb_app_s = (*env)->GetMethodID(env, _sb_cls, "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;");
        _sb_app_i = (*env)->GetMethodID(env, _sb_cls, "append", "(I)Ljava/lang/StringBuilder;");
        _sb_app_j = (*env)->GetMethodID(env, _sb_cls, "append", "(J)Ljava/lang/StringBuilder;");
        _sb_app_o = (*env)->GetMethodID(env, _sb_cls, "append", "(Ljava/lang/Object;)Ljava/lang/StringBuilder;");
        _sb_ts = (*env)->GetMethodID(env, _sb_cls, "toString", "()Ljava/lang/String;");
    }

/* ===== Dispatch mechanism ===== */
#ifdef __GNUC__
    static const void *dispatch[256] = {
        [0x00]=&&OP_0x00, [0x01]=&&OP_0x01, [0x02]=&&OP_0x02, [0x03]=&&OP_0x03,
        [0x04]=&&OP_0x04, [0x05]=&&OP_0x05, [0x06]=&&OP_0x06, [0x07]=&&OP_0x07,
        [0x08]=&&OP_0x08, [0x09]=&&OP_0x09, [0x0a]=&&OP_0x0a, [0x0b]=&&OP_0x0b,
        [0x0c]=&&OP_0x0c, [0x0d]=&&OP_0x0d, [0x0e]=&&OP_0x0e, [0x0f]=&&OP_0x0f,
        [0x10]=&&OP_0x10, [0x11]=&&OP_0x11, [0x12]=&&OP_0x12, [0x13]=&&OP_0x13,
        [0x14]=&&OP_0x14, [0x15]=&&OP_0x15, [0x16]=&&OP_0x16, [0x17]=&&OP_0x17,
        [0x18]=&&OP_0x18, [0x19]=&&OP_0x19, [0x1a]=&&OP_0x1a, [0x1b]=&&OP_0x1b,
        [0x1c]=&&OP_0x1c, [0x1d]=&&OP_0x1d, [0x1e]=&&OP_0x1e, [0x1f]=&&OP_0x1f,
        [0x20]=&&OP_0x20, [0x21]=&&OP_0x21, [0x22]=&&OP_0x22, [0x23]=&&OP_0x23,
        [0x24]=&&OP_0x24, [0x25]=&&OP_0x25, [0x26]=&&OP_0x26, [0x27]=&&OP_0x27,
        [0x28]=&&OP_0x28, [0x29]=&&OP_0x29, [0x2a]=&&OP_0x2a, [0x2b]=&&OP_0x2b,
        [0x2c]=&&OP_0x2c, [0x2d]=&&OP_0x2d, [0x2e]=&&OP_0x2e, [0x2f]=&&OP_0x2f,
        [0x30]=&&OP_0x30, [0x31]=&&OP_0x31, [0x32]=&&OP_0x32, [0x33]=&&OP_0x33,
        [0x34]=&&OP_0x34, [0x35]=&&OP_0x35, [0x36]=&&OP_0x36, [0x37]=&&OP_0x37,
        [0x38]=&&OP_0x38, [0x39]=&&OP_0x39, [0x3a]=&&OP_0x3a, [0x3b]=&&OP_0x3b,
        [0x3c]=&&OP_0x3c, [0x3d]=&&OP_0x3d, [0x3e]=&&OP_0x3e, [0x3f]=&&OP_0x3f,
        [0x40]=&&OP_0x40, [0x41]=&&OP_0x41, [0x42]=&&OP_0x42, [0x43]=&&OP_0x43,
        [0x44]=&&OP_0x44, [0x45]=&&OP_0x45, [0x46]=&&OP_0x46, [0x47]=&&OP_0x47,
        [0x48]=&&OP_0x48, [0x49]=&&OP_0x49, [0x4a]=&&OP_0x4a, [0x4b]=&&OP_0x4b,
        [0x4c]=&&OP_0x4c, [0x4d]=&&OP_0x4d, [0x4e]=&&OP_0x4e, [0x4f]=&&OP_0x4f,
        [0x50]=&&OP_0x50, [0x51]=&&OP_0x51, [0x52]=&&OP_0x52, [0x53]=&&OP_0x53,
        [0x54]=&&OP_0x54, [0x55]=&&OP_0x55, [0x56]=&&OP_0x56, [0x57]=&&OP_0x57,
        [0x58]=&&OP_0x58, [0x59]=&&OP_0x59, [0x5a]=&&OP_0x5a, [0x5b]=&&OP_0x5b,
        [0x5c]=&&OP_0x5c, [0x5d]=&&OP_0x5d, [0x5e]=&&OP_0x5e, [0x5f]=&&OP_0x5f,
        [0x60]=&&OP_0x60, [0x61]=&&OP_0x61, [0x62]=&&OP_0x62, [0x63]=&&OP_0x63,
        [0x64]=&&OP_0x64, [0x65]=&&OP_0x65, [0x66]=&&OP_0x66, [0x67]=&&OP_0x67,
        [0x68]=&&OP_0x68, [0x69]=&&OP_0x69, [0x6a]=&&OP_0x6a, [0x6b]=&&OP_0x6b,
        [0x6c]=&&OP_0x6c, [0x6d]=&&OP_0x6d, [0x6e]=&&OP_0x6e, [0x6f]=&&OP_0x6f,
        [0x70]=&&OP_0x70, [0x71]=&&OP_0x71, [0x72]=&&OP_0x72, [0x73]=&&OP_0x73,
        [0x74]=&&OP_0x74, [0x75]=&&OP_0x75, [0x76]=&&OP_0x76, [0x77]=&&OP_0x77,
        [0x78]=&&OP_0x78, [0x79]=&&OP_0x79, [0x7a]=&&OP_0x7a, [0x7b]=&&OP_0x7b,
        [0x7c]=&&OP_0x7c, [0x7d]=&&OP_0x7d, [0x7e]=&&OP_0x7e, [0x7f]=&&OP_0x7f,
        [0x80]=&&OP_0x80, [0x81]=&&OP_0x81, [0x82]=&&OP_0x82, [0x83]=&&OP_0x83,
        [0x84]=&&OP_0x84, [0x85]=&&OP_0x85, [0x86]=&&OP_0x86, [0x87]=&&OP_0x87,
        [0x88]=&&OP_0x88, [0x89]=&&OP_0x89, [0x8a]=&&OP_0x8a, [0x8b]=&&OP_0x8b,
        [0x8c]=&&OP_0x8c, [0x8d]=&&OP_0x8d, [0x8e]=&&OP_0x8e, [0x8f]=&&OP_0x8f,
        [0x90]=&&OP_0x90, [0x91]=&&OP_0x91, [0x92]=&&OP_0x92, [0x93]=&&OP_0x93,
        [0x94]=&&OP_0x94, [0x95]=&&OP_0x95, [0x96]=&&OP_0x96, [0x97]=&&OP_0x97,
        [0x98]=&&OP_0x98, [0x99]=&&OP_0x99, [0x9a]=&&OP_0x9a, [0x9b]=&&OP_0x9b,
        [0x9c]=&&OP_0x9c, [0x9d]=&&OP_0x9d, [0x9e]=&&OP_0x9e, [0x9f]=&&OP_0x9f,
        [0xa0]=&&OP_0xa0, [0xa1]=&&OP_0xa1, [0xa2]=&&OP_0xa2, [0xa3]=&&OP_0xa3,
        [0xa4]=&&OP_0xa4, [0xa5]=&&OP_0xa5, [0xa6]=&&OP_0xa6, [0xa7]=&&OP_0xa7,
        [0xa8]=&&OP_DEFAULT, [0xa9]=&&OP_DEFAULT,
        [0xaa]=&&OP_0xaa, [0xab]=&&OP_0xab,
        [0xac]=&&OP_0xac, [0xad]=&&OP_0xad, [0xae]=&&OP_0xae, [0xaf]=&&OP_0xaf,
        [0xb0]=&&OP_0xb0, [0xb1]=&&OP_0xb1,
        [0xb2]=&&OP_0xb2, [0xb3]=&&OP_0xb2, [0xb4]=&&OP_0xb2, [0xb5]=&&OP_0xb2,
        [0xb6]=&&OP_0xb6, [0xb7]=&&OP_0xb6, [0xb8]=&&OP_0xb6, [0xb9]=&&OP_0xb6,
        [0xba]=&&OP_0xba,
        [0xbb]=&&OP_0xbb, [0xbc]=&&OP_0xbc, [0xbd]=&&OP_0xbd, [0xbe]=&&OP_0xbe,
        [0xbf]=&&OP_0xbf, [0xc0]=&&OP_0xc0, [0xc1]=&&OP_0xc1, [0xc2]=&&OP_0xc2,
        [0xc3]=&&OP_0xc3, [0xc4]=&&OP_0xc4, [0xc5]=&&OP_0xc5, [0xc6]=&&OP_0xc6,
        [0xc7]=&&OP_0xc7, [0xc8]=&&OP_0xc8,
        [0xc9]=&&OP_DEFAULT, [0xca]=&&OP_DEFAULT, [0xcb]=&&OP_DEFAULT,
        [0xcc]=&&OP_DEFAULT, [0xcd]=&&OP_DEFAULT, [0xce]=&&OP_DEFAULT,
        [0xcf]=&&OP_DEFAULT, [0xd0]=&&OP_DEFAULT, [0xd1]=&&OP_DEFAULT,
        [0xd2]=&&OP_DEFAULT, [0xd3]=&&OP_DEFAULT, [0xd4]=&&OP_DEFAULT,
        [0xd5]=&&OP_DEFAULT, [0xd6]=&&OP_DEFAULT, [0xd7]=&&OP_DEFAULT,
        [0xd8]=&&OP_DEFAULT, [0xd9]=&&OP_DEFAULT, [0xda]=&&OP_DEFAULT,
        [0xdb]=&&OP_DEFAULT, [0xdc]=&&OP_DEFAULT, [0xdd]=&&OP_DEFAULT,
        [0xde]=&&OP_DEFAULT, [0xdf]=&&OP_DEFAULT, [0xe0]=&&OP_DEFAULT,
        [0xe1]=&&OP_DEFAULT, [0xe2]=&&OP_DEFAULT, [0xe3]=&&OP_DEFAULT,
        [0xe4]=&&OP_DEFAULT, [0xe5]=&&OP_DEFAULT, [0xe6]=&&OP_DEFAULT,
        [0xe7]=&&OP_DEFAULT, [0xe8]=&&OP_DEFAULT, [0xe9]=&&OP_DEFAULT,
        [0xea]=&&OP_DEFAULT, [0xeb]=&&OP_DEFAULT, [0xec]=&&OP_DEFAULT,
        [0xed]=&&OP_DEFAULT, [0xee]=&&OP_DEFAULT, [0xef]=&&OP_DEFAULT,
        [0xf0]=&&OP_DEFAULT, [0xf1]=&&OP_DEFAULT, [0xf2]=&&OP_DEFAULT,
        [0xf3]=&&OP_DEFAULT, [0xf4]=&&OP_DEFAULT, [0xf5]=&&OP_DEFAULT,
        [0xf6]=&&OP_DEFAULT, [0xf7]=&&OP_DEFAULT, [0xf8]=&&OP_DEFAULT,
        [0xf9]=&&OP_DEFAULT, [0xfa]=&&OP_DEFAULT, [0xfb]=&&OP_DEFAULT,
        [0xfc]=&&OP_DEFAULT, [0xfd]=&&OP_0xfd, [0xfe]=&&OP_0xfe, [0xff]=&&OP_DEFAULT
    };
    #define DISPATCH() do { if(pc>=code_len) goto _done; goto *dispatch[c[pc]]; } while(0)
    #define TARGET(x) OP_##x
    DISPATCH();
#else
    #define DISPATCH() break
    #define TARGET(x) case x
    while(pc<code_len){ uint8_t op=c[pc]; switch(op){
#endif

    TARGET(0x00): pc++; DISPATCH();
    TARGET(0x01): PUSH_L(NULL); pc++; DISPATCH();
    TARGET(0x02): PUSH_I(-1); pc++; DISPATCH();
    TARGET(0x03): PUSH_I(0); pc++; DISPATCH();
    TARGET(0x04): PUSH_I(1); pc++; DISPATCH();
    TARGET(0x05): PUSH_I(2); pc++; DISPATCH();
    TARGET(0x06): PUSH_I(3); pc++; DISPATCH();
    TARGET(0x07): PUSH_I(4); pc++; DISPATCH();
    TARGET(0x08): PUSH_I(5); pc++; DISPATCH();
    TARGET(0x09): PUSH_J(0); pc++; DISPATCH();
    TARGET(0x0a): PUSH_J(1); pc++; DISPATCH();
    TARGET(0x0b): PUSH_F(0.0f); pc++; DISPATCH();
    TARGET(0x0c): PUSH_F(1.0f); pc++; DISPATCH();
    TARGET(0x0d): PUSH_F(2.0f); pc++; DISPATCH();
    TARGET(0x0e): PUSH_D(0.0); pc++; DISPATCH();
    TARGET(0x0f): PUSH_D(1.0); pc++; DISPATCH();
    TARGET(0x10): PUSH_I((int8_t)c[pc+1]); pc+=2; DISPATCH();
    TARGET(0x11): PUSH_I(RI16(c,pc+1)); pc+=3; DISPATCH();
    TARGET(0x12): {uint16_t i=c[pc+1];if(i<cpc){switch(cp[i].tag){
        case JVM_CP_INTEGER:PUSH_I(cp[i].data.i);break;case JVM_CP_FLOAT:PUSH_F(cp[i].data.f);break;
        case JVM_CP_STRING:{if(!res[i].cached_obj){jstring s=(*env)->NewStringUTF(env,cp[i].data.str.value);res[i].cached_obj=(*env)->NewGlobalRef(env,s);(*env)->DeleteLocalRef(env,s);}PUSH_L(res[i].cached_obj);break;}
        case JVM_CP_CLASS:{jclass cc=_cls(env,cp,res,i,cpc);PUSH_L(cc);break;}
        default:PUSH_I(0);break;}}pc+=2;DISPATCH();}
    TARGET(0x13): {uint16_t i=RU16(c,pc+1);if(i<cpc){switch(cp[i].tag){
        case JVM_CP_INTEGER:PUSH_I(cp[i].data.i);break;case JVM_CP_FLOAT:PUSH_F(cp[i].data.f);break;
        case JVM_CP_STRING:{if(!res[i].cached_obj){jstring s=(*env)->NewStringUTF(env,cp[i].data.str.value);res[i].cached_obj=(*env)->NewGlobalRef(env,s);(*env)->DeleteLocalRef(env,s);}PUSH_L(res[i].cached_obj);break;}
        default:PUSH_I(0);break;}}pc+=3;DISPATCH();}
    TARGET(0x14): {uint16_t i=RU16(c,pc+1);if(i<cpc){if(cp[i].tag==JVM_CP_LONG)PUSH_J(cp[i].data.l);else if(cp[i].tag==JVM_CP_DOUBLE)PUSH_D(cp[i].data.d);}pc+=3;DISPATCH();}
    /* loads */
    TARGET(0x15): PUSH_I(loc[c[pc+1]].i); pc+=2; DISPATCH();
    TARGET(0x16): PUSH_J(loc[c[pc+1]].j); pc+=2; DISPATCH();
    TARGET(0x17): PUSH_F(loc[c[pc+1]].f); pc+=2; DISPATCH();
    TARGET(0x18): PUSH_D(loc[c[pc+1]].d); pc+=2; DISPATCH();
    TARGET(0x19): PUSH_L(loc[c[pc+1]].l); pc+=2; DISPATCH();
    TARGET(0x1a): PUSH_I(loc[0].i); pc++; DISPATCH();
    TARGET(0x1b): PUSH_I(loc[1].i); pc++; DISPATCH();
    TARGET(0x1c): PUSH_I(loc[2].i); pc++; DISPATCH();
    TARGET(0x1d): PUSH_I(loc[3].i); pc++; DISPATCH();
    TARGET(0x1e): PUSH_J(loc[0].j); pc++; DISPATCH();
    TARGET(0x1f): PUSH_J(loc[1].j); pc++; DISPATCH();
    TARGET(0x20): PUSH_J(loc[2].j); pc++; DISPATCH();
    TARGET(0x21): PUSH_J(loc[3].j); pc++; DISPATCH();
    TARGET(0x22): PUSH_F(loc[0].f); pc++; DISPATCH();
    TARGET(0x23): PUSH_F(loc[1].f); pc++; DISPATCH();
    TARGET(0x24): PUSH_F(loc[2].f); pc++; DISPATCH();
    TARGET(0x25): PUSH_F(loc[3].f); pc++; DISPATCH();
    TARGET(0x26): PUSH_D(loc[0].d); pc++; DISPATCH();
    TARGET(0x27): PUSH_D(loc[1].d); pc++; DISPATCH();

    TARGET(0x28): PUSH_D(loc[2].d); pc++; DISPATCH();
    TARGET(0x29): PUSH_D(loc[3].d); pc++; DISPATCH();
    TARGET(0x2a): PUSH_L(loc[0].l); pc++; DISPATCH();
    TARGET(0x2b): PUSH_L(loc[1].l); pc++; DISPATCH();
    TARGET(0x2c): PUSH_L(loc[2].l); pc++; DISPATCH();
    TARGET(0x2d): PUSH_L(loc[3].l); pc++; DISPATCH();
    /* array loads */
    TARGET(0x2e): {jint i=POP_I();jarray a=(jarray)POP_L();jint v;(*env)->GetIntArrayRegion(env,(jintArray)a,i,1,&v);PUSH_I(v);CHK();pc++;DISPATCH();}
    TARGET(0x2f): {jint i=POP_I();jarray a=(jarray)POP_L();jlong v;(*env)->GetLongArrayRegion(env,(jlongArray)a,i,1,&v);PUSH_J(v);CHK();pc++;DISPATCH();}
    TARGET(0x30): {jint i=POP_I();jarray a=(jarray)POP_L();jfloat v;(*env)->GetFloatArrayRegion(env,(jfloatArray)a,i,1,&v);PUSH_F(v);CHK();pc++;DISPATCH();}
    TARGET(0x31): {jint i=POP_I();jarray a=(jarray)POP_L();jdouble v;(*env)->GetDoubleArrayRegion(env,(jdoubleArray)a,i,1,&v);PUSH_D(v);CHK();pc++;DISPATCH();}
    TARGET(0x32): {jint i=POP_I();jarray a=(jarray)POP_L();PUSH_L((*env)->GetObjectArrayElement(env,(jobjectArray)a,i));CHK();pc++;DISPATCH();}
    TARGET(0x33): {jint i=POP_I();jarray a=(jarray)POP_L();jbyte v;(*env)->GetByteArrayRegion(env,(jbyteArray)a,i,1,&v);PUSH_I(v);CHK();pc++;DISPATCH();}
    TARGET(0x34): {jint i=POP_I();jarray a=(jarray)POP_L();jchar v;(*env)->GetCharArrayRegion(env,(jcharArray)a,i,1,&v);PUSH_I(v);CHK();pc++;DISPATCH();}
    TARGET(0x35): {jint i=POP_I();jarray a=(jarray)POP_L();jshort v;(*env)->GetShortArrayRegion(env,(jshortArray)a,i,1,&v);PUSH_I(v);CHK();pc++;DISPATCH();}
    /* stores */
    TARGET(0x36): loc[c[pc+1]].i=POP_I(); pc+=2; DISPATCH();
    TARGET(0x37): loc[c[pc+1]].j=POP_J(); pc+=2; DISPATCH();
    TARGET(0x38): loc[c[pc+1]].f=POP_F(); pc+=2; DISPATCH();
    TARGET(0x39): loc[c[pc+1]].d=POP_D(); pc+=2; DISPATCH();
    TARGET(0x3a): {jobject nv=POP_L();loc[c[pc+1]].l=nv;pc+=2;DISPATCH();}
    TARGET(0x3b): loc[0].i=POP_I(); pc++; DISPATCH();
    TARGET(0x3c): loc[1].i=POP_I(); pc++; DISPATCH();
    TARGET(0x3d): loc[2].i=POP_I(); pc++; DISPATCH();
    TARGET(0x3e): loc[3].i=POP_I(); pc++; DISPATCH();
    TARGET(0x3f): loc[0].j=POP_J(); pc++; DISPATCH();
    TARGET(0x40): loc[1].j=POP_J(); pc++; DISPATCH();
    TARGET(0x41): loc[2].j=POP_J(); pc++; DISPATCH();
    TARGET(0x42): loc[3].j=POP_J(); pc++; DISPATCH();
    TARGET(0x43): loc[0].f=POP_F(); pc++; DISPATCH();
    TARGET(0x44): loc[1].f=POP_F(); pc++; DISPATCH();
    TARGET(0x45): loc[2].f=POP_F(); pc++; DISPATCH();
    TARGET(0x46): loc[3].f=POP_F(); pc++; DISPATCH();
    TARGET(0x47): loc[0].d=POP_D(); pc++; DISPATCH();
    TARGET(0x48): loc[1].d=POP_D(); pc++; DISPATCH();
    TARGET(0x49): loc[2].d=POP_D(); pc++; DISPATCH();
    TARGET(0x4a): loc[3].d=POP_D(); pc++; DISPATCH();
    TARGET(0x4b): loc[0].l=POP_L(); pc++; DISPATCH();
    TARGET(0x4c): loc[1].l=POP_L(); pc++; DISPATCH();
    TARGET(0x4d): loc[2].l=POP_L(); pc++; DISPATCH();
    TARGET(0x4e): loc[3].l=POP_L(); pc++; DISPATCH();
    /* array stores */
    TARGET(0x4f): {jint v=POP_I();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetIntArrayRegion(env,(jintArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x50): {jlong v=POP_J();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetLongArrayRegion(env,(jlongArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x51): {jfloat v=POP_F();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetFloatArrayRegion(env,(jfloatArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x52): {jdouble v=POP_D();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetDoubleArrayRegion(env,(jdoubleArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x53): {jobject v=POP_L();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetObjectArrayElement(env,(jobjectArray)a,i,v);pc++;DISPATCH();}
    TARGET(0x54): {jbyte v=(jbyte)POP_I();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetByteArrayRegion(env,(jbyteArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x55): {jchar v=(jchar)POP_I();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetCharArrayRegion(env,(jcharArray)a,i,1,&v);pc++;DISPATCH();}
    TARGET(0x56): {jshort v=(jshort)POP_I();jint i=POP_I();jarray a=(jarray)POP_L();(*env)->SetShortArrayRegion(env,(jshortArray)a,i,1,&v);pc++;DISPATCH();}

    /* stack ops */
    TARGET(0x57): sp--; pc++; DISPATCH();
    TARGET(0x58): sp-=2; pc++; DISPATCH();
    TARGET(0x59): stk[sp]=stk[sp-1]; sp++; pc++; DISPATCH();
    TARGET(0x5a): {jvalue t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=t;stk[sp]=t;sp++;pc++;DISPATCH();}
    TARGET(0x5b): {jvalue t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=stk[sp-3];stk[sp-3]=t;stk[sp]=t;sp++;pc++;DISPATCH();}
    TARGET(0x5c): stk[sp]=stk[sp-2]; stk[sp+1]=stk[sp-1]; sp+=2; pc++; DISPATCH();
    TARGET(0x5d): {jvalue a=stk[sp-1],b=stk[sp-2],cc2=stk[sp-3];stk[sp-3]=b;stk[sp-2]=a;stk[sp-1]=cc2;stk[sp]=b;stk[sp+1]=a;sp+=2;pc++;DISPATCH();}
    TARGET(0x5e): {jvalue a=stk[sp-1],b=stk[sp-2],cc2=stk[sp-3],d=stk[sp-4];stk[sp-4]=b;stk[sp-3]=a;stk[sp-2]=d;stk[sp-1]=cc2;stk[sp]=b;stk[sp+1]=a;sp+=2;pc++;DISPATCH();}
    TARGET(0x5f): {jvalue t=stk[sp-1];stk[sp-1]=stk[sp-2];stk[sp-2]=t;pc++;DISPATCH();}
    /* arithmetic int */
    TARGET(0x60): {jint b=POP_I(),a=POP_I();PUSH_I(a+b);pc++;DISPATCH();}
    TARGET(0x64): {jint b=POP_I(),a=POP_I();PUSH_I(a-b);pc++;DISPATCH();}
    TARGET(0x68): {jint b=POP_I(),a=POP_I();PUSH_I(a*b);pc++;DISPATCH();}
    TARGET(0x6c): {jint b=POP_I(),a=POP_I();PUSH_I(a/b);pc++;DISPATCH();}
    TARGET(0x70): {jint b=POP_I(),a=POP_I();PUSH_I(a%b);pc++;DISPATCH();}
    TARGET(0x74): {PUSH_I(-POP_I());pc++;DISPATCH();}
    TARGET(0x78): {jint b=POP_I(),a=POP_I();PUSH_I(a<<(b&31));pc++;DISPATCH();}
    TARGET(0x7a): {jint b=POP_I(),a=POP_I();PUSH_I(a>>(b&31));pc++;DISPATCH();}
    TARGET(0x7c): {jint b=POP_I(),a=POP_I();PUSH_I((jint)((uint32_t)a>>(b&31)));pc++;DISPATCH();}
    TARGET(0x7e): {jint b=POP_I(),a=POP_I();PUSH_I(a&b);pc++;DISPATCH();}
    TARGET(0x80): {jint b=POP_I(),a=POP_I();PUSH_I(a|b);pc++;DISPATCH();}
    TARGET(0x82): {jint b=POP_I(),a=POP_I();PUSH_I(a^b);pc++;DISPATCH();}
    TARGET(0x84): {uint8_t i=c[pc+1];loc[i].i+=(int8_t)c[pc+2];pc+=3;DISPATCH();}
    /* arithmetic long */
    TARGET(0x61): {jlong b=POP_J(),a=POP_J();PUSH_J(a+b);pc++;DISPATCH();}
    TARGET(0x65): {jlong b=POP_J(),a=POP_J();PUSH_J(a-b);pc++;DISPATCH();}
    TARGET(0x69): {jlong b=POP_J(),a=POP_J();PUSH_J(a*b);pc++;DISPATCH();}
    TARGET(0x6d): {jlong b=POP_J(),a=POP_J();PUSH_J(a/b);pc++;DISPATCH();}
    TARGET(0x71): {jlong b=POP_J(),a=POP_J();PUSH_J(a%b);pc++;DISPATCH();}
    TARGET(0x75): {PUSH_J(-POP_J());pc++;DISPATCH();}
    TARGET(0x79): {jint b=POP_I();jlong a=POP_J();PUSH_J(a<<(b&63));pc++;DISPATCH();}
    TARGET(0x7b): {jint b=POP_I();jlong a=POP_J();PUSH_J(a>>(b&63));pc++;DISPATCH();}
    TARGET(0x7d): {jint b=POP_I();jlong a=POP_J();PUSH_J((jlong)((uint64_t)a>>(b&63)));pc++;DISPATCH();}
    TARGET(0x7f): {jlong b=POP_J(),a=POP_J();PUSH_J(a&b);pc++;DISPATCH();}
    TARGET(0x81): {jlong b=POP_J(),a=POP_J();PUSH_J(a|b);pc++;DISPATCH();}
    TARGET(0x83): {jlong b=POP_J(),a=POP_J();PUSH_J(a^b);pc++;DISPATCH();}
    /* arithmetic float/double */
    TARGET(0x62): {jfloat b=POP_F(),a=POP_F();PUSH_F(a+b);pc++;DISPATCH();}
    TARGET(0x66): {jfloat b=POP_F(),a=POP_F();PUSH_F(a-b);pc++;DISPATCH();}
    TARGET(0x6a): {jfloat b=POP_F(),a=POP_F();PUSH_F(a*b);pc++;DISPATCH();}
    TARGET(0x6e): {jfloat b=POP_F(),a=POP_F();PUSH_F(a/b);pc++;DISPATCH();}
    TARGET(0x72): {jfloat b=POP_F(),a=POP_F();PUSH_F(a-((int)(a/b))*b);pc++;DISPATCH();}
    TARGET(0x76): {PUSH_F(-POP_F());pc++;DISPATCH();}
    TARGET(0x63): {jdouble b=POP_D(),a=POP_D();PUSH_D(a+b);pc++;DISPATCH();}
    TARGET(0x67): {jdouble b=POP_D(),a=POP_D();PUSH_D(a-b);pc++;DISPATCH();}
    TARGET(0x6b): {jdouble b=POP_D(),a=POP_D();PUSH_D(a*b);pc++;DISPATCH();}
    TARGET(0x6f): {jdouble b=POP_D(),a=POP_D();PUSH_D(a/b);pc++;DISPATCH();}
    TARGET(0x73): {jdouble b=POP_D(),a=POP_D();PUSH_D(a-((long long)(a/b))*b);pc++;DISPATCH();}
    TARGET(0x77): {PUSH_D(-POP_D());pc++;DISPATCH();}

    /* conversions */
    TARGET(0x85): {PUSH_J((jlong)POP_I());pc++;DISPATCH();}
    TARGET(0x86): {PUSH_F((jfloat)POP_I());pc++;DISPATCH();}
    TARGET(0x87): {PUSH_D((jdouble)POP_I());pc++;DISPATCH();}
    TARGET(0x88): {PUSH_I((jint)POP_J());pc++;DISPATCH();}
    TARGET(0x89): {PUSH_F((jfloat)POP_J());pc++;DISPATCH();}
    TARGET(0x8a): {PUSH_D((jdouble)POP_J());pc++;DISPATCH();}
    TARGET(0x8b): {PUSH_I((jint)POP_F());pc++;DISPATCH();}
    TARGET(0x8c): {PUSH_J((jlong)POP_F());pc++;DISPATCH();}
    TARGET(0x8d): {PUSH_D((jdouble)POP_F());pc++;DISPATCH();}
    TARGET(0x8e): {PUSH_I((jint)POP_D());pc++;DISPATCH();}
    TARGET(0x8f): {PUSH_J((jlong)POP_D());pc++;DISPATCH();}
    TARGET(0x90): {PUSH_F((jfloat)POP_D());pc++;DISPATCH();}
    TARGET(0x91): {PUSH_I((jint)(int8_t)POP_I());pc++;DISPATCH();}
    TARGET(0x92): {PUSH_I((jint)(uint16_t)POP_I());pc++;DISPATCH();}
    TARGET(0x93): {PUSH_I((jint)(int16_t)POP_I());pc++;DISPATCH();}
    /* comparisons */
    TARGET(0x94): {jlong b=POP_J(),a=POP_J();PUSH_I(a>b?1:(a<b?-1:0));pc++;DISPATCH();}
    TARGET(0x95): {jfloat b=POP_F(),a=POP_F();PUSH_I(a>b?1:(a<b?-1:(a==b?0:-1)));pc++;DISPATCH();}
    TARGET(0x96): {jfloat b=POP_F(),a=POP_F();PUSH_I(a>b?1:(a<b?-1:(a==b?0:1)));pc++;DISPATCH();}
    TARGET(0x97): {jdouble b=POP_D(),a=POP_D();PUSH_I(a>b?1:(a<b?-1:(a==b?0:-1)));pc++;DISPATCH();}
    TARGET(0x98): {jdouble b=POP_D(),a=POP_D();PUSH_I(a>b?1:(a<b?-1:(a==b?0:1)));pc++;DISPATCH();}
    /* branches */
    TARGET(0x99): {jint v=POP_I();if(v==0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9a): {jint v=POP_I();if(v!=0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9b): {jint v=POP_I();if(v<0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9c): {jint v=POP_I();if(v>=0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9d): {jint v=POP_I();if(v>0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9e): {jint v=POP_I();if(v<=0)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0x9f): {jint b=POP_I(),a=POP_I();if(a==b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa0): {jint b=POP_I(),a=POP_I();if(a!=b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa1): {jint b=POP_I(),a=POP_I();if(a<b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa2): {jint b=POP_I(),a=POP_I();if(a>=b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa3): {jint b=POP_I(),a=POP_I();if(a>b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa4): {jint b=POP_I(),a=POP_I();if(a<=b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa5): {jobject b=POP_L(),a=POP_L();if(a==b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa6): {jobject b=POP_L(),a=POP_L();if(a!=b)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xa7): { /* goto */
        int16_t _off = RI16(c,pc+1);
        pc += _off;
        /* Periodic anti-debug on backward jumps (loops) */
        if (_off < 0) {
            static int __ad_counter = 0;
            if (++__ad_counter >= 10000) {
                __ad_counter = 0;
                extern volatile int __ad_flag;
                extern void __anti_debug_check(void);
                if (__ad_flag) __anti_debug_check();
            }
        }
        DISPATCH(); }
    TARGET(0xc8): pc+=RI32(c,pc+1); DISPATCH();
    TARGET(0xaa): {uint32_t bp=pc;uint32_t pp=(pc+4)&~3u;int32_t def=RI32(c,pp);int32_t lo=RI32(c,pp+4);int32_t hi=RI32(c,pp+8);jint k=POP_I();if(k>=lo&&k<=hi)pc=bp+RI32(c,pp+12+(k-lo)*4);else pc=bp+def;DISPATCH();}
    TARGET(0xab): {uint32_t bp=pc;uint32_t pp=(pc+4)&~3u;int32_t def=RI32(c,pp);int32_t np=RI32(c,pp+4);jint k=POP_I();int32_t tgt=def;for(int32_t p=0;p<np;p++){if(k==RI32(c,pp+8+p*8)){tgt=RI32(c,pp+8+p*8+4);break;}}pc=bp+tgt;DISPATCH();}

    /* returns */
    TARGET(0xac): result.i=POP_I(); goto _done;
    TARGET(0xad): result.j=POP_J(); goto _done;
    TARGET(0xae): result.f=POP_F(); goto _done;
    TARGET(0xaf): result.d=POP_D(); goto _done;
    TARGET(0xb0): result.l=POP_L(); goto _done;
    TARGET(0xb1): goto _done;
    /* field access */
    TARGET(0xb2): TARGET(0xb3): TARGET(0xb4): TARGET(0xb5): {
        uint8_t op=c[pc];
        uint16_t idx=RU16(c,pc+1);int is_s=(op<=0xb3),is_g=(op==0xb2||op==0xb4);
        jclass fc=_cls(env,cp,res,idx,cpc);if(!fc){CHK();pc+=3;DISPATCH();}
        jfieldID fid=_fid(env,cp,res,idx,cpc,is_s);if(!fid){CHK();pc+=3;DISPATCH();}
        char ft=cp[idx].data.ref.descriptor[0];
        if(is_g){jobject o=is_s?NULL:POP_L();switch(ft){
            case'I':case'Z':case'B':case'S':case'C':PUSH_I(is_s?(*env)->GetStaticIntField(env,fc,fid):(*env)->GetIntField(env,o,fid));break;
            case'J':PUSH_J(is_s?(*env)->GetStaticLongField(env,fc,fid):(*env)->GetLongField(env,o,fid));break;
            case'F':PUSH_F(is_s?(*env)->GetStaticFloatField(env,fc,fid):(*env)->GetFloatField(env,o,fid));break;
            case'D':PUSH_D(is_s?(*env)->GetStaticDoubleField(env,fc,fid):(*env)->GetDoubleField(env,o,fid));break;
            default:PUSH_L(is_s?(*env)->GetStaticObjectField(env,fc,fid):(*env)->GetObjectField(env,o,fid));break;}}
        else{switch(ft){
            case'I':case'Z':case'B':case'S':case'C':{jint v=POP_I();jobject o=is_s?NULL:POP_L();if(is_s)(*env)->SetStaticIntField(env,fc,fid,v);else(*env)->SetIntField(env,o,fid,v);break;}
            case'J':{jlong v=POP_J();jobject o=is_s?NULL:POP_L();if(is_s)(*env)->SetStaticLongField(env,fc,fid,v);else(*env)->SetLongField(env,o,fid,v);break;}
            case'F':{jfloat v=POP_F();jobject o=is_s?NULL:POP_L();if(is_s)(*env)->SetStaticFloatField(env,fc,fid,v);else(*env)->SetFloatField(env,o,fid,v);break;}
            case'D':{jdouble v=POP_D();jobject o=is_s?NULL:POP_L();if(is_s)(*env)->SetStaticDoubleField(env,fc,fid,v);else(*env)->SetDoubleField(env,o,fid,v);break;}
            default:{jobject v=POP_L();jobject o=is_s?NULL:POP_L();if(is_s)(*env)->SetStaticObjectField(env,fc,fid,v);else(*env)->SetObjectField(env,o,fid,v);break;}}}
        pc+=3;DISPATCH();}

    /* invoke */
    TARGET(0xb6): TARGET(0xb7): TARGET(0xb8): TARGET(0xb9): {
        uint8_t op=c[pc];
        uint16_t idx=RU16(c,pc+1);int is_s=(op==0xb8);int adv=(op==0xb9)?5:3;
        /* Inline encrypted constant lookup for jnic$native_* methods */
        if (is_s && idx<cpc && (cp[idx].tag==JVM_CP_METHODREF||cp[idx].tag==JVM_CP_IFACEREF)) {
            const char *_mn = cp[idx].data.ref.name;
            if (_mn[0]=='j' && _mn[1]=='n' && _mn[2]=='i' && _mn[3]=='c' && _mn[4]=='$') {
                /* jnic$native_* — supports both (J)X single-key and (JJ)X dual-key */
                const char *_desc = cp[idx].data.ref.descriptor;
                int _dual = (_desc[1]=='J' && _desc[2]=='J'); /* (JJ) = dual-key */
                jlong _decode_key = _dual ? POP_J() : 0; /* second param if dual-key */
                jlong _ek = POP_J(); /* first param: lookup key */
                int64_t _combined = _ek ^ _decode_key ^ __runtime_master_key;
                if (strcmp(_mn, "jnic$native_string") == 0) {
                    extern EncStr _enc_strs[];
                    extern const uint8_t _sbox_inv[];
                    extern int64_t __runtime_master_key;
                    static jobject _sc[256]; static int8_t _scc[256];
                    jobject _sr = NULL;
                    int64_t _dk64 = _combined;
                    uint8_t *_dk = (uint8_t*)&_dk64;
                    uint8_t *_mk = (uint8_t*)&__runtime_master_key;
                    for (int _i=0; _enc_strs[_i].enc!=NULL; _i++) {
                        if (_enc_strs[_i].key == _ek) {
                            if (_i < 256 && _scc[_i]) { _sr = _sc[_i]; break; }
                            int32_t _sl = _enc_strs[_i].len;
                            char *_dec = (char*)malloc(_sl+1);
                            for (int _j=0;_j<_sl;_j++) {
                                uint8_t v = (uint8_t)_enc_strs[_i].enc[_j];
                                for (int r=3;r>=0;r--) { v-=_mk[r%8]; v^=_dk[(_j+r)%8]; v=(v>>3)|(v<<5); v=_sbox_inv[v]; }
                                _dec[_j] = v;
                            }
                            _dec[_sl]=0;
                            _sr = (*env)->NewStringUTF(env, _dec);
                            free(_dec);
                            if (_i<256){_sc[_i]=(*env)->NewGlobalRef(env,_sr);_scc[_i]=1;}
                            break;
                        }
                    }
                    PUSH_L(_sr);
                } else if (strcmp(_mn, "jnic$native_int") == 0) {
                    extern EncNum _enc_nums[];
                    extern const uint8_t _sbox_inv[];
                    int64_t _dk64=_combined; uint8_t*_dk=(uint8_t*)&_dk64; uint8_t*_mk=(uint8_t*)&__runtime_master_key;
                    jint _iv = 0;
                    for (int _i=0; _enc_nums[_i].key!=0||_enc_nums[_i].enc_val!=0; _i++) {
                        if (_enc_nums[_i].key==_ek && _enc_nums[_i].kind==0) {
                            uint8_t*ev=(uint8_t*)&_enc_nums[_i].enc_val; uint8_t d[4];
                            for(int j=0;j<4;j++){uint8_t v=ev[j];for(int r=3;r>=0;r--){v-=_mk[r%8];v^=_dk[(j+r)%8];v=(v>>3)|(v<<5);v=_sbox_inv[v];}d[j]=v;}
                            memcpy(&_iv,d,4); break;
                        }
                    }
                    PUSH_I(_iv);
                } else if (strcmp(_mn, "jnic$native_long") == 0) {
                    extern EncNum _enc_nums[];
                    extern const uint8_t _sbox_inv[];
                    int64_t _dk64=_combined; uint8_t*_dk=(uint8_t*)&_dk64; uint8_t*_mk=(uint8_t*)&__runtime_master_key;
                    jlong _lv = 0;
                    for (int _i=0; _enc_nums[_i].key!=0||_enc_nums[_i].enc_val!=0; _i++) {
                        if (_enc_nums[_i].key==_ek && _enc_nums[_i].kind==1) {
                            uint8_t*ev=(uint8_t*)&_enc_nums[_i].enc_val; uint8_t d[8];
                            for(int j=0;j<8;j++){uint8_t v=ev[j];for(int r=3;r>=0;r--){v-=_mk[r%8];v^=_dk[(j+r)%8];v=(v>>3)|(v<<5);v=_sbox_inv[v];}d[j]=v;}
                            memcpy(&_lv,d,8); break;
                        }
                    }
                    PUSH_J(_lv);

                } else if (strcmp(_mn, "jnic$native_float") == 0) {
                    extern EncNum _enc_nums[];
                    extern const uint8_t _sbox_inv[];
                    int64_t _dk64=_combined; uint8_t*_dk=(uint8_t*)&_dk64; uint8_t*_mk=(uint8_t*)&__runtime_master_key;
                    jfloat _fv = 0.0f;
                    for (int _i=0; _enc_nums[_i].key!=0||_enc_nums[_i].enc_val!=0; _i++) {
                        if (_enc_nums[_i].key==_ek && _enc_nums[_i].kind==2) {
                            uint8_t*ev=(uint8_t*)&_enc_nums[_i].enc_val; uint8_t d[4];
                            for(int j=0;j<4;j++){uint8_t v=ev[j];for(int r=3;r>=0;r--){v-=_mk[r%8];v^=_dk[(j+r)%8];v=(v>>3)|(v<<5);v=_sbox_inv[v];}d[j]=v;}
                            memcpy(&_fv,d,4); break;
                        }
                    }
                    PUSH_F(_fv);
                } else if (strcmp(_mn, "jnic$native_double") == 0) {
                    extern EncNum _enc_nums[];
                    extern const uint8_t _sbox_inv[];
                    int64_t _dk64=_combined; uint8_t*_dk=(uint8_t*)&_dk64; uint8_t*_mk=(uint8_t*)&__runtime_master_key;
                    jdouble _dv = 0.0;
                    for (int _i=0; _enc_nums[_i].key!=0||_enc_nums[_i].enc_val!=0; _i++) {
                        if (_enc_nums[_i].key==_ek && _enc_nums[_i].kind==3) {
                            uint8_t*ev=(uint8_t*)&_enc_nums[_i].enc_val; uint8_t d[8];
                            for(int j=0;j<8;j++){uint8_t v=ev[j];for(int r=3;r>=0;r--){v-=_mk[r%8];v^=_dk[(j+r)%8];v=(v>>3)|(v<<5);v=_sbox_inv[v];}d[j]=v;}
                            memcpy(&_dv,d,8); break;
                        }
                    }
                    PUSH_D(_dv);
                } else { /* unknown jnic$ method, push keys back and fall through */
                    PUSH_J(_ek);
                    if (_dual) PUSH_J(_decode_key);
                    goto _normal_invoke;
                }
                pc+=adv;DISPATCH();
            }
        }
        _normal_invoke:;
        jmethodID mid=_mid(env,cp,res,idx,cpc,is_s);if(!mid){CHK();pc+=adv;DISPATCH();}
        jclass mc=res[idx].clazz;const char*md=cp[idx].data.ref.descriptor;
        char pt[64];int pn=_parse_args(md,pt,64);jvalue ma[64];
        for(int i=pn-1;i>=0;i--){switch(pt[i]){case'J':ma[i].j=POP_J();break;case'D':ma[i].d=POP_D();break;case'F':ma[i].f=POP_F();break;case'L':ma[i].l=POP_L();break;default:ma[i].i=POP_I();break;}}
        jobject obj=is_s?NULL:POP_L();char rc=_ret_ch(md);
        if(is_s){switch(rc){case'V':(*env)->CallStaticVoidMethodA(env,mc,mid,ma);break;case'J':PUSH_J((*env)->CallStaticLongMethodA(env,mc,mid,ma));break;case'F':PUSH_F((*env)->CallStaticFloatMethodA(env,mc,mid,ma));break;case'D':PUSH_D((*env)->CallStaticDoubleMethodA(env,mc,mid,ma));break;case'L':case'[':PUSH_L((*env)->CallStaticObjectMethodA(env,mc,mid,ma));break;default:PUSH_I((*env)->CallStaticIntMethodA(env,mc,mid,ma));break;}}
        else if(op==0xb7){switch(rc){case'V':(*env)->CallNonvirtualVoidMethodA(env,obj,mc,mid,ma);break;case'J':PUSH_J((*env)->CallNonvirtualLongMethodA(env,obj,mc,mid,ma));break;case'F':PUSH_F((*env)->CallNonvirtualFloatMethodA(env,obj,mc,mid,ma));break;case'D':PUSH_D((*env)->CallNonvirtualDoubleMethodA(env,obj,mc,mid,ma));break;case'L':case'[':PUSH_L((*env)->CallNonvirtualObjectMethodA(env,obj,mc,mid,ma));break;default:PUSH_I((*env)->CallNonvirtualIntMethodA(env,obj,mc,mid,ma));break;}}
        else{switch(rc){case'V':(*env)->CallVoidMethodA(env,obj,mid,ma);break;case'J':PUSH_J((*env)->CallLongMethodA(env,obj,mid,ma));break;case'F':PUSH_F((*env)->CallFloatMethodA(env,obj,mid,ma));break;case'D':PUSH_D((*env)->CallDoubleMethodA(env,obj,mid,ma));break;case'L':case'[':PUSH_L((*env)->CallObjectMethodA(env,obj,mid,ma));break;default:PUSH_I((*env)->CallIntMethodA(env,obj,mid,ma));break;}}
        CHK();pc+=adv;DISPATCH();}

    /* invokedynamic - string concat optimized */
    TARGET(0xba): {uint16_t idx=RU16(c,pc+1);
        if(idx<cpc&&cp[idx].tag==JVM_CP_INVOKEDYN){
            const char*nm=cp[idx].data.indy.name;const char*md=cp[idx].data.indy.descriptor;
            char pt[64];int pn=_parse_args(md,pt,64);jvalue ma[64];
            for(int i=pn-1;i>=0;i--){switch(pt[i]){case'J':ma[i].j=POP_J();break;case'D':ma[i].d=POP_D();break;case'F':ma[i].f=POP_F();break;case'L':ma[i].l=POP_L();break;default:ma[i].i=POP_I();break;}}
            if(strcmp(nm,"makeConcatWithConstants")==0){
                /* Always use StringBuilder */
                jobject sb = (*env)->NewObject(env, _sb_cls, _sb_init);
                const char *recipe = cp[idx].data.indy.recipe;
                int ai = 0;
                if (recipe && recipe[0]) {
                    const char *p = recipe;
                    while (*p) {
                        if (*p == '\x01') {
                            if (ai < pn) {
                                switch(pt[ai]){
                                case'J':(*env)->CallObjectMethod(env,sb,_sb_app_j,ma[ai].j);break;
                                case'F':{jvalue fa;fa.d=(jdouble)ma[ai].f;(*env)->CallObjectMethod(env,sb,_sb_app_o,
                                    (*env)->CallStaticObjectMethod(env,(*env)->FindClass(env,"java/lang/Float"),
                                    (*env)->GetStaticMethodID(env,(*env)->FindClass(env,"java/lang/Float"),"valueOf","(F)Ljava/lang/Float;"),ma[ai].f));break;}
                                case'D':(*env)->CallObjectMethod(env,sb,_sb_app_o,
                                    (*env)->CallStaticObjectMethod(env,(*env)->FindClass(env,"java/lang/Double"),
                                    (*env)->GetStaticMethodID(env,(*env)->FindClass(env,"java/lang/Double"),"valueOf","(D)Ljava/lang/Double;"),ma[ai].d));break;
                                case'L':(*env)->CallObjectMethod(env,sb,_sb_app_s,(jstring)ma[ai].l);break;
                                default:(*env)->CallObjectMethod(env,sb,_sb_app_i,ma[ai].i);break;}
                                ai++;
                            }
                            p++;
                        } else {
                            const char *start = p;
                            while (*p && *p != '\x01') p++;
                            int slen=(int)(p-start);char tmp[512];int cl=slen<511?slen:511;
                            memcpy(tmp,start,cl);tmp[cl]=0;
                            jstring lit=(*env)->NewStringUTF(env,tmp);
                            (*env)->CallObjectMethod(env,sb,_sb_app_s,lit);
                            (*env)->DeleteLocalRef(env,lit);
                        }
                    }
                } else {
                    for(int i=0;i<pn;i++){
                        switch(pt[i]){
                        case'J':(*env)->CallObjectMethod(env,sb,_sb_app_j,ma[i].j);break;
                        case'L':(*env)->CallObjectMethod(env,sb,_sb_app_o,ma[i].l);break;
                        default:(*env)->CallObjectMethod(env,sb,_sb_app_i,ma[i].i);break;}
                    }
                }
                jobject r=(*env)->CallObjectMethod(env,sb,_sb_ts);
                (*env)->DeleteLocalRef(env,sb);
                PUSH_L(r);}
            else{char rc=_ret_ch(md);if(rc!='V')PUSH_L(NULL);}}
        CHK();pc+=5;DISPATCH();}

    /* object ops */
    TARGET(0xbb): {uint16_t idx=RU16(c,pc+1);jclass cc2=_cls(env,cp,res,idx,cpc);PUSH_L(cc2?(*env)->AllocObject(env,cc2):NULL);CHK();pc+=3;DISPATCH();}
    TARGET(0xbc): {uint8_t t=c[pc+1];jint n=POP_I();jarray a=NULL;switch(t){case 4:a=(jarray)(*env)->NewBooleanArray(env,n);break;case 5:a=(jarray)(*env)->NewCharArray(env,n);break;case 6:a=(jarray)(*env)->NewFloatArray(env,n);break;case 7:a=(jarray)(*env)->NewDoubleArray(env,n);break;case 8:a=(jarray)(*env)->NewByteArray(env,n);break;case 9:a=(jarray)(*env)->NewShortArray(env,n);break;case 10:a=(jarray)(*env)->NewIntArray(env,n);break;case 11:a=(jarray)(*env)->NewLongArray(env,n);break;default:break;}PUSH_L(a);pc+=2;DISPATCH();}
    TARGET(0xbd): {uint16_t idx=RU16(c,pc+1);jint n=POP_I();jclass cc2=_cls(env,cp,res,idx,cpc);PUSH_L(cc2?(*env)->NewObjectArray(env,n,cc2,NULL):NULL);pc+=3;DISPATCH();}
    TARGET(0xbe): {jarray a=(jarray)POP_L();PUSH_I((*env)->GetArrayLength(env,a));pc++;DISPATCH();}
    TARGET(0xbf): {jobject e=POP_L();(*env)->Throw(env,(jthrowable)e);goto _exc;}
    TARGET(0xc0): {uint16_t idx=RU16(c,pc+1);jobject o=stk[sp-1].l;if(o){jclass cc2=_cls(env,cp,res,idx,cpc);if(cc2&&!(*env)->IsInstanceOf(env,o,cc2)){jclass cce=(*env)->FindClass(env,"java/lang/ClassCastException");(*env)->ThrowNew(env,cce,"");goto _exc;}}pc+=3;DISPATCH();}
    TARGET(0xc1): {uint16_t idx=RU16(c,pc+1);jobject o=POP_L();if(!o)PUSH_I(0);else{jclass cc2=_cls(env,cp,res,idx,cpc);PUSH_I(cc2&&(*env)->IsInstanceOf(env,o,cc2)?1:0);}pc+=3;DISPATCH();}
    TARGET(0xc2): {jobject o=POP_L();(*env)->MonitorEnter(env,o);pc++;DISPATCH();}
    TARGET(0xc3): {jobject o=POP_L();(*env)->MonitorExit(env,o);pc++;DISPATCH();}
    TARGET(0xc4): {uint8_t w=c[pc+1];uint16_t wi=RU16(c,pc+2);switch(w){case 0x15:PUSH_I(loc[wi].i);pc+=4;break;case 0x16:PUSH_J(loc[wi].j);pc+=4;break;case 0x17:PUSH_F(loc[wi].f);pc+=4;break;case 0x18:PUSH_D(loc[wi].d);pc+=4;break;case 0x19:PUSH_L(loc[wi].l);pc+=4;break;case 0x36:loc[wi].i=POP_I();pc+=4;break;case 0x37:loc[wi].j=POP_J();pc+=4;break;case 0x38:loc[wi].f=POP_F();pc+=4;break;case 0x39:loc[wi].d=POP_D();pc+=4;break;case 0x3a:loc[wi].l=POP_L();pc+=4;break;case 0x84:loc[wi].i+=RI16(c,pc+4);pc+=6;break;default:pc+=4;break;}DISPATCH();}
    TARGET(0xc5): {uint16_t idx=RU16(c,pc+1);uint8_t dm=c[pc+3];jint sz[8];for(int i=dm-1;i>=0;i--)sz[i]=POP_I();jclass cc2=_cls(env,cp,res,idx,cpc);PUSH_L(cc2?(*env)->NewObjectArray(env,sz[0],cc2,NULL):NULL);pc+=4;DISPATCH();}
    TARGET(0xc6): {jobject v=POP_L();if(!v)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}
    TARGET(0xc7): {jobject v=POP_L();if(v)pc+=RI16(c,pc+1);else pc+=3;DISPATCH();}

    /* === Superinstructions === */
    TARGET(0xfe): { /* SUPER_IINC_GOTO: iinc + goto backward */
        uint8_t idx = c[pc+1];
        loc[idx].i += (int8_t)c[pc+2];
        pc += (int16_t)((c[pc+3]<<8)|c[pc+4]);
        DISPATCH();
    }
    TARGET(0xfd): { /* SUPER_ILOAD_CMP: iload + iload + if_icmpXX */
        jint a = loc[c[pc+1]].i;
        jint b = loc[c[pc+2]].i;
        uint8_t cmp = c[pc+3];
        int16_t off = (int16_t)((c[pc+4]<<8)|c[pc+5]);
        int taken = 0;
        switch(cmp) {
            case 0: taken = (a < b); break;
            case 1: taken = (a >= b); break;
            case 2: taken = (a > b); break;
            case 3: taken = (a <= b); break;
            case 4: taken = (a == b); break;
            case 5: taken = (a != b); break;
        }
        if (taken) pc += off; else pc += 6;
        DISPATCH();
    }

    /* default/unhandled opcode */
#ifdef __GNUC__
    OP_DEFAULT: pc++; DISPATCH();
#else
    default: pc++; break;
    }
    continue;
#endif

_exc: {
    jthrowable exc=(*env)->ExceptionOccurred(env);if(!exc)goto _done;(*env)->ExceptionClear(env);
    int handled=0;
    for(uint16_t ei=0;ei<exc_count;ei++){uint32_t eo=ei*8;uint16_t spc=RU16(exc_tbl,eo),epc=RU16(exc_tbl,eo+2),hpc=RU16(exc_tbl,eo+4),ct=RU16(exc_tbl,eo+6);
        if(pc>=spc&&pc<epc){if(ct==0||(ct<cpc&&cp[ct].tag==JVM_CP_CLASS)){
            if(ct==0||(*env)->IsInstanceOf(env,exc,_cls(env,cp,res,ct,cpc))){sp=0;PUSH_L(exc);pc=hpc;handled=1;break;}}}}
    if(!handled){(*env)->Throw(env,exc);goto _done;}
#ifdef __GNUC__
    DISPATCH();
#else
    continue;
#endif
    }

#ifndef __GNUC__
    }
#endif

_done:
    if(stk!=stk_buf)free(stk);
    if(loc!=loc_buf)free(loc);
    return result;
}

