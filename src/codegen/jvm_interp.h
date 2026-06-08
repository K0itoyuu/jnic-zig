#ifndef JVM_INTERP_H
#define JVM_INTERP_H

#include <jni.h>
#include <stdint.h>

#define JVM_CP_NONE        0
#define JVM_CP_UTF8        1
#define JVM_CP_INTEGER     3
#define JVM_CP_FLOAT       4
#define JVM_CP_LONG        5
#define JVM_CP_DOUBLE      6
#define JVM_CP_CLASS       7
#define JVM_CP_STRING      8
#define JVM_CP_FIELDREF    9
#define JVM_CP_METHODREF   10
#define JVM_CP_IFACEREF    11
#define JVM_CP_INVOKEDYN   18

#define TAG_INT    0
#define TAG_LONG   1
#define TAG_FLOAT  2
#define TAG_DOUBLE 3
#define TAG_OBJ    4
#define TAG_VOID   5

typedef struct {
    uint8_t tag;
    union {
        const char *utf8;
        int32_t i;
        float f;
        int64_t l;
        double d;
        struct { const char *name; } cls;
        struct { const char *value; } str;
        struct { const char *class_name; const char *name; const char *descriptor; } ref;
        struct { uint16_t bsm_idx; const char *name; const char *descriptor; const char *recipe; } indy;
    } data;
} JvmCpEntry;

/* Pre-resolved references — allocated ONCE at JNI_OnLoad, reused forever */
typedef struct {
    jclass clazz;
    jmethodID method_id;
    jfieldID field_id;
    jobject cached_obj; /* for STRING constants */
    uint8_t resolved;
} JvmResolved;

typedef enum {
    RET_VOID = 0, RET_INT, RET_LONG, RET_FLOAT, RET_DOUBLE, RET_OBJECT
} JvmRetType;

/* Method descriptor for a native-ized method */
typedef struct {
    const uint8_t *code_attr;
    uint32_t code_attr_len;
    const JvmCpEntry *cp;
    uint32_t cp_count;
    JvmResolved *resolved; /* persistent resolution cache */
} JvmMethodCtx;

jvalue jvm_interpret(JNIEnv *env, const JvmMethodCtx *ctx,
                     const jvalue *args, uint16_t arg_count, JvmRetType ret_type);

/* Forward declarations for encrypted constant tables (defined in generated code) */
typedef struct { int64_t key; const char *enc; int32_t len; } EncStr;
typedef struct { int64_t key; int64_t enc_val; int8_t is_long; } EncNum;

#endif
