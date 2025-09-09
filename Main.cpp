#include "jni.h"
#include <jni.h>
#include <string>
#include "rLogin/Login.h"

int type = 1, utype = 2;

int Register1(JNIEnv *env) {
    JNINativeMethod methods[] = {
            {"native_Check", "(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;",
             (void *) native_Check}};
    jclass clazz = env->FindClass("com/zenin/activity/LoginActivity");
    if (!clazz)
        return -1;

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) != 0)
        return -1;
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    vm->GetEnv((void **) &env, JNI_VERSION_1_6);
    if (Register1(env) != 0)
        return -1;
    return JNI_VERSION_1_6;
}

extern "C"
JNIEXPORT jstring JNICALL
        Java_com_zenin_LoginActivity_activity(JNIEnv *env, jclass clazz) {
if (!memek){
return env->NewStringUTF(
        oxorany("com.zenin.activity.LoginActivity"));
}else{
return env->NewStringUTF(
        oxorany("com.zenin.activity.MainActivity"));
}
}



extern "C"
JNIEXPORT jstring JNICALL
Java_com_zenin_activity_LoginActivity_ziplink(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(oxorany("https://github.com/ZENIN565/YOUTUBEHELP/releases/download/YOUTUBEHELP/"));
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_zenin_activity_MainActivity_exdate(JNIEnv *env, jclass clazz) {
    return env->NewStringUTF(exdate.c_str());
}
