package master.koitoyuu;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * 字符串加密注解。
 * 在类上使用：类中所有方法和字段的字符串常量将被抽取到 native 层加密存储。
 * 在方法上使用：仅该方法内的字符串常量被加密。
 * 在字段上使用：仅该字段的初始化字符串被加密。
 *
 * 加密后的字符串通过 yuri$native_string(long key) 在运行时解密并缓存。
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD})
public @interface StringEncrypt {
}
