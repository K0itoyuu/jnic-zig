package master.koitoyuu;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

/**
 * 标记需要 Native 化的类或方法。
 *
 * 在类上使用：该类所有方法（除 main、构造器、静态初始化块）都将被 native 化。
 * 在方法上使用：仅该方法被 native 化。
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface Native {
}
