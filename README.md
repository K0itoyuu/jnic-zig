# JNIC-zig

JVM 字节码 Native 化工具，使用 Zig 编写。将带有 `@master.koitoyuu.Native` 注解的 Java/Kotlin 类方法转换为 native 实现，通过嵌入式字节码解释器在 C 层执行原始逻辑，防止反编译。

## 功能

- **字节码 Native 化** — 自动检测 `@Native` 注解，将方法体抽取到 native 库中
- **嵌入式 JVM 解释器** — 生成的 C 代码包含完整的 JVM 字节码解释器，通过 JNI 回调 Java
- **Main 方法保护** — 自动将 `main` 逻辑抽取到 `yuri$main`，注入 `System.loadLibrary`
- **符号混淆 (Renamer)** — DLL 导出符号随机化为 IDA 风格（`sub_180005D70`）
- **反调试** — 注入 `IsDebuggerPresent` / `ptrace` 检测
- **水印** — 嵌入可追踪的水印字符串
- **JAR-to-JAR** — 输入 JAR，输出保护后的 JAR + native 源码

## 快速开始

### 1. 添加注解

```java
package master.koitoyuu;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface Native {}
```

在需要保护的类或方法上添加 `@Native`：

```java
import master.koitoyuu.Native;

@Native
public class MyClass {
    public static void main(String[] args) {
        // 自动抽取到 yuri$main 并 native 化
    }

    private void secretLogic() {
        // 将变为 native 方法
    }
}
```

### 2. 配置

创建 `config.toml`：

```toml
[jnic-zig]
watermark = "MyApp v1.0"
use_ffm = false
anti_debug = true
renamer = true
input_jar = "./app.jar"
output_jar = "./app-protected.jar"
```

### 3. 运行混淆

```bash
jnic-zig --config config.toml
```

输出：
- `app-protected.jar` — native 化后的 JAR
- `native_jni.c` — 需编译为动态库的 C 源码

### 4. 编译 Native 库

#### Windows

```bash
zig cc -shared -o yurijvm_native.dll native_jni.c ^
    -I"%JAVA_HOME%/include" -I"%JAVA_HOME%/include/win32" -O2
```

#### Linux

```bash
zig cc -shared -fPIC -o libyurijvm_native.so native_jni.c \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/linux" -O2
```

#### macOS

```bash
zig cc -shared -o libyurijvm_native.dylib native_jni.c \
    -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin" -O2
```

### 5. 运行

#### Windows

```bash
java -Xss4m --enable-native-access=ALL-UNNAMED ^
    -Djava.library.path=. -jar app-protected.jar
```

#### Linux / macOS

```bash
java -Xss4m --enable-native-access=ALL-UNNAMED \
    -Djava.library.path=. -jar app-protected.jar
```

## 从源码构建

需要 [Zig 0.16+](https://ziglang.org/download/)：

```bash
zig build -Doptimize=ReleaseFast
```

产物在 `zig-out/bin/jnic-zig`。

## 配置选项

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `watermark` | string | `"JNIC-zig"` | 嵌入到 native 库中的水印字符串 |
| `use_ffm` | bool | `false` | 使用 FFM API (Java 22+) 代替 JNI |
| `anti_debug` | bool | `true` | 注入反调试检测代码 |
| `renamer` | bool | `false` | 随机化 DLL 中的所有符号名 |
| `input_jar` | string | `"./input.jar"` | 输入 JAR 路径 |
| `output_jar` | string | `"./output.jar"` | 输出 JAR 路径 |

## 注意事项

- 含有大量 `String +=` 循环的方法（编译为 `invokedynamic` string concat）在解释器中性能较差，建议排除
- `<init>`、`<clinit>` 不会被 native 化
- 需要 `-Xss4m` 以支持深度递归的 native 方法
- Java 17+ 需要 `--enable-native-access=ALL-UNNAMED`

## 免责声明

本工具仅供学习研究和合法软件保护用途。使用者应确保：

1. 仅对自己拥有合法权利的代码进行保护
2. 不得将本工具用于规避软件授权验证、破解、逆向他人软件等违法行为
3. 不得将本工具用于制作恶意软件、病毒、木马等危害计算机安全的程序
4. 使用本工具所产生的一切后果由使用者自行承担

作者不对因使用本工具造成的任何直接或间接损失承担责任。使用本工具即表示您已阅读并同意上述条款。

## License

Private / All Rights Reserved
