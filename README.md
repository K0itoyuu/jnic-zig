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
| `renamer` | bool | `false` | 随机化 DLL 中的所有符号名（IDA 风格 `sub_180XXXXX`） |
| `remove_native_annotation` | bool | `false` | 混淆后删除所有混淆注解 |
| `input_jar` | string | `"./input.jar"` | 输入 JAR 路径 |
| `output_jar` | string | `"./output.jar"` | 输出 JAR 路径 |

## 性能基准测试

所有测试开启 `@Native` + `@StringEncrypt` + `@NumberEncrypt`，使用 `-O3` 编译 native 库。

### 纯计算方法（自动 Transpile 为 C）

纯计算方法（无方法调用、无对象操作）被直接翻译为等价 C 代码，由 C 编译器 -O3 优化。
`@NumberEncrypt` 加密后的 `int` / `long` / `float` / `double` 常量在 Transpile 路径中会被内联解密为 C 常量，不产生 JNI 回调开销。

| 测试项 | Java JIT | Native (Transpile) | 比率 |
|--------|----------|-------------------|------|
| Int 算术 (10M iter) | 27ms | **3ms** | **9x 更快** |
| Long 算术 (5M iter) | 13ms | **4ms** | **3x 更快** |
| 位运算 (10M iter) | 18ms | **9ms** | **2x 更快** |
| 嵌套循环 (1K×1K) | 4ms | **0ms** | **>4x 更快** |
| **合计** | **62ms** | **16ms** | **3.9x 更快** |

### Float / Double 纯计算（NumberEncrypt + Transpile）

`FloatDoubleBench` 使用 `@Native + @NumberEncrypt`，保护后的 `float` / `double` 常量会先被抽取到 native 加密表，纯计算方法再由 Transpile 生成等价 C 代码。实测 Java JIT 热身后与 Native Transpile 接近，Native 略快；冷启动时 Native 更有优势。

| 测试项 | Java JIT（热身后） | Native (Transpile) | 结论 |
|--------|-------------------|-------------------|------|
| Float 算术 (10M iter) | 约 11-13ms | **11ms** | 接近 |
| Double 算术 (10M iter) | 约 12-15ms | **12ms** | 接近 |
| **合计** | **约 24-28ms** | **23ms** | **Native 略快** |

### 混合方法（解释器 + JNI 回调）

包含方法调用的方法走 JVM 字节码解释器。

| 测试项 | Java JIT | Native (Interpreter) | 比率 |
|--------|----------|---------------------|------|
| For 循环 (1M) | 1ms | 17ms | 17x |
| While 循环 (1M) | 3ms | 27ms | 9x |
| 字符串拼接 (1K次) | 8ms | **3ms** | **2.7x 更快** |
| 嵌套循环 (1K×1K) | 3ms | 19ms | 6x |
| **合计** | **15ms** | **66ms** | **4.4x** |

### 加密常量访问

`@StringEncrypt` / `@NumberEncrypt` 注解的常量在 native 层 XOR 加密存储。`@NumberEncrypt` 支持 `int`、`long`、`float`、`double`；纯计算 Transpile 方法会直接内联解密后的数值，解释器路径会通过 native lookup 解密。

| 测试项 | Java JIT | Native (加密 + 解密) | 比率 |
|--------|----------|---------------------|------|
| 5×int + 5×long + 5×String 字段访问 | 20ms | **1ms** | **20x 更快** |

### 完整 Obfuscator Test Suite

| 测试 | 结果 |
|------|------|
| Test #1: Basics (7项) | 全部 PASS |
| Test #2: Reflects (8项) | 6 PASS, 2 N/A (JDK 兼容) |
| Test #3: Calc benchmark | 393ms (baseline 35ms) |

## 注意事项

- 纯计算方法自动使用 Transpile 模式（性能超越 JIT）
- `@NumberEncrypt` 支持 `int` / `long` / `float` / `double`，但 `<clinit>` 中的静态初始化常量不会被改写，以避免 native 库加载阶段的注册时序问题
- 含 JNI 调用的方法使用解释器模式（约 4-17x，取决于 JNI 调用密度）
- 字符串拼接因 StringBuilder 预缓存优化，反而比 JIT 更快
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
