# JNIC-zig

JVM 字节码 Native 化保护工具，使用 Zig 编写。通过注解驱动，将 Java/Kotlin 方法转换为 native 实现，在 C 层执行原始逻辑，防止反编译。

## 功能

- **字节码 Native 化** — `@Native` 注解驱动，将方法体抽取到 native 库
- **字符串/数字加密** — `@StringEncrypt` / `@NumberEncrypt`，多轮 Feistel + 动态密钥
- **数组加密** — `@ArrayObfuscation`，大数组 blob 加密 + 直接 C 内存访问优化
- **纯计算 Transpiler** — 无 JNI 的方法直接编译为优化 C 代码（-O3 -ffast-math）
- **JNI Transpiler** — 有字段/方法调用的循环也可 transpile，内联 cached JNI ID
- **Computed goto 解释器** — GCC `&&label` 扩展消除 switch 开销
- **超级指令** — `iinc+goto` / `iload+iload+if_icmp` 合并为单条伪指令
- **自动加载** — DLL 打包进 JAR，运行时自动解压加载（NativeLoader）
- **符号混淆** — DLL 导出符号随机化为 IDA 风格（`sub_180005D70`）
- **反调试** — IsDebuggerPresent / PEB / ptrace / 完整性校验
- **动态密钥** — 每次构建唯一 salt → master_key，静态逆向无效
- **双密钥模式** — `enchanted_encryption=true` 时 decode_key 隔离在 JAR
- **注解清除** — `remove_jnic_annotation=true` 自动删除注解及 class 文件

## 注解包

```
master.koitoyuu.jnic.Native            — 类级：native 化所有方法
master.koitoyuu.jnic.StringEncrypt     — 类/方法/字段：字符串加密
master.koitoyuu.jnic.NumberEncrypt     — 类/方法/字段：数字常量加密
master.koitoyuu.jnic.ArrayObfuscation  — 类/方法/字段：数组 blob 加密
```

## 快速开始

### 1. 添加注解

```java
import master.koitoyuu.jnic.*;

@Native
@StringEncrypt
@NumberEncrypt
@ArrayObfuscation
public class MyClass {
    private static final int[] TABLE = {0x63, 0x7C, 0x77, ...};

    public static void main(String[] args) {
        System.out.println("Hello");
    }
}
```

### 2. 配置 `config.toml`

```toml
[jnic-zig]
watermark = "JNIC-zig"
use_ffm = false
anti_debug = true
renamer = true
remove_jnic_annotation = true
fast_math = true
enchanted_encryption = false
input_jar = "./input.jar"
output_jar = "./out.jar"
```

### 3. 运行

```bash
# 混淆
zig build run

# 编译 native 库
zig cc -shared -o jnic_native.dll native_jni.c ^
    -I"%JAVA_HOME%/include" -I"%JAVA_HOME%/include/win32" -O3 -ffast-math

# 打包 DLL 进 JAR
mkdir master\koitoyuu\jnic
copy jnic_native.dll master\koitoyuu\jnic\
jar uf out.jar master/koitoyuu/jnic/jnic_native.dll

# 运行（无需手动 loadLibrary）
java -jar out.jar
```

## 性能基准测试

环境：Windows 11, Java 26, Zig 0.16, i5-11300H (10 次取平均)

### PureBench（纯计算：int/long/bitwise/nested 循环）

| | JVM (无混淆) | JNIC (transpiled -O3) | 比率 |
|---|---|---|---|
| 平均耗时 | 43.2ms | **15.5ms** | **0.36x (快 2.8 倍)** |

> 纯计算方法走 transpile 路径，直接编译为 C 并启用 -O3 + -ffast-math，性能超越 JVM JIT。

### Calc（递归 + try/catch + 加密常量）

| | JVM (无混淆) | JNIC (interpreter) | 比率 |
|---|---|---|---|
| 平均耗时 | 31.9ms | 282.1ms | 8.8x |

> 递归密集型 + 异常表方法走解释器路径，内联加密常量解密。

### LoopBench（for/while/nested/string concat 循环）

| | JVM (无混淆) | JNIC (interpreter + concat) | 比率 |
|---|---|---|---|
| 平均耗时 | 17.0ms | 40.7ms | 2.4x |

> 包含 invokedynamic 字符串拼接的循环走解释器，computed goto + 超级指令优化。

### ArrayBench（数组 blob 加密 + 直接 C 内存访问）

| | 逐元素 JNI 访问 | 直接 C 数组访问 | 提升 |
|---|---|---|---|
| 1M 次迭代 | 1720ms | **190ms** | **9x** |

> `@ArrayObfuscation` 数组加密后，transpiled 方法通过 `_narr_N[]` 直接读取 C 缓冲区，零 JNI 开销。

### 总结

| 方法类型 | 保护方式 | 性能开销 |
|---|---|---|
| 纯计算（无 JNI） | Transpile → C (-O3) | **负开销（比 JVM 快）** |
| 循环 + 字段/方法 | Interpreter + computed goto | 2-3x |
| 递归 + 异常 | Interpreter | 8-9x |
| 数组访问 | Blob 加密 + C 缓冲区直读 | 17x（vs JVM JIT） |

## 架构

```
input.jar → [解析 class] → [检测注解] → [加密常量] → [数组 blob]
         → [nativize 方法] → [生成 C 代码] → output.jar + native_jni.c

native_jni.c 包含：
├── jvm_interp.c    — Computed goto 字节码解释器
├── transpiled 方法  — 纯 C 代码（无解释器开销）
├── 加密表          — Feistel 加密的字符串/数字/数组 blob
├── S-Box           — 每次构建随机生成
├── anti-debug      — 完整性校验 + 调试器检测
└── JNI_OnLoad      — 批量 RegisterNatives + 密钥初始化
```

