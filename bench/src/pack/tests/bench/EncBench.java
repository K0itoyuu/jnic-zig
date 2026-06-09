package pack.tests.bench;

import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.StringEncrypt;
import master.koitoyuu.jnic.NumberEncrypt;

@Native
@StringEncrypt
@NumberEncrypt
public class EncBench {
    public static int i1 = 114514;
    public static int i2 = 1919810;
    public static int i3 = 65535;
    public static int i4 = 123456789;
    public static int i5 = 999999;

    public static long l1 = 2147483648L;
    public static long l2 = 9876543210L;
    public static long l3 = 1000000000000L;
    public static long l4 = Long.MAX_VALUE;
    public static long l5 = 8848860L;

    public static String s1 = "Hello, World!";
    public static String s2 = "JNIC-zig obfuscator";
    public static String s3 = "The quick brown fox jumps over the lazy dog";
    public static String s4 = "master.koitoyuu.jnic.Native";
    public static String s5 = "加密字符串测试 - Encrypted!";

    public static long run() {
        long start = System.currentTimeMillis();
        System.out.println("=== EncBench ===");
        System.out.println("i1=" + i1 + " i2=" + i2 + " i3=" + i3 + " i4=" + i4 + " i5=" + i5);
        System.out.println("l1=" + l1 + " l2=" + l2 + " l3=" + l3 + " l4=" + l4 + " l5=" + l5);
        System.out.println("s1=" + s1);
        System.out.println("s2=" + s2);
        System.out.println("s3=" + s3);
        System.out.println("s4=" + s4);
        System.out.println("s5=" + s5);
        long elapsed = System.currentTimeMillis() - start;
        System.out.println("EncBench: " + elapsed + "ms");
        return elapsed;
    }

    public static void main(String[] args) {
        run();
    }
}
