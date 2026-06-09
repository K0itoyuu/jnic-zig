package pack.tests.bench;

import master.koitoyuu.jnic.Native;
import master.koitoyuu.jnic.NumberEncrypt;

@Native
@NumberEncrypt
public class NumBench {
    public static void main(String[] args) {
        System.loadLibrary("yurijvm_native");
        run();
    }

    public static void run() {
        System.out.println("=== Number Benchmark (Native) ===");

        // int arithmetic
        long t1 = System.currentTimeMillis();
        int sum = 0;
        for (int i = 0; i < 10000000; i++) {
            sum += i * 3 - i / 2 + i % 7;
        }
        t1 = System.currentTimeMillis() - t1;
        System.out.println("Int arith (10M):  " + t1 + "ms");

        // long arithmetic
        long t2 = System.currentTimeMillis();
        long lsum = 0;
        for (long i = 0; i < 5000000; i++) {
            lsum += i * 7 - i / 3;
        }
        t2 = System.currentTimeMillis() - t2;
        System.out.println("Long arith (5M):  " + t2 + "ms");

        // double arithmetic
        long t3 = System.currentTimeMillis();
        double dsum = 0.0;
        for (int i = 0; i < 5000000; i++) {
            dsum += i * 0.99 - i * 0.01;
        }
        t3 = System.currentTimeMillis() - t3;
        System.out.println("Double arith (5M):" + t3 + "ms");

        // bitwise ops
        long t4 = System.currentTimeMillis();
        int bits = 0xDEADBEEF;
        for (int i = 0; i < 10000000; i++) {
            bits = (bits << 1) ^ (bits >> 3) ^ i;
        }
        t4 = System.currentTimeMillis() - t4;
        System.out.println("Bitwise (10M):    " + t4 + "ms");

        System.out.println("Total: " + (t1+t2+t3+t4) + "ms");
    }
}
