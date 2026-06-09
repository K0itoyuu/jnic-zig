package pack.tests.bench;

import master.koitoyuu.jnic.Native;

@Native
public class LoopBench {
    public static void main(String[] args) {
        System.loadLibrary("yurijvm_native");
        runAll();
    }

    public static void runAll() {
        System.out.println("=== LoopBench ===");
        long t1 = benchForLoop();
        long t2 = benchWhileLoop();
        long t3 = benchStringConcat();
        long t4 = benchNestedLoop();
        System.out.println("For loop (1M iter):     " + t1 + "ms");
        System.out.println("While loop (1M iter):   " + t2 + "ms");
        System.out.println("String concat (1K):     " + t3 + "ms");
        System.out.println("Nested loop (1K*1K):    " + t4 + "ms");
        System.out.println("Total: " + (t1 + t2 + t3 + t4) + "ms");
    }

    private static long benchForLoop() {
        long start = System.currentTimeMillis();
        int sum = 0;
        for (int i = 0; i < 1000000; i++) {
            sum += i;
        }
        long elapsed = System.currentTimeMillis() - start;
        if (sum != 1783293664) throw new RuntimeException("for loop error: " + sum);
        return elapsed;
    }

    private static long benchWhileLoop() {
        long start = System.currentTimeMillis();
        int count = 0;
        int i = 0;
        while (i < 1000000) {
            count += (i % 7 == 0) ? 1 : 0;
            i++;
        }
        long elapsed = System.currentTimeMillis() - start;
        if (count != 142858) throw new RuntimeException("while loop error: " + count);
        return elapsed;
    }

    private static long benchStringConcat() {
        long start = System.currentTimeMillis();
        String s = "";
        for (int i = 0; i < 1000; i++) {
            s += "a";
        }
        long elapsed = System.currentTimeMillis() - start;
        if (s.length() != 1000) throw new RuntimeException("string error: " + s.length());
        return elapsed;
    }

    private static long benchNestedLoop() {
        long start = System.currentTimeMillis();
        int sum = 0;
        for (int i = 0; i < 1000; i++) {
            for (int j = 0; j < 1000; j++) {
                sum += i * j;
            }
        }
        long elapsed = System.currentTimeMillis() - start;
        if (sum != 392146832) throw new RuntimeException("nested error: " + sum);
        return elapsed;
    }
}
