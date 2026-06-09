import master.koitoyuu.jnic.Native;

/**
 * Benchmark for transpiled JNI loop performance.
 * No invokedynamic, no try/catch — pure loops with field access + array ops.
 */
@Native
public class JniLoopBench {
    private static int counter = 0;
    private static long accumulator = 0;
    private static double sum = 0.0;

    public static void main(String[] args) {
        // Warmup
        fieldLoop(100000);
        arrayLoop(100000);
        mixedLoop(100000);
        counter = 0; accumulator = 0; sum = 0.0;

        long t0 = System.nanoTime();
        fieldLoop(10000000);
        long t1 = System.nanoTime();
        arrayLoop(10000000);
        long t2 = System.nanoTime();
        mixedLoop(5000000);
        long t3 = System.nanoTime();
        nestedFieldLoop(3000, 3000);
        long t4 = System.nanoTime();

        printResult("Field loop (10M)", t0, t1, counter);
        printResult("Array loop (10M)", t1, t2, accumulator);
        printResult("Mixed loop (5M)", t2, t3, sum);
        printResult("Nested field (3K*3K)", t3, t4, counter);
    }

    /** Loop incrementing a static field — getstatic + add + putstatic per iteration */
    public static void fieldLoop(int n) {
        for (int i = 0; i < n; i++) {
            counter = counter + 1;
        }
    }

    /** Loop summing an int array — array load + arithmetic per iteration */
    public static void arrayLoop(int n) {
        int[] arr = new int[1024];
        for (int i = 0; i < 1024; i++) arr[i] = i * 7;
        long total = 0;
        for (int i = 0; i < n; i++) {
            total += arr[i & 1023];
        }
        accumulator = total;
    }

    /** Loop with field read + floating point — getstatic + double arithmetic */
    public static void mixedLoop(int n) {
        double s = 0.0;
        for (int i = 0; i < n; i++) {
            s += (double)(counter + i) * 0.001;
        }
        sum = s;
    }

    /** Nested loop with field writes */
    public static void nestedFieldLoop(int outer, int inner) {
        for (int i = 0; i < outer; i++) {
            for (int j = 0; j < inner; j++) {
                counter = counter + 1;
            }
        }
    }

    private static void printResult(String name, long start, long end, long val) {
        long ms = (end - start) / 1000000;
        System.out.print(name);
        System.out.print(": ");
        System.out.print(ms);
        System.out.print("ms  v=");
        System.out.println(val);
    }

    private static void printResult(String name, long start, long end, int val) {
        printResult(name, start, end, (long)val);
    }

    private static void printResult(String name, long start, long end, double val) {
        long ms = (end - start) / 1000000;
        System.out.print(name);
        System.out.print(": ");
        System.out.print(ms);
        System.out.print("ms  v=");
        System.out.println(val);
    }
}
