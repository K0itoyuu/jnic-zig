import master.koitoyuu.jnic.Native;

@Native
public class QuickTest {
    public static int add(int a, int b) {
        return a + b;
    }

    public static long factorial(int n) {
        long result = 1;
        for (int i = 2; i <= n; i++) {
            result *= i;
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println("add(3,4) = " + add(3, 4));
        System.out.println("factorial(10) = " + factorial(10));

        // Benchmark add loop
        long start = System.currentTimeMillis();
        int sum = 0;
        for (int i = 0; i < 1000000; i++) {
            sum = add(sum, 1);
        }
        long elapsed = System.currentTimeMillis() - start;
        System.out.println("1M add calls: " + elapsed + "ms, sum=" + sum);
    }
}
