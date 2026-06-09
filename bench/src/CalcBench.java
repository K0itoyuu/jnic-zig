import master.koitoyuu.jnic.Native;

@Native
public class CalcBench {
    public static int count = 0;

    public static void runAll() {
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; i++) {
            call(100);
            runAdd();
        }
        System.out.println("Calc (no str): " + (System.currentTimeMillis() - start) + "ms");
        if (count != 20000)
            throw new RuntimeException("[ERROR]: count=" + count);
    }

    private static void call(int i) {
        if (i == 0) count++;
        else call(i - 1);
    }

    private static void runAdd() {
        double i = 0d;
        while (i < 100.1d) {
            i += 0.99d;
        }
        count++;
    }

    public static void main(String[] args) {
        runAll();
    }
}
