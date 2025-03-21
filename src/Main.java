import java.io.File;
import java.io.IOException;
import java.util.Objects;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {

    public static void main(String[] args) throws IOException {
        System.out.println(Main.class.getResource("resources"));
        System.out.println(Main.class.getResource("resources/test.log"));
        System.err.println(Objects.requireNonNull(Main.class.getResource("resources")).getPath());
        File file = new File(Objects.requireNonNull(Main.class.getResource("resources")).getPath() + "/aarch64-linux-android/libc++_shared.so");
        System.err.println(file.getAbsoluteFile());
        ReadElf re = new ReadElf(file);
        ReadElf.Symbol symbol = re.getSymbol("use_face");
        System.err.println("libc++_shared.so " + " Symbol Check = " + symbol);
        ReadElf.Symbol dynamicSymbol = re.getDynamicSymbol("use_face");
        System.err.println("libc++_shared.so " + " DynamicSymbol Check = " + dynamicSymbol);
        re.close();
    }
}