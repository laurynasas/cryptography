/**
 * Created by Laurynas Tamulevicius on 2/9/18.
 */

import java.io.*;
import java.util.HashMap;
import java.util.Random;

public class TMT1 {
    private HashMap<Integer, Integer> table;
    protected String plainTextFile = "src/tmt1_plain.txt";
    protected int tableChains = 256;
    protected int tableColumns = 256;
    protected String tableName = "src/table.txt";
    protected String cypherTextFile = "src/tmt_encrypted.txt";
    protected String decryptedTextFile = "src/tmt_decrypted.txt";
    protected String decryptedFileRoot = "src/tmt_decrypted";

    public TMT1() {
        this.table = new HashMap<>();
    }

    public static void main(String[] args) throws FileNotFoundException {
        TMT1 tmt1 = new TMT1();
        int plainTextBlock = tmt1.getPlainTextBlock(tmt1.plainTextFile);

        tmt1.generateTable(plainTextBlock, tmt1.tableChains, tmt1.tableColumns);
        tmt1.saveTable(tmt1.tableName);
    }


    /**
     * Method to get first block of a plain text
     */
    protected int getPlainTextBlock(String filename) {
        String line;
        try {
            FileReader fileReader = new FileReader(filename);
            BufferedReader bufferedReader =
                    new BufferedReader(fileReader);

            if ((line = bufferedReader.readLine()) != null) {
                bufferedReader.close();
                return Hex16.convert(line);
            } else {
                throw new NullPointerException("The file is empty!");
            }

        } catch (FileNotFoundException ex) {
            System.out.println(
                    "Unable to open file '" + filename + "'");
            System.exit(1);
        } catch (IOException ex) {
            System.out.println("Error reading file '" + filename + "'");
            System.exit(1);

        }
        return -1;

    }


    /**
     * Renders given number of chains (rows) which have given number of columns
     * and store only the first and last chain entries
     */
    protected void generateTable(int plainText, int rows, int columns) {
        table = new HashMap<>();
        Random rand = new Random();

        for (int i = 0; i < rows; i++) {
            int key = rand.nextInt((int) Math.pow(16, 4));
            while (table.containsKey(key)) {
                key = rand.nextInt((int) Math.pow(16, 4));
            }
            int x_j = key;
            for (int j = 0; j < columns; j++) {
                x_j = Coder.encrypt(x_j, plainText);

            }
            table.put(key, x_j);
        }
    }


    /**
     * Reverses the computed table and saves it the file
     */
    protected void saveTable(String filename) throws FileNotFoundException {
        try (PrintWriter writer = new PrintWriter(filename)) {
            for (int key : table.keySet()) {
                writer.println(table.get(key) + ", " + key);
            }
            writer.close();
        }
    }
}
