/**
 * Created by Laurynas Tamulevicius on 2/9/18.
 */

import FormatIO.EofX;
import FormatIO.FileIn;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

public class TMT2 {
    private HashMap<Integer, Integer> table;

    private TMT2() {
        this.table = new HashMap<>();
    }

    /***
     * Extended class to decrypt encrypted blocks without writing to file
     */
    static class DecryptAllBlocksExtended extends DecryptAllBlocks {
        private String keyString;
        private String nameIn;

        public DecryptAllBlocksExtended(String keyString, String nameIn) {
            this.keyString = keyString;
            this.nameIn = nameIn;
        }

        public String getDecoded() {
            StringWriter newBuffer = new StringWriter();
            int key = Hex16.convert(keyString);

            // open files
            FileIn fin = new FileIn(nameIn);

            // read blocks, encrypt and output blocks
            try {
                for (; ; ) {
                    String s = fin.readWord();
                    int c = Hex16.convert(s);
                    int p = Coder.decrypt(key, c);
                    String out = String.format("0x%04x", p);
                    newBuffer.write(out + "\n");
                }
            } catch (EofX x) {
            }
            fin.close();
            return newBuffer.toString();
        }

        public void setKey(String key) {
            this.keyString = key;
        }
    }

    /***
     * Extended class to convert hex-blocks to plain text without writing to file
     */
    static class Block2TextExtended extends Block2Text {
        private FileIn fin;

        public void setFiles(String name) {
            fin = new FileIn(name + ".txt");
        }

        private String getText() {
            StringWriter buffer = new StringWriter();
            try {
                for (; ; ) {
                    String s = fin.readWord();
                    int i = Hex16.convert(s);
                    int c0 = i / 256;
                    int c1 = i % 256;
                    buffer.write(((char) c0));
                    if (c1 != 0)
                        buffer.write((char) c1);
                }
            } catch (EofX x) {
            }
            return buffer.toString();
        }

    }

    public static void main(String[] args) throws Exception {
        TMT2 tmt2 = new TMT2();
        TMT1 tmt1 = new TMT1();

//        Construct table which was pre-generated using tm1 class
        tmt2.constructTable(tmt1.tableName);
        int firstTextBlock = tmt2.getFirstTextBlock(tmt1.plainTextFile);
        int firstCypherTextBlock = tmt2.getFirstTextBlock(tmt1.cypherTextFile);

        int key = tmt2.findKey(firstCypherTextBlock, firstTextBlock);

        System.out.println("INT key: " + key);
        String hexKey = String.format("0x%04x", key);
        System.out.println("HEX key: " + hexKey);

//        Write decrypted hex-blocks to file
        DecryptAllBlocksExtended dec = new DecryptAllBlocksExtended(hexKey, tmt1.cypherTextFile);
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(tmt1.decryptedTextFile));
            writer.write(dec.getDecoded());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Block2TextExtended block2TextExtended = new Block2TextExtended();
        block2TextExtended.setFiles(tmt1.decryptedFileRoot);
        System.out.println("DECRYPTED TEXT: " + block2TextExtended.getText());
    }


    /**
     * Method to get first block as integer from a given file
     */
    private int getFirstTextBlock(String filename) {
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
     * Reconstruct the pre-computed table from a file
     */
    private void constructTable(String filename) throws IOException {
        String line;

        try {
            FileReader fileReader = new FileReader(filename);
            BufferedReader bufferedReader =
                    new BufferedReader(fileReader);

            while ((line = bufferedReader.readLine()) != null) {
//              Parse the string elements to integer list
                List<Integer> pair = Arrays.stream(line.split(", "))
                        .map((x) -> Integer.parseInt(x))
                        .collect(Collectors.toList());
                if (table.get(pair.get(0)) != null) {
                    System.out.println("Cypher value already exists!");
                }
                table.put(pair.get(0), pair.get(1));
            }

            bufferedReader.close();
        } catch (FileNotFoundException ex) {
            System.out.println(
                    "Unable to open file '" + filename + "'");
            System.exit(1);

        } catch (IOException ex) {
            System.out.println("Error reading file '" + filename + "'");
            System.exit(1);
        }
    }


    /**
     * 1) Looks for a chain that ends with given cypher-text
     * 2) Reverses the chain and looks for a key
     */
    private int findKey(int cypherText, int plainText) throws Exception {
        int newCypherText = cypherText;

//        Figure out which chain contains the key
        int count = 0;
        while (table.get(newCypherText) == null) {
            newCypherText = Coder.encrypt(newCypherText, plainText);
            count += 1;
//            Check if it doesn't take too long to find an end of a chain
            if (count > Math.pow(16, 4) * 0.5) {
                break;
            }
        }

//      This will only be executed if we broke the previous while loop,
//      as it took too long to find an end of a chain
        if (table.get(newCypherText) == null) {
            generateNewTable(plainText);
            return this.findKey(cypherText, plainText);
        }

//        Get corresponding start-key of the chain
        int x_l = table.get(newCypherText);

        int endCypherText = newCypherText;
        int startCypherText = Coder.encrypt(x_l, plainText);

//        Start rebuilding the chain
        while (startCypherText != cypherText && startCypherText != endCypherText) {
            x_l = startCypherText;
            startCypherText = Coder.encrypt(startCypherText, plainText);
        }

//        If the we reach the end of a chain regenerate the table as the chain didn't contain the key
        if (startCypherText == endCypherText) {
            generateNewTable(plainText);
            return this.findKey(cypherText, plainText);
        }

        return x_l;
    }


    /**
     * Method to regenerate a new table and warn user that it was regenerated.
     * The table is regenerated using initially set TM1 parameters
     */
    private void generateNewTable(int plainText) throws Exception {
        System.out.println("WARNING: Not found in table, so it will be regenerated!");
        TMT1 tmt1 = new TMT1();
        tmt1.generateTable(plainText, tmt1.tableChains, tmt1.tableColumns);
        tmt1.saveTable(tmt1.tableName);

//        Clean old table
        this.table.clear();
        this.constructTable(tmt1.tableName);
    }

}
