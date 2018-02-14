/**
 * Created by Laurynas Tamulevicius on 2/3/18.
 */

import FormatIO.EofX;
import FormatIO.FileIn;

import java.io.*;


public class KPT {
    private String encryptedFile = "src/kpt_encrypted.txt";
    private String decryptedTextFile = "src/kpt_decrypted.txt";
    private String decryptedFileRoot = "src/kpt_decrypted";
    private String initPlainText = "0x5769";

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

    /***
     * Extended class to decrypt encrypted blocks without writing to file
     */
    static class DecryptAllBlocksExtended extends DecryptAllBlocks {
        private String key_string;
        private String name_in;

        public DecryptAllBlocksExtended(String key_string, String name_in) {
            this.key_string = key_string;
            this.name_in = name_in;
        }

        public String getDecoded() {
            StringWriter new_buffer = new StringWriter();
            int key = Hex16.convert(key_string);

            // open files
            FileIn fin = new FileIn(name_in);

            // read blocks, encrypt and output blocks
            try {
                for (; ; ) {
                    String s = fin.readWord();
                    int c = Hex16.convert(s);
                    int p = Coder.decrypt(key, c);
                    String out = String.format("0x%04x", p);
                    new_buffer.write(out + "\n");
                }
            } catch (EofX x) {
            }
            fin.close();
            return new_buffer.toString();
        }

        public void setKey(String key) {
            this.key_string = key;
        }
    }

    /***
     * Extended class to encrypt given string using given key without writing to file
     */
    static class EncryptAllBlocksExtended extends EncryptAllBlocks {

        private String key_string;

        private EncryptAllBlocksExtended(String key_string) {
            this.key_string = key_string;

        }

        private String getEncoded(String text) {
            StringWriter new_buffer = new StringWriter();
            int key = Hex16.convert(key_string);

//            Initial plain text

            int p = Hex16.convert(text);
            int c = Coder.encrypt(key, p);

            String out = String.format("0x%04x", c);

            new_buffer.write(out);

            return new_buffer.toString();
        }

        private void setKey(String new_key) {
            this.key_string = new_key;
        }

    }

    public static void main(String[] args) {
        KPT kpt = new KPT();
        String first_cypher_text_block = kpt.getFirstTextBlock(kpt.encryptedFile);
        String key = "0x0000";

        int keySpaceSize = (int) Math.pow(16, 4);
        EncryptAllBlocksExtended enc = new EncryptAllBlocksExtended(key);
        for (int i = 0; i <= keySpaceSize; i++) {
            key = String.format("0x%04X", i);
            enc.setKey(key);

//          If key is found - break;
            if (enc.getEncoded(kpt.initPlainText).equals(first_cypher_text_block)) {
                break;
            }
        }

        System.out.println("INT key: " + Hex16.convert(key));
        System.out.println("HEX key: " + key);

        DecryptAllBlocksExtended dec = new DecryptAllBlocksExtended(key, kpt.encryptedFile);
//        Write decrypted blocks to file
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(kpt.decryptedTextFile));
            writer.write(dec.getDecoded());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Block2TextExtended b_t_ext = new Block2TextExtended();
        b_t_ext.setFiles(kpt.decryptedFileRoot);

        System.out.println("DECRYPTED TEXT: " + b_t_ext.getText());
    }

    /***
     * Helper method to extract first hex-block from a given file
     */
    private String getFirstTextBlock(String filename) {
        String line;
        try {
            FileReader fileReader = new FileReader(filename);
            BufferedReader bufferedReader =
                    new BufferedReader(fileReader);

            if ((line = bufferedReader.readLine()) != null) {
                bufferedReader.close();
                return line;
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
        return "";

    }

}
