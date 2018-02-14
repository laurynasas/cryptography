/**
 * Created by Laurynas Tamulevicius on 2/3/18.
 */

import FormatIO.EofX;
import FormatIO.FileIn;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class CTO {
    private String encryptedFile = "src/cto_encrypted.txt";
    public String decryptedTextFile = "src/cto_decrypted.txt";
    public String decryptedFileRoot = "src/cto_decrypted";
    private double keySpaceSize = (int) Math.pow(16, 4);
    private double extendedCharLimit = 0;
    private String monogramTableDir = "src/english_monograms.txt";
    private String bigramTableDir = "src/english_bigrams.txt";

    /***
     * Extended class to convert hex-blocks to plain text without writing to file
     */
    static class Block2TextExtended extends Block2Text {

        private String blockToTextArray(String hexString) {
            StringWriter buffer = new StringWriter();

            for (String s : hexString.split("\\n")) {
                int i = Hex16.convert(s);
                int c0 = i / 256;
                int c1 = i % 256;
                buffer.write((char) c0);
                if (c1 != 0)
                    buffer.write((char) c1);
            }
            return buffer.toString();
        }


    }

    /***
     * Extended class to decrypt encrypted blocks without writing to file
     */
    static class DecryptAllBlocksExtended extends DecryptAllBlocks {
        private String keyString;
        private String nameIn;
        private ArrayList<String> textToDecode = new ArrayList<>();

        public DecryptAllBlocksExtended(String keyString, String nameIn) {
            this.keyString = keyString;
            this.nameIn = nameIn;
        }

        public String getDecoded() {
            if (textToDecode.size() == 0) {
                // open files
                FileIn fin = new FileIn(nameIn);
                String word;
                try {
                    for (; ; ) {
                        word = fin.readWord();
                        textToDecode.add(word);
                    }
                } catch (EofX x) {
                }
                fin.close();
            }

            StringWriter newBuffer = new StringWriter();
            int key = Hex16.convert(keyString);


            // read blocks, encrypt and output blocks
            for (String s : textToDecode) {
                int c = Hex16.convert(s);
                int p = Coder.decrypt(key, c);
                String out = String.format("0x%04x", p);
                newBuffer.write(out + "\n");
            }
            return newBuffer.toString();
        }

        public void setKey(String key) {
            this.keyString = key;
        }
    }

    /***
     * Helper method to read the monogram frequency table from file and divide
     * frequencies by 100 as their are in % in the file.
     */
    private static HashMap<String, Float> getFreqTable(String fileName) throws IOException {
        BufferedReader buffer = new BufferedReader(new FileReader(fileName));
        HashMap<String, Float> freqTable = new HashMap<>();
        String line;
        while ((line = buffer.readLine()) != null) {
            String[] parts = line.split(":");
            freqTable.put(parts[0].trim().toLowerCase(), Float.parseFloat(parts[1].trim()) / 100);
        }
        return freqTable;
    }

    /***
     * Helper method to read the bigram frequency table from
     * file and normalise by dividing by the highest frequency.
     */
    private static HashMap<String, Float> getBigramTable(String fileName) throws IOException {
        BufferedReader buffer = new BufferedReader(new FileReader(fileName));
        HashMap<String, Float> freqTable = new HashMap<>();
        String line;
        boolean first = true;
        float denom = 1;
        while ((line = buffer.readLine()) != null) {
            String[] parts = line.split(",");
            if (first) {
                denom = Float.parseFloat(parts[1].trim());
                first = false;
            }
            freqTable.put(parts[0].trim().toLowerCase(), Float.parseFloat(parts[1].trim()) / denom);
        }
        return freqTable;
    }

    /***
     * Split given text to words, loop through every word and count the bigram occurrences.
     */
    private static HashMap<String, Integer> countBigrams(HashMap<String, Float> bigramTable, String text) {
        HashMap<String, Integer> table = new HashMap<>();
        String sub;
        for (String word : text.split("\\b")) {
            for (int i = 0; i < word.length() - 2; i++) {
                sub = word.substring(i, i + 2).toLowerCase();
                if (bigramTable.get(sub) != null) {
                    if (table.get(sub) == null) {
                        table.put(sub, 1);
                    } else {
                        table.put(sub, table.get(sub) + 1);
                    }
                }
            }
        }
        return table;
    }

    /***
     * Calculate the bigram score by multiplying the 'popularity' of a bigram by number
     * of occurrences in the plain text. Sum these terms for every bigram
     * that was found in the plain text to get a final score
     */
    private static float calcBigramScore(HashMap<String, Float> bigramTable, HashMap<String, Integer> sentenceTable) {
        float score = 0;
        for (String key : sentenceTable.keySet()) {
            score += bigramTable.get(key) * sentenceTable.get(key);
        }
        return score;
    }

    /***
     * Calculate the distance between plain text and typical English text by comparing letter frequencies.
     * Distance is measured as Mean Squared Error.
     */
    private static float getMse(String text, HashMap<String, Float> freqTable) {
        HashMap<String, Float> table = new HashMap<>();
        int oldTextLength = text.length();

//        Leave only English alphabet letters
        text = text.replaceAll("[^A-Za-z]", "").toLowerCase();

        for (char ch : text.toCharArray()) {
            String strKey = Character.toString(ch);
            if (table.get(strKey) != null) {
                table.put(strKey, table.get(strKey) + 1);
            } else {
                table.put(strKey, (float) 0);
            }
        }

//        Get letter frequency in a found plain text
        for (String key : table.keySet()) {
            table.put(key, table.get(key) / oldTextLength);
        }

        float mse = 0;
        for (String key : freqTable.keySet()) {
            float letterOcc = ((table.get(key) == null) ? 0 : table.get(key));
            mse += Math.pow(freqTable.get(key) - letterOcc, 2);
        }
        return mse;

    }

    /***
     * Takes a decrypted piece of text in hex-word format and counts
     * how many control and extended characters there are
     */
    private int countExtendedASCII(String hexString) {
        int counter = 0;
        int startExtendedAsciiCodes = 128;
        int finishControlAsciiCodes = 31;

        for (String hexWord : hexString.split("\n")) {
            int chasInt = Hex16.convert(hexWord);
            while (chasInt != 0) {
                int asciiCode = chasInt & (Hex16.convert("0x00ff"));
                if (asciiCode >= startExtendedAsciiCodes || asciiCode <= finishControlAsciiCodes) {
                    counter += 1;
//                    No point of continuing if the limit is exceeded
                    if (counter > extendedCharLimit)
                        return counter;
                }
                chasInt >>= 8;
            }
        }
        return counter;
    }

    public static void main(String[] args) throws IOException {
        CTO cto = new CTO();
        HashMap<String, Float> freqTable = null;
        try {
            freqTable = getFreqTable(cto.monogramTableDir);
        } catch (IOException e) {
            e.printStackTrace();
        }


        String key = "0x0000";
        double lowMse = -1;
        ArrayList<Integer> finalKeys = new ArrayList<>();

        ArrayList<String> potText = new ArrayList<>();
        DecryptAllBlocksExtended dec = new DecryptAllBlocksExtended(key, cto.encryptedFile);
        String plaintText;
        for (int i = 0; i <= cto.keySpaceSize; i++) {
            key = String.format("0x%04X", i);
            dec.setKey(key);

            String decodedHexText = dec.getDecoded();
            Block2TextExtended block2TextExtended = new Block2TextExtended();


            plaintText = block2TextExtended.blockToTextArray(decodedHexText);

//            If we find any extended or control characters, throw the plain text away and try other key
            int illegalChars = cto.countExtendedASCII(decodedHexText);
            if (illegalChars > cto.extendedCharLimit) {
                continue;
            }

//            Collect the plain texts with lowest MSEs only
            if (lowMse < 0) {
                lowMse = getMse(plaintText, freqTable);
                finalKeys.add(i);
                potText.add(plaintText);
            } else {
                float currMse = getMse(plaintText, freqTable);
                if (currMse <= lowMse) {
                    lowMse = currMse;
                    finalKeys.add(i);
                    potText.add(plaintText);
                }
            }

        }


        HashMap<String, Float> bigramTable = getBigramTable(cto.bigramTableDir);
        float score;
        float maxScore = 0;
        String decryptedText = null;
        int finalKey = -1;
        int counter = 0;

//        Get bigram score for every potential plain text string
        for (String s : potText) {
            score = calcBigramScore(bigramTable, countBigrams(bigramTable, s));
            if (score >= maxScore) {
                decryptedText = s;
                maxScore = score;
                finalKey = finalKeys.get(counter);
            }
            counter++;
        }
        System.out.println("INT key: " + finalKey);
        System.out.println("HEX key: " + String.format("0x%04X", finalKey));
        System.out.println("DECRYPTED TEXT: " + decryptedText);
    }
}
