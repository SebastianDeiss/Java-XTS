/*
 * Copyright (c) 2015-2016, Sebastian Deiss
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package sdeiss.crypto.block.mode.xts;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Main class to test XTS mode.
 * 
 * @author Sebastian Deiss
 * 
 */
public final class Main
{
    /**
     * The Java main method.
     * 
     * @param args The command line arguments.
     */
    public static void main(String[] args)
    {
        // IEEE 1619 test vector 10
        final String key = "2718281828459045235360287471352662497757247093699959574966967627";
        final String tweakKey = "3141592653589793238462643383279502884197169399375105820974944592";
        final String dataUnit = "00000000000000ff";
        final String plainText = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                               + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                               + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                               + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                               + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                               + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                               + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                               + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
                               + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
                               + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
                               + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
                               + "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
                               + "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
                               + "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                               + "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                               + "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        final String cipherText = "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
                                + "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
                                + "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
                                + "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
                                + "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
                                + "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
                                + "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
                                + "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
                                + "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
                                + "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
                                + "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
                                + "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
                                + "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
                                + "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
                                + "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
                                + "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151";

        /*
         * Run test with IEEE 1619 test vector 10
         */

        // Setup ciphers
        CipherParameters params = new KeyParameter(ByteUtil.hexToBytes(key));
        CipherParameters tweakParams = new KeyParameter(ByteUtil.hexToBytes(tweakKey));
        BlockCipher cipher = new AESFastEngine();
        BlockCipher tweakCipher = new AESFastEngine();
        cipher.init(true, params);
        tweakCipher.init(true, tweakParams);

        // Setup XTS mode test
        XTS xts = new XTS(cipher, tweakCipher);
        byte[] plaintext = ByteUtil.hexToBytes(plainText);
        byte[] ciphertext = ByteUtil.hexToBytes(cipherText);
        long dataUnitNumber = ByteUtil.loadInt64BE(ByteUtil.hexToBytes(dataUnit), 0);
        byte[] createdCipherText = new byte[xts.getDataUnitSize()];
        byte[] decryptedPlainText = new byte[xts.getDataUnitSize()];

        info();
        System.out.println("====================================================");
        System.out.println("IEEE 1619 test vector 10");
        System.out.println("Key               " + key);
        System.out.println("Tweak key:        " + tweakKey);
        System.out.println("Data unit number: " + dataUnitNumber);
        System.out.println("Plaintext:        " + plainText);
        System.out.println("Ciphertext:       " + cipherText);
        System.out.println("====================================================");
        System.out.println("Result");
        System.out.println("====================================================");

        // Encrypt
        xts.processDataUnit(plaintext, 0, createdCipherText, 0, dataUnitNumber);

        System.out.println("Ciphertext:       " + ByteUtil.bytesToHex(createdCipherText));
        if (ByteUtil.bytesToHex(createdCipherText).equals(cipherText))
            System.out.println("Ciphertext matches IEEE 1619 test vector 10");
        else
            System.out.println("Ciphertext does not match IEEE 1619 test vector 10");

        // Decrypt
        cipher.init(false, params);
        xts.resetCipher(cipher);
        xts.processDataUnit(ciphertext, 0, decryptedPlainText, 0, dataUnitNumber);

        System.out.println("Plaintext:        " + ByteUtil.bytesToHex(decryptedPlainText));
        if (ByteUtil.bytesToHex(decryptedPlainText).equals(plainText))
            System.out.println("Plaintext matches IEEE 1619 test vector 10");
        else
            System.out.println("Plaintext does not match IEEE 1619 test vector 10");
    }

    private static void info()
    {
        System.out.println("XTS mode implementation for Java");
        System.out.println("specified in IEEE P1619(TM)/D16 Standard for");
        System.out.println("Cryptographic Protection of Data on Block-Oriented Storage Devices");
        System.out.println("Copyright (C) 2015 Sebastian Deiss. All rights reserved.");
        System.out.println("");
    }
}
