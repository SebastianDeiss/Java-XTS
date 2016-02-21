/*
 * Copyright (c) 2015-2016, Sebastian Deiss
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or
 * other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package sdeiss.crypto.block.mode.xts;

import java.util.Arrays;
import org.bouncycastle.crypto.BlockCipher;

/**
 * XTS mode implementation.
 * XTS stands for XOR Encrypt XOR Tweakable Block Cipher with Ciphertext Stealing.
 * 
 * @author Sebastian Deiss
 * @see IEEE P1619(TM)/D16 Standard for Cryptographic Protection of Data on
 * Block-Oriented Storage Devices
 *
 */
public final class XTS
{
	private static final int XTS_DATA_UNIT_SIZE = 512;
	// Size of a 64 bit integer in bytes
	private static final int SIZE_OF_LONG = 8;
	// The block size of the underlying cipher
	private static int BLOCK_SIZE;
	
	private BlockCipher cipherInstance;
	private final BlockCipher tweakCipherInstance;
	
	/**
	 * Create a new XTS instance.
	 * 
	 * @param cipher The {@link BlockCipher } to use for encryption / decryption.
	 * @param tweakCipher The {@link BlockCipher } to use for tweak encryption.
	 * @throws IllegalStateException If both {@link BlockCipher } objects are not from the same algorithm.
	 */
	public XTS(final BlockCipher cipher, final BlockCipher tweakCipher) throws IllegalStateException
	{
		if (!cipher.getAlgorithmName().equals(tweakCipher.getAlgorithmName()))
			throw new IllegalStateException();
		
		this.cipherInstance = cipher;
		this.tweakCipherInstance = tweakCipher;
		BLOCK_SIZE = cipher.getBlockSize();
	}
	
	/**
	 * Encrypt / decrypt a data unit in XTS mode.
	 * 
	 * @param in The input data unit.
	 * @param inOffset Offset in the input data unit array.
	 * @param out The output data unit.
	 * @param outOffset Offset in the output data unit array.
	 * @param dataUnitNumber The sector number of this data unit on the block storage device.
	 * @return Returns the number of bytes processed.
	 */
	public int processDataUnit(byte[] in, final int inOffset, byte[] out, final int outOffset, final long dataUnitNumber) throws IllegalStateException
	{
		int processedBytes = in.length - inOffset;
		// Check if the length of in is a multiple of BLOCK_SIZE
		if (processedBytes % BLOCK_SIZE != 0)
			throw new IllegalStateException();
		
		// Produce the tweak value
		byte[] tweak = new byte[BLOCK_SIZE];
		// Convert the dataUnitNumber (long) to little-endian bytes
		ByteUtil.storeInt64LE(dataUnitNumber, tweak, 0);
		// A long consists of 8 bytes but the block size is 16 so we
		// fill the rest of the IV array with zeros.
		Arrays.fill(tweak, SIZE_OF_LONG, BLOCK_SIZE, (byte)0);
		// Encrypt tweak
		this.tweakCipherInstance.processBlock(tweak, 0, tweak, 0);
		
		for (int i = 0; i < XTS_DATA_UNIT_SIZE; i += BLOCK_SIZE)
		{
			// Encrypt / decrypt one block
			this.processBlock(in, i, out, i, tweak);
			// Multiply tweak by alpha
			tweak = this.multiplyTweakByA(tweak);
		}
		
		return processedBytes;
	}
	
	/**
	 * Gets the name of the underlying cipher.
	 * 
	 * @return The name of the underlying cipher.
	 */
	public String getAlgorithmName()
	{
		return this.cipherInstance.getAlgorithmName();
	}
	
	/**
	 * Gets the size of an XTS data unit.
	 * 
	 * @return The size of an XTS data unit.
	 */
	public final int getDataUnitSize()
	{
		return XTS_DATA_UNIT_SIZE;
	}
	
	/**
	 * Gets the block size of the underlying cipher which is equal to the XTS block size.
	 * 
	 * @return The block size of the underlying cipher.
	 */
	public final int getBlockSize()
	{
		return BLOCK_SIZE;
	}
	
	/**
	 * Resets the cipher.
	 * 
	 * @param cipher The new cipher to use or the old cipher but with other parameters.
	 */
	public void resetCipher(final BlockCipher cipher)
	{
		this.cipherInstance = cipher;
	}
	
	/**
	 * Encrypt / decrypt a single block in XTS mode.
	 * 
	 * @param in The input block.
	 * @param inOffset Offset in the input block array.
	 * @param out The output block.
	 * @param outOffset Offset in the output block array.
	 * @param tweak The tweak value for this block.
	 * @return Returns the number of bytes processed.
	 */
	private int processBlock(byte[] in, final int inOffset, byte[] out, final int outOffset, final byte[] tweak)
	{
		// XOR
		// PP <- P ^ T
		for (int i = 0; i < BLOCK_SIZE; i++)
			in[inOffset + i] ^= tweak[i];

		// Encrypt	  CC <- enc(Key1, PP)
		// Or decrypt PP <- dec(Key1, CC)
		this.cipherInstance.processBlock(in, inOffset, out, outOffset);

		// XOR
		// C <- CC ^ T
		for (int i = 0; i < BLOCK_SIZE; i++)
			out[outOffset + i] ^= tweak[i];

		return BLOCK_SIZE;
	}
	
	/**
	 * Multiplication of two polynomials over the binary field
	 * GF(2) modulo x^128 + x^7 + x^2 + x + 1, where GF stands for Galois Field.
	 * 
	 * @param tweak The tweak value which is a primitive element of GF(2^128)
	 * @return Returns the result of the multiplication as a byte array
	 */
	private byte[] multiplyTweakByA(final byte[] tweak)
	{
		long whiteningLo = ByteUtil.loadInt64LE(tweak, 0);
		long whiteningHi = ByteUtil.loadInt64LE(tweak, SIZE_OF_LONG);
		
		// Multiplication of two polynomials over the binary field
		// GF(2) modulo x^128 + x^7 + x^2 + x + 1, where GF stands for Galois Field.
		int finalCarry = 0 == (whiteningHi & 0x8000000000000000L) ? 0 : 135;
		
		whiteningHi <<= 1;
		whiteningHi |= whiteningLo >>> 63;
		whiteningLo <<= 1;
		whiteningLo ^= finalCarry;
		
		ByteUtil.storeInt64LE(whiteningLo, tweak, 0);
		ByteUtil.storeInt64LE(whiteningHi, tweak, SIZE_OF_LONG);
		
		return tweak;
	}
}
