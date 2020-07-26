using System;
using PinnedMemory;

namespace Poly1305ChaCha20.NetCore
{
    /*
     * This code was adapted from BouncyCastle 1.8.3 Poly1305.cs
     * you can read more about poly1305 here https://cr.yp.to/mac.html
     */

    /// <summary>
    /// Poly1305 message authentication code, designed by D. J. Bernstein.
    /// </summary>
    /// <remarks>
    /// Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
    /// consisting of a 128 bit key applied to the ChaCha20 cipher, and a 128 bit key (with 106
    /// effective key bits) used in the authenticator.
    /// 
    /// The polynomial calculation in this implementation is adapted from the public domain <a
    /// href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
    /// by Andrew M (@floodyberry).
    /// </remarks>
    public class Poly1305ChaCha20 : IDisposable
    {
        private const int BlockSize = 16;
        private readonly bool _dance;
        private readonly byte[] _singleByte = new byte[1];
        private readonly PinnedMemory<byte> _singleBytePin;

        /** Polynomial key */
        private uint r0, r1, r2, r3, r4;

        /** Precomputed 5 * r[1..4] */
        private uint s1, s2, s3, s4;

        /** Encrypted nonce */
        private uint k0, k1, k2, k3;

        // Accumulating state

        /** Current block of buffered input */
        private readonly byte[] _currentBlock = new byte[BlockSize];
        private readonly PinnedMemory<byte> _currentBlockPin;

        /** Current offset in input buffer */
        private int _currentBlockOffset;

        /** Polynomial accumulator */
        private uint h0, h1, h2, h3, h4;

        /// <summary>
        /// Constructs a Poly1305 MAC with ChaCha20 cipher.
        /// </summary>
        public Poly1305ChaCha20(PinnedMemory<byte> key, byte[] salt)
        {
            _singleBytePin = new PinnedMemory<byte>(_singleByte);
            _currentBlockPin = new PinnedMemory<byte>(_currentBlock);

            _dance = true;
            SetKey(key, salt);
            Reset();
        }

        private void SetKey(PinnedMemory<byte> key, byte[] nonce)
        {
            if (key.Length != 32)
                throw new ArgumentException("Poly1305 key must be 256 bits.");

            if (_dance && (nonce == null || nonce.Length != BlockSize))
                throw new ArgumentException("Poly1305 requires a 128 bit IV.");

            // Extract r portion of key (and "clamp" the values)
            var t0 = LE_To_UInt32(key, 0);
            var t1 = LE_To_UInt32(key, 4);
            var t2 = LE_To_UInt32(key, 8);
            var t3 = LE_To_UInt32(key, 12);

            // NOTE: The masks perform the key "clamping" implicitly
            r0 =   t0                      & 0x03FFFFFFU;
            r1 = ((t0 >> 26) | (t1 <<  6)) & 0x03FFFF03U;
            r2 = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FFU;
            r3 = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFFU;
            r4 =  (t3 >>  8)               & 0x000FFFFFU;

            // Precompute multipliers
            s1 = r1 * 5;
            s2 = r2 * 5;
            s3 = r3 * 5;
            s4 = r4 * 5;

            PinnedMemory<byte> kBytes;
            int kOff;

            if (!_dance)
            {
                kBytes = key.Clone();
                kOff = BlockSize;
            }
            else
            {
                // Compute encrypted nonce with chacha20
                kBytes = key.Clone();
                kOff = 0;

                using var cipher = new ChaCha20.NetCore.ChaCha20(kBytes, nonce);
                cipher.UpdateBlock(nonce, 0, BlockSize);
                cipher.DoFinal(kBytes, 0);
                cipher.Reset();
            }

            k0 = LE_To_UInt32(kBytes, kOff + 0);
            k1 = LE_To_UInt32(kBytes, kOff + 4);
            k2 = LE_To_UInt32(kBytes, kOff + 8);
            k3 = LE_To_UInt32(kBytes, kOff + 12);

            kBytes.Dispose();
        }

        public int GetLength()
        {
            return BlockSize;
        }

        public void Update(byte input)
        {
            _singleByte[0] = input;
            UpdateBlock(_singleByte, 0, 1);
        }

        public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
        {
            UpdateBlock(value.ToArray(), offset, length);
            value.Dispose();
        }

        public void UpdateBlock(byte[] input, int inOff, int len)
        {
            var copied = 0;
            while (len > copied)
            {
                if (_currentBlockOffset == BlockSize)
                {
                    ProcessBlock();
                    _currentBlockOffset = 0;
                }

                var toCopy = System.Math.Min((len - copied), BlockSize - _currentBlockOffset);
                Array.Copy(input, copied + inOff, _currentBlock, _currentBlockOffset, toCopy);
                copied += toCopy;
                _currentBlockOffset += toCopy;
            }

        }

        private void ProcessBlock()
        {
            if (_currentBlockOffset < BlockSize)
            {
                _currentBlock[_currentBlockOffset] = 1;
                for (var i = _currentBlockOffset + 1; i < BlockSize; i++)
                {
                    _currentBlock[i] = 0;
                }
            }

            ulong t0 = LE_To_UInt32(_currentBlock, 0);
            ulong t1 = LE_To_UInt32(_currentBlock, 4);
            ulong t2 = LE_To_UInt32(_currentBlock, 8);
            ulong t3 = LE_To_UInt32(_currentBlock, 12);

            h0 += (uint)(t0 & 0x3ffffffU);
            h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
            h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
            h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
            h4 += (uint)(t3 >> 8);

            if (_currentBlockOffset == BlockSize)
            {
                h4 += (1 << 24);
            }

            var tp0 = mul32x32_64(h0,r0) + mul32x32_64(h1,s4) + mul32x32_64(h2,s3) + mul32x32_64(h3,s2) + mul32x32_64(h4,s1);
            var tp1 = mul32x32_64(h0,r1) + mul32x32_64(h1,r0) + mul32x32_64(h2,s4) + mul32x32_64(h3,s3) + mul32x32_64(h4,s2);
            var tp2 = mul32x32_64(h0,r2) + mul32x32_64(h1,r1) + mul32x32_64(h2,r0) + mul32x32_64(h3,s4) + mul32x32_64(h4,s3);
            var tp3 = mul32x32_64(h0,r3) + mul32x32_64(h1,r2) + mul32x32_64(h2,r1) + mul32x32_64(h3,r0) + mul32x32_64(h4,s4);
            var tp4 = mul32x32_64(h0,r4) + mul32x32_64(h1,r3) + mul32x32_64(h2,r2) + mul32x32_64(h3,r1) + mul32x32_64(h4,r0);

            h0 = (uint)tp0 & 0x3ffffff; tp1 += (tp0 >> 26);
            h1 = (uint)tp1 & 0x3ffffff; tp2 += (tp1 >> 26);
            h2 = (uint)tp2 & 0x3ffffff; tp3 += (tp2 >> 26);
            h3 = (uint)tp3 & 0x3ffffff; tp4 += (tp3 >> 26);
            h4 = (uint)tp4 & 0x3ffffff;
            h0 += (uint)(tp4 >> 26) * 5;
            h1 += (h0 >> 26); h0 &= 0x3ffffff;
        }

        public void DoFinal(PinnedMemory<byte> output, int outOff)
        {
            DataLength(output, outOff, BlockSize, "Output buffer is too short.");

            if (_currentBlockOffset > 0)
            {
                // Process padded block
                ProcessBlock();
            }

            h1 += (h0 >> 26); h0 &= 0x3ffffff;
            h2 += (h1 >> 26); h1 &= 0x3ffffff;
            h3 += (h2 >> 26); h2 &= 0x3ffffff;
            h4 += (h3 >> 26); h3 &= 0x3ffffff;
            h0 += (h4 >> 26) * 5; h4 &= 0x3ffffff;
            h1 += (h0 >> 26); h0 &= 0x3ffffff;

            var g0 = h0 + 5;
            var b = g0 >> 26; g0 &= 0x3ffffff;
            var g1 = h1 + b; b = g1 >> 26; g1 &= 0x3ffffff;
            var g2 = h2 + b; b = g2 >> 26; g2 &= 0x3ffffff;
            var g3 = h3 + b; b = g3 >> 26; g3 &= 0x3ffffff;
            var g4 = h4 + b - (1 << 26);

            b = (g4 >> 31) - 1;
            var nb = ~b;
            h0 = (h0 & nb) | (g0 & b);
            h1 = (h1 & nb) | (g1 & b);
            h2 = (h2 & nb) | (g2 & b);
            h3 = (h3 & nb) | (g3 & b);
            h4 = (h4 & nb) | (g4 & b);

            var f0 = ((h0      ) | (h1 << 26)) + (ulong)k0;
            var f1 = ((h1 >> 6 ) | (h2 << 20)) + (ulong)k1;
            var f2 = ((h2 >> 12) | (h3 << 14)) + (ulong)k2;
            var f3 = ((h3 >> 18) | (h4 << 8 )) + (ulong)k3;

            UInt32_To_LE((uint)f0, output, outOff);
            f1 += (f0 >> 32);
            UInt32_To_LE((uint)f1, output, outOff + 4);
            f2 += (f1 >> 32);
            UInt32_To_LE((uint)f2, output, outOff + 8);
            f3 += (f2 >> 32);
            UInt32_To_LE((uint)f3, output, outOff + 12);

            Reset();
        }

        public void Reset()
        {
            _currentBlockOffset = 0;
            h0 = h1 = h2 = h3 = h4 = 0;
        }

        private static ulong mul32x32_64(uint i1, uint i2)
        {
            return ((ulong)i1) * i2;
        }

        private uint LE_To_UInt32(byte[] bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private uint LE_To_UInt32(PinnedMemory<byte> bs, int off)
        {
            return (uint)bs[off]
                   | (uint)bs[off + 1] << 8
                   | (uint)bs[off + 2] << 16
                   | (uint)bs[off + 3] << 24;
        }

        private ulong LE_To_UInt64(PinnedMemory<byte> bs, int off)
        {
            var lo = LE_To_UInt32(bs, off);
            var hi = LE_To_UInt32(bs, off + 4);
            return ((ulong)hi << 32) | (ulong)lo;
        }

        private PinnedMemory<byte> UInt64_To_LE(ulong n)
        {
            var bs = new PinnedMemory<byte>(new byte[8]);
            UInt64_To_LE(n, bs, 0);
            return bs;
        }

        private void UInt64_To_LE(ulong n, PinnedMemory<byte> bs, int off)
        {
            UInt32_To_LE((uint)(n), bs, off);
            UInt32_To_LE((uint)(n >> 32), bs, off + 4);
        }

        private void UInt32_To_LE(uint n, PinnedMemory<byte> bs, int off)
        {
            bs[off] = (byte)(n);
            bs[off + 1] = (byte)(n >> 8);
            bs[off + 2] = (byte)(n >> 16);
            bs[off + 3] = (byte)(n >> 24);
        }

        private void DataLength(PinnedMemory<byte> buf, int off, int len, string msg)
        {
            if (off + len > buf.Length)
                throw new Exception(msg);
        }

        public void Dispose()
        {
            _singleBytePin?.Dispose();
            _currentBlockPin?.Dispose();
        }
    }
}
