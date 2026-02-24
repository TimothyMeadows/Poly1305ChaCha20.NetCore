using System;
using System.Security.Cryptography;
using PinnedMemory;

namespace Poly1305ChaCha20.NetCore;

/*
 * This code was adapted from BouncyCastle 1.8.3 Poly1305.cs
 * you can read more about poly1305 here https://cr.yp.to/mac.html
 */

/// <summary>
/// Poly1305 message authentication code, designed by D. J. Bernstein.
/// </summary>
/// <remarks>
/// Poly1305 computes a 128-bit (16 bytes) authenticator and uses a 256-bit key.
///
/// This implementation derives the Poly1305 pad from ChaCha20 using an RFC 8439 compliant 96-bit
/// nonce and expects that nonce to be unique for every message under the same key.
///
/// The polynomial calculation in this implementation is adapted from the public domain <a
/// href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
/// by Andrew M (@floodyberry).
/// </remarks>
public sealed class Poly1305ChaCha20 : IDisposable
{
    private const int BlockSize = 16;
    private const int NonceSize = 12;
    private const int KeySize = 32;

    private readonly bool _dance;
    private readonly byte[] _singleByte = new byte[1];
    private readonly PinnedMemory<byte> _singleBytePin;

    // Polynomial key
    private uint r0;
    private uint r1;
    private uint r2;
    private uint r3;
    private uint r4;

    // Precomputed 5 * r[1..4]
    private uint s1;
    private uint s2;
    private uint s3;
    private uint s4;

    // Encrypted nonce
    private uint k0;
    private uint k1;
    private uint k2;
    private uint k3;

    // Current block of buffered input
    private readonly byte[] _currentBlock = new byte[BlockSize];
    private readonly PinnedMemory<byte> _currentBlockPin;

    // Current offset in input buffer
    private int _currentBlockOffset;

    // Polynomial accumulator
    private uint h0;
    private uint h1;
    private uint h2;
    private uint h3;
    private uint h4;

    private bool _disposed;

    /// <summary>
    /// Constructs a Poly1305 MAC with ChaCha20 cipher.
    /// </summary>
    public Poly1305ChaCha20(PinnedMemory<byte> key, byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(salt);

        _singleBytePin = new PinnedMemory<byte>(_singleByte);
        _currentBlockPin = new PinnedMemory<byte>(_currentBlock);

        _dance = true;
        SetKey(key, salt);
        Reset();
    }

    public int GetLength() => BlockSize;

    public void Update(byte input)
    {
        ThrowIfDisposed();

        _singleByte[0] = input;
        UpdateBlock(_singleByte, 0, 1);
    }

    public void UpdateBlock(PinnedMemory<byte> value, int offset, int length)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(value);

        UpdateBlock(value.ToArray(), offset, length);
    }

    public void UpdateBlock(byte[] input, int inOff, int len)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(input);

        if (inOff < 0 || len < 0 || inOff > input.Length - len)
        {
            throw new ArgumentOutOfRangeException(nameof(inOff), "Offset and length are outside the input buffer.");
        }

        var copied = 0;
        while (len > copied)
        {
            if (_currentBlockOffset == BlockSize)
            {
                ProcessBlock();
                _currentBlockOffset = 0;
            }

            var toCopy = Math.Min(len - copied, BlockSize - _currentBlockOffset);
            Array.Copy(input, copied + inOff, _currentBlock, _currentBlockOffset, toCopy);
            copied += toCopy;
            _currentBlockOffset += toCopy;
        }
    }

    public void DoFinal(PinnedMemory<byte> output, int outOff)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(output);

        ValidateBufferLength(output, outOff, BlockSize, "Output buffer is too short.");

        if (_currentBlockOffset > 0)
        {
            ProcessBlock();
        }

        h1 += h0 >> 26;
        h0 &= 0x3ffffff;
        h2 += h1 >> 26;
        h1 &= 0x3ffffff;
        h3 += h2 >> 26;
        h2 &= 0x3ffffff;
        h4 += h3 >> 26;
        h3 &= 0x3ffffff;
        h0 += (h4 >> 26) * 5;
        h4 &= 0x3ffffff;
        h1 += h0 >> 26;
        h0 &= 0x3ffffff;

        var g0 = h0 + 5;
        var b = g0 >> 26;
        g0 &= 0x3ffffff;
        var g1 = h1 + b;
        b = g1 >> 26;
        g1 &= 0x3ffffff;
        var g2 = h2 + b;
        b = g2 >> 26;
        g2 &= 0x3ffffff;
        var g3 = h3 + b;
        b = g3 >> 26;
        g3 &= 0x3ffffff;
        var g4 = h4 + b - (1U << 26);

        b = (g4 >> 31) - 1;
        var nb = ~b;
        h0 = (h0 & nb) | (g0 & b);
        h1 = (h1 & nb) | (g1 & b);
        h2 = (h2 & nb) | (g2 & b);
        h3 = (h3 & nb) | (g3 & b);
        h4 = (h4 & nb) | (g4 & b);

        var f0 = ((h0) | (h1 << 26)) + k0;
        var f1 = ((h1 >> 6) | (h2 << 20)) + k1;
        var f2 = ((h2 >> 12) | (h3 << 14)) + k2;
        var f3 = ((h3 >> 18) | (h4 << 8)) + k3;

        UInt32ToLittleEndian((uint)f0, output, outOff);
        f1 += f0 >> 32;
        UInt32ToLittleEndian((uint)f1, output, outOff + 4);
        f2 += f1 >> 32;
        UInt32ToLittleEndian((uint)f2, output, outOff + 8);
        f3 += f2 >> 32;
        UInt32ToLittleEndian((uint)f3, output, outOff + 12);

        Reset();
    }

    public void Reset()
    {
        ThrowIfDisposed();

        _currentBlockOffset = 0;
        Array.Clear(_currentBlock, 0, _currentBlock.Length);
        h0 = h1 = h2 = h3 = h4 = 0;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(_singleByte);
        CryptographicOperations.ZeroMemory(_currentBlock);

        r0 = r1 = r2 = r3 = r4 = 0;
        s1 = s2 = s3 = s4 = 0;
        k0 = k1 = k2 = k3 = 0;
        h0 = h1 = h2 = h3 = h4 = 0;
        _currentBlockOffset = 0;

        _singleBytePin.Dispose();
        _currentBlockPin.Dispose();
        _disposed = true;
    }

    private void SetKey(PinnedMemory<byte> key, byte[] nonce)
    {
        if (key.Length != KeySize)
        {
            throw new ArgumentException("Poly1305 key must be 256 bits.", nameof(key));
        }

        if (_dance && nonce.Length != NonceSize)
        {
            throw new ArgumentException("Poly1305 requires a 96-bit nonce per RFC 8439.", nameof(nonce));
        }

        var t0 = LittleEndianToUInt32(key, 0);
        var t1 = LittleEndianToUInt32(key, 4);
        var t2 = LittleEndianToUInt32(key, 8);
        var t3 = LittleEndianToUInt32(key, 12);

        r0 = t0 & 0x03FFFFFFU;
        r1 = ((t0 >> 26) | (t1 << 6)) & 0x03FFFF03U;
        r2 = ((t1 >> 20) | (t2 << 12)) & 0x03FFC0FFU;
        r3 = ((t2 >> 14) | (t3 << 18)) & 0x03F03FFFU;
        r4 = (t3 >> 8) & 0x000FFFFFU;

        s1 = r1 * 5;
        s2 = r2 * 5;
        s3 = r3 * 5;
        s4 = r4 * 5;

        using var kBytes = key.Clone();
        var kOff = 0;

        if (!_dance)
        {
            kOff = BlockSize;
        }
        else
        {
            using var cipher = new ChaCha20.NetCore.ChaCha20(kBytes, nonce);
            var zeros = new byte[BlockSize];
            cipher.UpdateBlock(zeros, 0, BlockSize);
            cipher.DoFinal(kBytes, 0);
            cipher.Reset();
        }

        k0 = LittleEndianToUInt32(kBytes, kOff);
        k1 = LittleEndianToUInt32(kBytes, kOff + 4);
        k2 = LittleEndianToUInt32(kBytes, kOff + 8);
        k3 = LittleEndianToUInt32(kBytes, kOff + 12);
    }

    private void ProcessBlock()
    {
        if (_currentBlockOffset < BlockSize)
        {
            _currentBlock[_currentBlockOffset] = 1;
            Array.Clear(_currentBlock, _currentBlockOffset + 1, BlockSize - (_currentBlockOffset + 1));
        }

        ulong t0 = LittleEndianToUInt32(_currentBlock, 0);
        ulong t1 = LittleEndianToUInt32(_currentBlock, 4);
        ulong t2 = LittleEndianToUInt32(_currentBlock, 8);
        ulong t3 = LittleEndianToUInt32(_currentBlock, 12);

        h0 += (uint)(t0 & 0x3ffffffU);
        h1 += (uint)((((t1 << 32) | t0) >> 26) & 0x3ffffff);
        h2 += (uint)((((t2 << 32) | t1) >> 20) & 0x3ffffff);
        h3 += (uint)((((t3 << 32) | t2) >> 14) & 0x3ffffff);
        h4 += (uint)(t3 >> 8);

        if (_currentBlockOffset == BlockSize)
        {
            h4 += 1 << 24;
        }

        var tp0 = Multiply32x32To64(h0, r0) + Multiply32x32To64(h1, s4) + Multiply32x32To64(h2, s3) + Multiply32x32To64(h3, s2) + Multiply32x32To64(h4, s1);
        var tp1 = Multiply32x32To64(h0, r1) + Multiply32x32To64(h1, r0) + Multiply32x32To64(h2, s4) + Multiply32x32To64(h3, s3) + Multiply32x32To64(h4, s2);
        var tp2 = Multiply32x32To64(h0, r2) + Multiply32x32To64(h1, r1) + Multiply32x32To64(h2, r0) + Multiply32x32To64(h3, s4) + Multiply32x32To64(h4, s3);
        var tp3 = Multiply32x32To64(h0, r3) + Multiply32x32To64(h1, r2) + Multiply32x32To64(h2, r1) + Multiply32x32To64(h3, r0) + Multiply32x32To64(h4, s4);
        var tp4 = Multiply32x32To64(h0, r4) + Multiply32x32To64(h1, r3) + Multiply32x32To64(h2, r2) + Multiply32x32To64(h3, r1) + Multiply32x32To64(h4, r0);

        h0 = (uint)tp0 & 0x3ffffff;
        tp1 += tp0 >> 26;
        h1 = (uint)tp1 & 0x3ffffff;
        tp2 += tp1 >> 26;
        h2 = (uint)tp2 & 0x3ffffff;
        tp3 += tp2 >> 26;
        h3 = (uint)tp3 & 0x3ffffff;
        tp4 += tp3 >> 26;
        h4 = (uint)tp4 & 0x3ffffff;
        h0 += (uint)(tp4 >> 26) * 5;
        h1 += h0 >> 26;
        h0 &= 0x3ffffff;
    }

    private static ulong Multiply32x32To64(uint i1, uint i2) => (ulong)i1 * i2;

    private static uint LittleEndianToUInt32(byte[] bytes, int offset)
    {
        return (uint)bytes[offset]
               | (uint)bytes[offset + 1] << 8
               | (uint)bytes[offset + 2] << 16
               | (uint)bytes[offset + 3] << 24;
    }

    private static uint LittleEndianToUInt32(PinnedMemory<byte> bytes, int offset)
    {
        return (uint)bytes[offset]
               | (uint)bytes[offset + 1] << 8
               | (uint)bytes[offset + 2] << 16
               | (uint)bytes[offset + 3] << 24;
    }

    private static void UInt32ToLittleEndian(uint value, PinnedMemory<byte> bytes, int offset)
    {
        bytes[offset] = (byte)value;
        bytes[offset + 1] = (byte)(value >> 8);
        bytes[offset + 2] = (byte)(value >> 16);
        bytes[offset + 3] = (byte)(value >> 24);
    }

    private static void ValidateBufferLength(PinnedMemory<byte> buffer, int offset, int length, string message)
    {
        if (offset < 0 || length < 0 || offset > buffer.Length - length)
        {
            throw new ArgumentOutOfRangeException(nameof(offset), message);
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
