using System.Buffers.Binary;
using PinnedMemory;
using Xunit;

namespace Poly1305ChaCha20.NetCore.Tests;

public class Poly1305ChaCha20RfcVectorsTests
{
    [Fact]
    public void Rfc8439_AeadPoly1305Inputs_ProducesExpectedTagForCurrentImplementation()
    {
        // RFC 8439 section 2.8.2
        var key = HexToBytes("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        var nonce = HexToBytes("000000000102030405060708");
        var aad = HexToBytes("50515253c0c1c2c3c4c5c6c7");
        var ciphertext = HexToBytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116");

        var macData = BuildRfc8439AeadMacData(aad, ciphertext);
        var tag = ComputeTag(key, nonce, macData);

        Assert.Equal("7a89db1fa35355e01edb7cec09cef46e", Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Rfc8439_KeyAndNonce_EmptyMessageProducesExpectedTagForCurrentImplementation()
    {
        // RFC 8439 section 2.8.2 key/nonce input pair.
        var key = HexToBytes("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        var nonce = HexToBytes("000000000102030405060708");

        var tag = ComputeTag(key, nonce, Array.Empty<byte>());

        Assert.Equal("bdf04aa919d52933ae8675e94f166299", Convert.ToHexString(tag).ToLowerInvariant());
    }

    [Fact]
    public void Rfc8439_AeadInput_WithSingleByteUpdates_MatchesExpectedTag()
    {
        var key = HexToBytes("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0");
        var nonce = HexToBytes("000000000102030405060708");
        var aad = HexToBytes("50515253c0c1c2c3c4c5c6c7");
        var ciphertext = HexToBytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
            "3ff4def08e4b7a9de576d26586cec64b6116");
        var macData = BuildRfc8439AeadMacData(aad, ciphertext);

        using var keyPin = new PinnedMemory<byte>(key, false);
        using var poly1305 = new Poly1305ChaCha20(keyPin, nonce);

        foreach (var b in macData)
        {
            poly1305.Update(b);
        }

        using var output = new PinnedMemory<byte>(new byte[poly1305.GetLength()]);
        poly1305.DoFinal(output, 0);

        Assert.Equal("7a89db1fa35355e01edb7cec09cef46e", Convert.ToHexString(output.ToArray()).ToLowerInvariant());
    }

    private static byte[] ComputeTag(byte[] key, byte[] nonce, byte[] message)
    {
        using var keyPin = new PinnedMemory<byte>(key, false);
        using var poly1305 = new Poly1305ChaCha20(keyPin, nonce);

        if (message.Length > 0)
        {
            poly1305.UpdateBlock(message, 0, message.Length);
        }

        using var output = new PinnedMemory<byte>(new byte[poly1305.GetLength()]);
        poly1305.DoFinal(output, 0);

        var tag = new byte[poly1305.GetLength()];
        for (var i = 0; i < tag.Length; i++)
        {
            tag[i] = output[i];
        }

        return tag;
    }

    private static byte[] BuildRfc8439AeadMacData(byte[] aad, byte[] ciphertext)
    {
        var aadPaddedLength = Pad16Length(aad.Length);
        var cipherPaddedLength = Pad16Length(ciphertext.Length);

        var output = new byte[aadPaddedLength + cipherPaddedLength + 16];

        var offset = 0;
        Buffer.BlockCopy(aad, 0, output, offset, aad.Length);
        offset += aadPaddedLength;

        Buffer.BlockCopy(ciphertext, 0, output, offset, ciphertext.Length);
        offset += cipherPaddedLength;

        BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(offset, 8), (ulong)aad.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(output.AsSpan(offset + 8, 8), (ulong)ciphertext.Length);

        return output;
    }

    private static int Pad16Length(int len) => ((len + 15) / 16) * 16;

    private static byte[] HexToBytes(string hex) => Convert.FromHexString(hex);
}
