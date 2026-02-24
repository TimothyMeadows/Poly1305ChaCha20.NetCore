using System;
using System.Security.Cryptography;
using PinnedMemory;

namespace Poly1305ChaCha20.NetCore.Examples;

internal static class Program
{
    private static void Main()
    {
        var iv = new byte[12];
        var key = new byte[32];

        RandomNumberGenerator.Fill(iv);
        RandomNumberGenerator.Fill(key);

        using var keyPin = new PinnedMemory<byte>(key, false);
        using var cipher = new Poly1305ChaCha20(keyPin, iv);

        var input = new byte[] { 63, 61, 77, 20, 63, 61, 77, 20, 63, 61, 77 };
        using var inputPin = new PinnedMemory<byte>(input, false);
        cipher.UpdateBlock(inputPin, 0, input.Length);

        using var output = new PinnedMemory<byte>(new byte[cipher.GetLength()]);
        cipher.DoFinal(output, 0);

        Console.WriteLine(BitConverter.ToString(output.ToArray()));
    }
}
