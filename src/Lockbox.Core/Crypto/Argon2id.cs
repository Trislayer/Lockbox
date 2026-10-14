using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Lockbox.Core.Crypto;

/// <summary>
/// Argon2id, version 0x13 (RFC 9106). The memory-hard password hash that turns the master
/// password into a key; the base class library has PBKDF2 but nothing memory-hard, and a
/// vault that lives in a cloud folder must assume an attacker can guess offline on GPUs.
/// </summary>
/// <remarks>
/// A direct transcription of the RFC and its reference implementation (the PHC repo's
/// <c>ref.c</c>/<c>core.c</c>), favouring obviousness over speed. Correctness is pinned in
/// Lockbox.Checks by the RFC 9106 §5.3 test vector and by agreement with OpenSSL's Argon2id
/// (via Node) at the parameters Lockbox actually uses.
/// </remarks>
internal static class Argon2id
{
    private const uint Version = 0x13;
    private const uint TypeId = 2; // Argon2id
    private const int BlockWords = 128; // 1024-byte blocks as 128 little-endian ulongs
    private const int BlockBytes = BlockWords * 8;
    private const int SyncPoints = 4;
    private const int PrehashLength = 64;

    public static byte[] Hash(
        ReadOnlySpan<byte> password,
        ReadOnlySpan<byte> salt,
        int memoryKiB,
        int passes,
        int lanes,
        int tagLength,
        ReadOnlySpan<byte> secret = default,
        ReadOnlySpan<byte> associatedData = default)
    {
        if (lanes is < 1 or > 0xFFFFFF) throw new ArgumentOutOfRangeException(nameof(lanes));
        if (passes < 1) throw new ArgumentOutOfRangeException(nameof(passes));
        if (memoryKiB < 8 * lanes) throw new ArgumentOutOfRangeException(nameof(memoryKiB), "Argon2 needs at least 8 KiB per lane.");
        if (tagLength < 4) throw new ArgumentOutOfRangeException(nameof(tagLength));
        if (salt.Length < 8) throw new ArgumentOutOfRangeException(nameof(salt), "Argon2 salt is at least 8 bytes.");

        // m' = 4p * floor(m / 4p): every lane gets the same number of whole segments.
        var segmentLength = memoryKiB / (SyncPoints * lanes);
        var laneLength = segmentLength * SyncPoints;
        var blockCount = laneLength * lanes;

        var h0 = new byte[PrehashLength + 8]; // H0 followed by two LE32 slots used when seeding lanes
        ComputeH0(h0.AsSpan(0, PrehashLength), password, salt, secret, associatedData,
            lanes, tagLength, memoryKiB, passes);

        var memory = new ulong[(long)blockCount * BlockWords];
        try
        {
            var ctx = new Context(memory, lanes, laneLength, segmentLength, blockCount, passes);

            // B[i][0] = H'(H0 || LE32(0) || LE32(i)),  B[i][1] = H'(H0 || LE32(1) || LE32(i))
            var seed = new byte[BlockBytes];
            for (var lane = 0; lane < lanes; lane++)
            {
                for (var j = 0; j < 2; j++)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(h0.AsSpan(PrehashLength), (uint)j);
                    BinaryPrimitives.WriteUInt32LittleEndian(h0.AsSpan(PrehashLength + 4), (uint)lane);
                    VariableHash(h0, seed);
                    LoadBlock(ctx.Block(lane * laneLength + j), seed);
                }
            }
            CryptographicOperations.ZeroMemory(seed);

            for (var pass = 0; pass < passes; pass++)
            {
                for (var slice = 0; slice < SyncPoints; slice++)
                {
                    // Lanes within a slice are independent; the slice boundary is the sync point.
                    if (lanes == 1)
                        FillSegment(ctx, pass, 0, slice);
                    else
                    {
                        var (p, s) = (pass, slice);
                        Parallel.For(0, lanes, lane => FillSegment(ctx, p, lane, s));
                    }
                }
            }

            // C = XOR of the last block of every lane; tag = H'(C).
            var final = new ulong[BlockWords];
            for (var lane = 0; lane < lanes; lane++)
                Xor(final, ctx.Block(lane * laneLength + laneLength - 1));
            var finalBytes = new byte[BlockBytes];
            StoreBlock(finalBytes, final);
            var tag = new byte[tagLength];
            VariableHash(finalBytes, tag);

            Array.Clear(final);
            CryptographicOperations.ZeroMemory(finalBytes);
            return tag;
        }
        finally
        {
            Array.Clear(memory);
            CryptographicOperations.ZeroMemory(h0);
        }
    }

    private static void ComputeH0(Span<byte> output, ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, int lanes, int tagLength, int memoryKiB, int passes)
    {
        var h = new Blake2b(PrehashLength);
        var le = new byte[4];
        void U32(uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(le, value);
            h.Update(le);
        }

        U32((uint)lanes);
        U32((uint)tagLength);
        U32((uint)memoryKiB);
        U32((uint)passes);
        U32(Version);
        U32(TypeId);
        U32((uint)password.Length); h.Update(password);
        U32((uint)salt.Length); h.Update(salt);
        U32((uint)secret.Length); h.Update(secret);
        U32((uint)associatedData.Length); h.Update(associatedData);
        h.Final(output);
    }

    /// <summary>H' (RFC 9106 §3.3): BLAKE2b extended to any output length.</summary>
    private static void VariableHash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<byte> lengthPrefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(lengthPrefix, (uint)output.Length);

        if (output.Length <= Blake2b.MaxOutputLength)
        {
            var h = new Blake2b(output.Length);
            h.Update(lengthPrefix);
            h.Update(input);
            h.Final(output);
            return;
        }

        // r = ceil(T/32) - 2 full 64-byte hashes, each contributing its first 32 bytes, then
        // one last hash of the remaining length.
        Span<byte> v = stackalloc byte[Blake2b.MaxOutputLength];
        var first = new Blake2b(Blake2b.MaxOutputLength);
        first.Update(lengthPrefix);
        first.Update(input);
        first.Final(v);

        var r = (output.Length + 31) / 32 - 2;
        var offset = 0;
        v[..32].CopyTo(output);
        offset += 32;
        Span<byte> next = stackalloc byte[Blake2b.MaxOutputLength];
        for (var i = 2; i <= r; i++)
        {
            Blake2b.Hash(v, next);
            next.CopyTo(v);
            v[..32].CopyTo(output[offset..]);
            offset += 32;
        }
        Blake2b.Hash(v, output[offset..]);
        CryptographicOperations.ZeroMemory(v);
        CryptographicOperations.ZeroMemory(next);
    }

    private sealed class Context(ulong[] memory, int lanes, int laneLength, int segmentLength, int blockCount, int passes)
    {
        public readonly ulong[] Memory = memory;
        public readonly int Lanes = lanes;
        public readonly int LaneLength = laneLength;
        public readonly int SegmentLength = segmentLength;
        public readonly int BlockCount = blockCount;
        public readonly int Passes = passes;

        public Span<ulong> Block(long index) => Memory.AsSpan().Slice((int)(index * BlockWords), BlockWords);
    }

    private static void FillSegment(Context ctx, int pass, int lane, int slice)
    {
        // Argon2id: data-independent addressing (Argon2i) for the first half of the first
        // pass, data-dependent (Argon2d) for everything after.
        var dataIndependent = pass == 0 && slice < SyncPoints / 2;

        Span<ulong> address = stackalloc ulong[BlockWords];
        Span<ulong> input = stackalloc ulong[BlockWords];
        Span<ulong> zero = stackalloc ulong[BlockWords];
        Span<ulong> r = stackalloc ulong[BlockWords];
        Span<ulong> tmp = stackalloc ulong[BlockWords];
        address.Clear(); input.Clear(); zero.Clear();

        if (dataIndependent)
        {
            input[0] = (ulong)pass;
            input[1] = (ulong)lane;
            input[2] = (ulong)slice;
            input[3] = (ulong)ctx.BlockCount;
            input[4] = (ulong)ctx.Passes;
            input[5] = TypeId;
        }

        var startingIndex = 0;
        if (pass == 0 && slice == 0)
        {
            startingIndex = 2; // blocks 0 and 1 were seeded from H0
            if (dataIndependent) NextAddresses(address, input, zero, r, tmp);
        }

        long currentOffset = (long)lane * ctx.LaneLength + slice * ctx.SegmentLength + startingIndex;
        long previousOffset = currentOffset % ctx.LaneLength == 0
            ? currentOffset + ctx.LaneLength - 1
            : currentOffset - 1;

        for (var i = startingIndex; i < ctx.SegmentLength; i++, currentOffset++, previousOffset++)
        {
            if (currentOffset % ctx.LaneLength == 1)
                previousOffset = currentOffset - 1;

            ulong pseudoRandom;
            if (dataIndependent)
            {
                if (i % BlockWords == 0) NextAddresses(address, input, zero, r, tmp);
                pseudoRandom = address[i % BlockWords];
            }
            else
            {
                pseudoRandom = ctx.Memory[previousOffset * BlockWords];
            }

            var referenceLane = (int)((pseudoRandom >> 32) % (ulong)ctx.Lanes);
            if (pass == 0 && slice == 0)
                referenceLane = lane;

            var referenceIndex = IndexAlpha(ctx, pass, slice, i, (uint)pseudoRandom, referenceLane == lane);
            var reference = ctx.Block((long)ctx.LaneLength * referenceLane + referenceIndex);
            var previous = ctx.Block(previousOffset);
            var current = ctx.Block(currentOffset);

            // Version 0x13: from the second pass on, the new block is XORed into the old one.
            FillBlock(previous, reference, current, withXor: pass != 0, r, tmp);
        }

        address.Clear(); input.Clear(); r.Clear(); tmp.Clear();
    }

    private static void NextAddresses(Span<ulong> address, Span<ulong> input, ReadOnlySpan<ulong> zero, Span<ulong> r, Span<ulong> tmp)
    {
        input[6]++;
        FillBlock(zero, input, address, withXor: false, r, tmp);
        FillBlock(zero, address, address, withXor: false, r, tmp);
    }

    private static uint IndexAlpha(Context ctx, int pass, int slice, int index, uint pseudoRandom, bool sameLane)
    {
        uint referenceAreaSize;
        if (pass == 0)
        {
            if (slice == 0)
                referenceAreaSize = (uint)(index - 1); // everything so far except the previous block
            else if (sameLane)
                referenceAreaSize = (uint)(slice * ctx.SegmentLength + index - 1);
            else
                referenceAreaSize = (uint)(slice * ctx.SegmentLength + (index == 0 ? -1 : 0));
        }
        else
        {
            if (sameLane)
                referenceAreaSize = (uint)(ctx.LaneLength - ctx.SegmentLength + index - 1);
            else
                referenceAreaSize = (uint)(ctx.LaneLength - ctx.SegmentLength + (index == 0 ? -1 : 0));
        }

        // Map the 32-bit pseudo-random value non-uniformly onto the reference area, biased
        // towards recent blocks (RFC 9106 §3.4.2).
        ulong relative = pseudoRandom;
        relative = (relative * relative) >> 32;
        relative = referenceAreaSize - 1 - ((referenceAreaSize * relative) >> 32);

        ulong start = 0;
        if (pass != 0)
            start = slice == SyncPoints - 1 ? 0UL : (ulong)((slice + 1) * ctx.SegmentLength);

        return (uint)((start + relative) % (ulong)ctx.LaneLength);
    }

    /// <summary>
    /// The compression function G: next = P(prev ^ ref) ^ (prev ^ ref) [^ next], where P
    /// applies the BLAKE2b-derived round to the eight rows and then the eight columns.
    /// </summary>
    private static void FillBlock(ReadOnlySpan<ulong> previous, ReadOnlySpan<ulong> reference, Span<ulong> next,
        bool withXor, Span<ulong> r, Span<ulong> tmp)
    {
        for (var i = 0; i < BlockWords; i++)
            r[i] = reference[i] ^ previous[i];
        r.CopyTo(tmp);
        if (withXor)
            for (var i = 0; i < BlockWords; i++)
                tmp[i] ^= next[i];

        ref var v = ref MemoryMarshal.GetReference(r);

        for (var i = 0; i < 8; i++)
        {
            var b = 16 * i;
            Round(ref v, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15);
        }
        for (var i = 0; i < 8; i++)
        {
            var b = 2 * i;
            Round(ref v, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113);
        }

        for (var i = 0; i < BlockWords; i++)
            next[i] = tmp[i] ^ r[i];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Round(ref ulong v,
        int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7,
        int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15)
    {
        GB(ref v, v0, v4, v8, v12);
        GB(ref v, v1, v5, v9, v13);
        GB(ref v, v2, v6, v10, v14);
        GB(ref v, v3, v7, v11, v15);
        GB(ref v, v0, v5, v10, v15);
        GB(ref v, v1, v6, v11, v12);
        GB(ref v, v2, v7, v8, v13);
        GB(ref v, v3, v4, v9, v14);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void GB(ref ulong v, int ia, int ib, int ic, int id)
    {
        ref var a = ref Unsafe.Add(ref v, ia);
        ref var b = ref Unsafe.Add(ref v, ib);
        ref var c = ref Unsafe.Add(ref v, ic);
        ref var d = ref Unsafe.Add(ref v, id);

        a = a + b + 2 * Lo(a) * Lo(b);
        d = RotR(d ^ a, 32);
        c = c + d + 2 * Lo(c) * Lo(d);
        b = RotR(b ^ c, 24);
        a = a + b + 2 * Lo(a) * Lo(b);
        d = RotR(d ^ a, 16);
        c = c + d + 2 * Lo(c) * Lo(d);
        b = RotR(b ^ c, 63);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong Lo(ulong x) => x & 0xFFFFFFFFUL;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong RotR(ulong x, int n) => (x >> n) | (x << (64 - n));

    private static void Xor(Span<ulong> target, ReadOnlySpan<ulong> source)
    {
        for (var i = 0; i < BlockWords; i++)
            target[i] ^= source[i];
    }

    private static void LoadBlock(Span<ulong> block, ReadOnlySpan<byte> bytes)
    {
        for (var i = 0; i < BlockWords; i++)
            block[i] = BinaryPrimitives.ReadUInt64LittleEndian(bytes[(i * 8)..]);
    }

    private static void StoreBlock(Span<byte> bytes, ReadOnlySpan<ulong> block)
    {
        for (var i = 0; i < BlockWords; i++)
            BinaryPrimitives.WriteUInt64LittleEndian(bytes[(i * 8)..], block[i]);
    }
}
