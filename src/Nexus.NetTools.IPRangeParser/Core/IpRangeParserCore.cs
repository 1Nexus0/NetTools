using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace Nexus.NetTools.IPRangeParser.Core
{
    /// <summary>
    /// 128-bit IPv6 address representation (Big Endian / Network Byte Order)
    /// </summary>
    public readonly struct Ipv6Address
    {
        public readonly uint H1; // Bits 96-127
        public readonly uint H2; // Bits 64-95
        public readonly uint H3; // Bits 32-63
        public readonly uint H4; // Bits 0-31

        public Ipv6Address(uint h1, uint h2, uint h3, uint h4)
        {
            H1 = h1;
            H2 = h2;
            H3 = h3;
            H4 = h4;
        }
    }

    public readonly struct ZeroRun
    {
        public readonly int Start;
        public readonly int Length;

        public ZeroRun(int start, int length)
        {
            Start = start;
            Length = length;
        }
    }

    /// <summary>
    /// Internal core logic shared between fast and pooled parsers
    /// </summary>
    internal static class IPRangeParserCore
    {
        // Pre-computed hex digits for faster conversion
        private static readonly char[] _hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

        #region Internal API

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static IEnumerable<string> ParseIPv4Range(uint start, uint end)
        {
            if (start > end)
                throw new ArgumentException("Start IP must be <= End IP");

            return ParseIPv4RangeInternal(start, end);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static IEnumerable<string> ParseIPv6Range(byte[] startBytes, byte[] endBytes)
        {
            var start = new Ipv6Address(
                (uint)((startBytes[0] << 24) | (startBytes[1] << 16) | (startBytes[2] << 8) | startBytes[3]),
                (uint)((startBytes[4] << 24) | (startBytes[5] << 16) | (startBytes[6] << 8) | startBytes[7]),
                (uint)((startBytes[8] << 24) | (startBytes[9] << 16) | (startBytes[10] << 8) | startBytes[11]),
                (uint)((startBytes[12] << 24) | (startBytes[13] << 16) | (startBytes[14] << 8) | startBytes[15])
            );

            var end = new Ipv6Address(
                (uint)((endBytes[0] << 24) | (endBytes[1] << 16) | (endBytes[2] << 8) | endBytes[3]),
                (uint)((endBytes[4] << 24) | (endBytes[5] << 16) | (endBytes[6] << 8) | endBytes[7]),
                (uint)((endBytes[8] << 24) | (endBytes[9] << 16) | (endBytes[10] << 8) | endBytes[11]),
                (uint)((endBytes[12] << 24) | (endBytes[13] << 16) | (endBytes[14] << 8) | endBytes[15])
            );

            if (Compare128(start, end) > 0)
                throw new ArgumentException("Start IP must be <= End IP");

            return ParseIPv6RangeInternal(start, end);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static string UInt32ToIPv4String(uint ip)
        {
            return $"{ip >> 24 & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}";
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static string UInt128ToIPv6String(uint h1, uint h2, uint h3, uint h4)
        {
            Span<ushort> parts = stackalloc ushort[8];
            parts[0] = (ushort)((h1 >> 16) & 0xFFFF);
            parts[1] = (ushort)(h1 & 0xFFFF);
            parts[2] = (ushort)((h2 >> 16) & 0xFFFF);
            parts[3] = (ushort)(h2 & 0xFFFF);
            parts[4] = (ushort)((h3 >> 16) & 0xFFFF);
            parts[5] = (ushort)(h3 & 0xFFFF);
            parts[6] = (ushort)((h4 >> 16) & 0xFFFF);
            parts[7] = (ushort)(h4 & 0xFFFF);

            var zeroRun = FindLongestZeroRun(parts);

            Span<char> span = stackalloc char[39];
            int pos = 0;
            int i = 0;

            while (i < 8)
            {
                if (i == zeroRun.Start && zeroRun.Length > 1)
                {
                    if (i == 0)
                    {
                        span[pos++] = ':';
                        span[pos++] = ':';
                    }
                    else
                    {
                        if (pos > 0 && span[pos - 1] != ':')
                            span[pos++] = ':';
                        span[pos++] = ':';
                    }
                    i += zeroRun.Length;
                    continue;
                }

                if (i > 0 && pos > 0 && span[pos - 1] != ':')
                    span[pos++] = ':';

                if (parts[i] == 0)
                {
                    span[pos++] = '0';
                }
                else
                {
                    bool started = false;
                    for (int shift = 12; shift >= 0; shift -= 4)
                    {
                        int digit = (parts[i] >> shift) & 0xF;
                        if (digit != 0 || started || shift == 0)
                        {
                            started = true;
                            span[pos++] = _hexDigits[digit];
                        }
                    }
                }

                i++;
            }

            return new string(span[..pos]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint BytesToUInt32(byte[] bytes)
        {
            return (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
        }

        #endregion

        #region IPv4 Implementation

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<string> ParseIPv4RangeInternal(uint start, uint end)
        {
            if (end - start <= 3)
            {
                uint ip = start;
                while (true)
                {
                    string ipString = UInt32ToIPv4String(ip);
                    yield return $"{ipString}/32";
                    if (ip == end) break;
                    ip++;
                }
                yield break;
            }

            uint current = start;
            while (current <= end)
            {
                int cidr = FindMaxCidrIPv4(current, end);
                string ipString = UInt32ToIPv4String(current);
                yield return $"{ipString}/{cidr}";

                if (cidr == 0)
                {
                    yield break;
                }

                uint blockSize = 1u << (32 - cidr);
                current += blockSize;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int FindMaxCidrIPv4(uint current, uint end)
        {
            for (int cidr = 0; cidr <= 32; cidr++)
            {
                if (cidr == 0)
                {
                    if (current == 0 && end == 0xFFFFFFFF)
                        return 0;
                    continue;
                }

                uint blockSize = 1u << (32 - cidr);

                if ((current & (blockSize - 1)) != 0)
                    continue;

                if (current <= end - blockSize + 1)
                {
                    return cidr;
                }
            }

            return 32;
        }

        #endregion

        #region IPv6 Implementation

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<string> ParseIPv6RangeInternal(Ipv6Address start, Ipv6Address end)
        {
            if (IsSmallIPv6Range(start, end))
            {
                Ipv6Address ip = start;
                while (Compare128(ip, end) <= 0)
                {
                    string ipString = UInt128ToIPv6String(ip.H1, ip.H2, ip.H3, ip.H4);
                    yield return $"{ipString}/128";
                    AddTo128(ref ip, 1);
                }
                yield break;
            }

            Ipv6Address current = start;
            while (Compare128(current, end) <= 0)
            {
                int cidr = FindMaxCidrIPv6(ref current, end);
                string ipString = UInt128ToIPv6String(current.H1, current.H2, current.H3, current.H4);
                yield return $"{ipString}/{cidr}";

                int shiftAmount = 128 - cidr;
                AddBlockSizeTo128(ref current, shiftAmount);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsSmallIPv6Range(Ipv6Address start, Ipv6Address end)
        {
            uint d4 = end.H4 - start.H4;
            if (d4 > 7) return false;

            return end.H1 == start.H1 && end.H2 == start.H2 && end.H3 == start.H3;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddBlockSizeTo128(ref Ipv6Address value, int shiftAmount)
        {
            if (shiftAmount < 32)
            {
                uint addValue = 1u << shiftAmount;
                AddTo128(ref value, addValue);
            }
            else if (shiftAmount < 64)
            {
                ulong addValue = 1UL << (shiftAmount - 32);
                AddTo128(ref value, addValue << 32);
            }
            else if (shiftAmount < 96)
            {
                uint addValue = 1u << (shiftAmount - 64);
                AddTo128High(ref value, addValue);
            }
            else if (shiftAmount < 128)
            {
                uint addValue = 1u << (shiftAmount - 96);
                AddTo128Highest(ref value, addValue);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddTo128Highest(ref Ipv6Address value, uint addValue)
        {
            ulong sum = (ulong)value.H1 + addValue;
            uint h1 = (uint)sum;
            value = new Ipv6Address(h1, value.H2, value.H3, value.H4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int FindMaxCidrIPv6(ref Ipv6Address current, Ipv6Address end)
        {
            // Fast path for common CIDR boundaries
            if ((current.H1 & 0xFFFF) == 0 && current.H2 == 0 && current.H3 == 0 && current.H4 == 0)
            {
                if ((end.H1 & 0xFFFF) == 0xFFFF && end.H2 == 0xFFFFFFFF && end.H3 == 0xFFFFFFFF && end.H4 == 0xFFFFFFFF)
                {
                    return 16;
                }
            }

            if (current.H2 == 0 && current.H3 == 0 && current.H4 == 0)
            {
                if (end.H2 == 0xFFFFFFFF && end.H3 == 0xFFFFFFFF && end.H4 == 0xFFFFFFFF)
                {
                    return 32;
                }
            }

            if ((current.H2 & 0xFFFF) == 0 && current.H3 == 0 && current.H4 == 0)
            {
                if ((end.H2 & 0xFFFF) == 0xFFFF && end.H3 == 0xFFFFFFFF && end.H4 == 0xFFFFFFFF)
                {
                    return 48;
                }
            }

            if (current.H3 == 0 && current.H4 == 0)
            {
                if (end.H3 == 0xFFFFFFFF && end.H4 == 0xFFFFFFFF)
                {
                    return 64;
                }
            }

            if (current.H4 == 0)
            {
                if (end.H4 == 0xFFFFFFFF)
                {
                    return 96;
                }
            }

            for (int cidr = 0; cidr <= 128; cidr++)
            {
                if (cidr == 0)
                {
                    if (current.H1 == 0 && current.H2 == 0 && current.H3 == 0 && current.H4 == 0 &&
                        end.H1 == 0xFFFFFFFF && end.H2 == 0xFFFFFFFF && end.H3 == 0xFFFFFFFF && end.H4 == 0xFFFFFFFF)
                        return 0;
                    continue;
                }

                int shift = 128 - cidr;

                if (!IsAligned128(current, shift))
                    continue;

                if (BlockFits128(current, end, shift))
                {
                    return cidr;
                }
            }

            return 128;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool BlockFits128(Ipv6Address current, Ipv6Address end, int shift)
        {
            uint d4 = end.H4 - current.H4;
            uint borrow = (end.H4 < current.H4) ? 1u : 0u;

            uint d3 = end.H3 - current.H3 - borrow;
            borrow = (end.H3 < current.H3 || (end.H3 == current.H3 && borrow > 0)) ? 1u : 0u;

            uint d2 = end.H2 - current.H2 - borrow;
            borrow = (end.H2 < current.H2 || (end.H2 == current.H2 && borrow > 0)) ? 1u : 0u;

            uint d1 = end.H1 - current.H1 - borrow;

            if (shift == 0)
                return true;

            if (shift < 32)
            {
                if (d1 != 0 || d2 != 0 || d3 != 0) return true;
                uint blockSize = (1u << shift) - 1;
                return d4 >= blockSize;
            }
            else if (shift < 64)
            {
                if (d1 != 0 || d2 != 0) return true;
                uint blockSize = (1u << (shift - 32)) - 1;
                if (d3 > blockSize) return true;
                if (d3 < blockSize) return false;
                return d4 >= 0xFFFFFFFF;
            }
            else if (shift < 96)
            {
                if (d1 != 0) return true;
                uint blockSize = (1u << (shift - 64)) - 1;
                if (d2 > blockSize) return true;
                if (d2 < blockSize) return false;
                return d3 == 0xFFFFFFFF && d4 == 0xFFFFFFFF;
            }
            else
            {
                uint blockSize = (1u << (shift - 96)) - 1;
                if (d1 > blockSize) return true;
                if (d1 < blockSize) return false;
                return d2 == 0xFFFFFFFF && d3 == 0xFFFFFFFF && d4 == 0xFFFFFFFF;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static bool IsAligned128(Ipv6Address value, int shift)
        {
            if (shift >= 96)
            {
                int localShift = shift - 96;
                uint mask = localShift >= 32 ? 0 : (1u << localShift) - 1;
                return (value.H2 | value.H3 | value.H4) == 0 && (value.H1 & mask) == 0;
            }
            else if (shift >= 64)
            {
                int localShift = shift - 64;
                uint mask = localShift >= 32 ? 0 : (1u << localShift) - 1;
                return (value.H3 | value.H4) == 0 && (value.H2 & mask) == 0;
            }
            else if (shift >= 32)
            {
                int localShift = shift - 32;
                uint mask = localShift >= 32 ? 0 : (1u << localShift) - 1;
                return value.H4 == 0 && (value.H3 & mask) == 0;
            }
            else
            {
                uint mask = shift >= 32 ? 0 : (1u << shift) - 1;
                return (value.H4 & mask) == 0;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddTo128(ref Ipv6Address value, ulong addValue)
        {
            ulong sum = (ulong)value.H4 + (addValue & 0xFFFFFFFF);
            uint h4 = (uint)sum;
            ulong carry = sum >> 32;

            sum = (ulong)value.H3 + (addValue >> 32) + carry;
            uint h3 = (uint)sum;
            carry = sum >> 32;

            uint h2 = value.H2;
            uint h1 = value.H1;

            if (carry > 0)
            {
                sum = (ulong)h2 + carry;
                h2 = (uint)sum;
                carry = sum >> 32;

                if (carry > 0)
                {
                    sum = (ulong)h1 + carry;
                    h1 = (uint)sum;
                }
            }

            value = new Ipv6Address(h1, h2, h3, h4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void AddTo128High(ref Ipv6Address value, uint addValue)
        {
            ulong sum = (ulong)value.H2 + addValue;
            uint h2 = (uint)sum;
            ulong carry = sum >> 32;

            if (carry > 0)
            {
                sum = (ulong)value.H1 + carry;
                uint h1 = (uint)sum;
                value = new Ipv6Address(h1, h2, value.H3, value.H4);
            }
            else
            {
                value = new Ipv6Address(value.H1, h2, value.H3, value.H4);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static int Compare128(Ipv6Address a, Ipv6Address b)
        {
            if (a.H1 != b.H1) return a.H1 > b.H1 ? 1 : -1;
            if (a.H2 != b.H2) return a.H2 > b.H2 ? 1 : -1;
            if (a.H3 != b.H3) return a.H3 > b.H3 ? 1 : -1;
            if (a.H4 != b.H4) return a.H4 > b.H4 ? 1 : -1;
            return 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ZeroRun FindLongestZeroRun(Span<ushort> parts)
        {
            int bestStart = -1;
            int bestLen = 0;
            int i = 0;

            while (i < 8)
            {
                if (parts[i] == 0)
                {
                    int start = i;
                    while (i < 8 && parts[i] == 0) i++;
                    int len = i - start;
                    if (len > bestLen)
                    {
                        bestLen = len;
                        bestStart = start;
                    }
                }
                else
                {
                    i++;
                }
            }

            return new ZeroRun(bestStart, bestLen);
        }

        #endregion
    }
}