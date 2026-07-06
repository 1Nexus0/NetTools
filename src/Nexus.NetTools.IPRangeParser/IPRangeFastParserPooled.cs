using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Runtime.CompilerServices;
using System.Threading;
using Nexus.NetTools.IPRangeParser.Core;
using Nexus.NetTools.IPRangeParser.Helpers;

namespace Nexus.NetTools.IPRangeParser
{
    /// <summary>
    /// Cached version of IPRangeFastParser with LRU cache for maximum performance
    /// Thread-safe for concurrent access using ConcurrentDictionary
    /// </summary>
    public static class IPRangeFastParserPooled
    {
        // IPv4 cache with LRU eviction
        private static readonly ConcurrentDictionary<uint, string> _ipv4Cache = new();
        private static readonly ConcurrentQueue<uint> _ipv4AccessOrder = new();
        private static int _ipv4CacheSize = 0;
        private const int MaxIpv4CacheSize = 1000;

        // IPv6 cache with LRU eviction
        private static readonly ConcurrentDictionary<Ipv6Key, string> _ipv6Cache = new();
        private static readonly ConcurrentQueue<Ipv6Key> _ipv6AccessOrder = new();
        private static int _ipv6CacheSize = 0;
        private const int MaxIpv6CacheSize = 500;

        #region Public API

        /// <summary>
        /// Parses an IP range from byte arrays and returns CIDR blocks (cached)
        /// </summary>
        public static IEnumerable<string> ParseRange(byte[] startBytes, byte[] endBytes)
        {
            RangeParserHelper.ValidateByteArrays(startBytes, endBytes);

            return startBytes.Length switch
            {
                4 => ParseIPv4Range(IPRangeParserCore.BytesToUInt32(startBytes), IPRangeParserCore.BytesToUInt32(endBytes)),
                16 => ParseIPv6Range(startBytes, endBytes),
                _ => throw new ArgumentException("Only IPv4 (4 bytes) and IPv6 (16 bytes) supported")
            };
        }

        /// <summary>
        /// Parses an IP range from IPAddress objects and returns CIDR blocks (cached)
        /// </summary>
        public static IEnumerable<string> ParseRange(IPAddress startIp, IPAddress endIp)
        {
            RangeParserHelper.ValidateIpAddresses(startIp, endIp);

            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();

            return startBytes.Length switch
            {
                4 => ParseIPv4Range(IPRangeParserCore.BytesToUInt32(startBytes), IPRangeParserCore.BytesToUInt32(endBytes)),
                16 => ParseIPv6Range(startBytes, endBytes),
                _ => throw new ArgumentException("Only IPv4 (4 bytes) and IPv6 (16 bytes) supported")
            };
        }

        /// <summary>
        /// Parses an IP range from string addresses and returns CIDR blocks (cached)
        /// </summary>
        public static IEnumerable<string> ParseRange(string startIp, string endIp)
        {
            return ParseRange(IPAddress.Parse(startIp), IPAddress.Parse(endIp));
        }

        /// <summary>
        /// Parses an IP range from a string in the format "startIP - endIP" and returns CIDR blocks (cached)
        /// </summary>
        public static IEnumerable<string> ParseRange(string range)
        {
            var (start, end) = RangeParserHelper.ParseRangeParts(range);
            return ParseRange(start, end);
        }

        /// <summary>
        /// Clears all caches
        /// </summary>
        public static void Clear()
        {
            _ipv4Cache.Clear();
            _ipv4AccessOrder.Clear();
            Interlocked.Exchange(ref _ipv4CacheSize, 0);

            _ipv6Cache.Clear();
            _ipv6AccessOrder.Clear();
            Interlocked.Exchange(ref _ipv6CacheSize, 0);
        }

        /// <summary>
        /// Gets the current cache size
        /// </summary>
        public static (int Ipv4Count, int Ipv6Count) GetCacheSize()
        {
            return (_ipv4Cache.Count, _ipv6Cache.Count);
        }

        #endregion

        #region IPv4 Implementation with Caching

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<string> ParseIPv4Range(uint start, uint end)
        {
            if (start > end)
                throw new ArgumentException("Start IP must be <= End IP");

            return ParseIPv4RangeInternal(start, end);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<string> ParseIPv4RangeInternal(uint start, uint end)
        {
            if (end - start <= 3)
            {
                uint ip = start;
                while (true)
                {
                    string ipString = GetIPv4String(ip);
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
                string ipString = GetIPv4String(current);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static string GetIPv4String(uint ip)
        {
            if (_ipv4Cache.TryGetValue(ip, out string? cached))
            {
                _ipv4AccessOrder.Enqueue(ip);
                return cached;
            }

            string result = IPRangeParserCore.UInt32ToIPv4String(ip);

            if (_ipv4Cache.TryAdd(ip, result))
            {
                _ipv4AccessOrder.Enqueue(ip);
                int newSize = Interlocked.Increment(ref _ipv4CacheSize);

                if (newSize > MaxIpv4CacheSize)
                {
                    EvictIPv4();
                }
            }
            else
            {
                if (_ipv4Cache.TryGetValue(ip, out cached))
                {
                    _ipv4AccessOrder.Enqueue(ip);
                    return cached;
                }
            }

            return result;
        }

        private static void EvictIPv4()
        {
            int toEvict = Math.Max(1, MaxIpv4CacheSize / 10);
            int evicted = 0;

            while (evicted < toEvict && _ipv4AccessOrder.TryDequeue(out uint key))
            {
                if (_ipv4Cache.TryRemove(key, out _))
                {
                    Interlocked.Decrement(ref _ipv4CacheSize);
                    evicted++;
                }
            }
        }

        #endregion

        #region IPv6 Implementation with Caching

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<string> ParseIPv6Range(byte[] startBytes, byte[] endBytes)
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
        private static IEnumerable<string> ParseIPv6RangeInternal(Ipv6Address start, Ipv6Address end)
        {
            if (IsSmallIPv6Range(start, end))
            {
                Ipv6Address ip = start;
                while (Compare128(ip, end) <= 0)
                {
                    // Use cached version for individual IP strings
                    string ipString = GetIPv6String(ip.H1, ip.H2, ip.H3, ip.H4);
                    yield return $"{ipString}/128";
                    AddTo128(ref ip, 1);
                }
                yield break;
            }

            Ipv6Address current = start;
            while (Compare128(current, end) <= 0)
            {
                int cidr = FindMaxCidrIPv6(ref current, end);
                // Use cached version for individual IP strings
                string ipString = GetIPv6String(current.H1, current.H2, current.H3, current.H4);
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
        private static int Compare128(Ipv6Address a, Ipv6Address b)
        {
            if (a.H1 != b.H1) return a.H1 > b.H1 ? 1 : -1;
            if (a.H2 != b.H2) return a.H2 > b.H2 ? 1 : -1;
            if (a.H3 != b.H3) return a.H3 > b.H3 ? 1 : -1;
            if (a.H4 != b.H4) return a.H4 > b.H4 ? 1 : -1;
            return 0;
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
        private static string GetIPv6String(uint h1, uint h2, uint h3, uint h4)
        {
            var key = new Ipv6Key(h1, h2, h3, h4);

            if (_ipv6Cache.TryGetValue(key, out string? cached))
            {
                _ipv6AccessOrder.Enqueue(key);
                return cached;
            }

            string result = IPRangeParserCore.UInt128ToIPv6String(h1, h2, h3, h4);

            if (_ipv6Cache.TryAdd(key, result))
            {
                _ipv6AccessOrder.Enqueue(key);
                int newSize = Interlocked.Increment(ref _ipv6CacheSize);

                if (newSize > MaxIpv6CacheSize)
                {
                    EvictIPv6();
                }
            }
            else
            {
                if (_ipv6Cache.TryGetValue(key, out cached))
                {
                    _ipv6AccessOrder.Enqueue(key);
                    return cached;
                }
            }

            return result;
        }

        private static void EvictIPv6()
        {
            int toEvict = Math.Max(1, MaxIpv6CacheSize / 10);
            int evicted = 0;

            while (evicted < toEvict && _ipv6AccessOrder.TryDequeue(out Ipv6Key key))
            {
                if (_ipv6Cache.TryRemove(key, out _))
                {
                    Interlocked.Decrement(ref _ipv6CacheSize);
                    evicted++;
                }
            }
        }

        #endregion

        #region Helper Structures

        private readonly struct Ipv6Key : IEquatable<Ipv6Key>
        {
            public readonly uint H1;
            public readonly uint H2;
            public readonly uint H3;
            public readonly uint H4;

            public Ipv6Key(uint h1, uint h2, uint h3, uint h4)
            {
                H1 = h1;
                H2 = h2;
                H3 = h3;
                H4 = h4;
            }

            public bool Equals(Ipv6Key other)
            {
                return H1 == other.H1 && H2 == other.H2 && H3 == other.H3 && H4 == other.H4;
            }

            public override bool Equals(object? obj)
            {
                return obj is Ipv6Key key && Equals(key);
            }

            public override int GetHashCode()
            {
                return HashCode.Combine(H1, H2, H3, H4);
            }
        }

        #endregion
    }
}