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
                16 => IPRangeParserCore.ParseIPv6Range(startBytes, endBytes),
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
                16 => IPRangeParserCore.ParseIPv6Range(startBytes, endBytes),
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