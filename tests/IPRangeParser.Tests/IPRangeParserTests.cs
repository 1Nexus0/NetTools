using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Nexus.NetTools.IPRangeParser;
using Xunit;

namespace Nexus.NetTools.IPRangeParser.Tests
{
    public class IPRangeParserTests
    {
        #region IPv4 Tests

        [Fact]
        public void ParseRange_IPv4_SingleIP_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 1 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("192.168.1.1/32", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_SmallRange_ReturnsCorrectCIDRs()
        {
            var start = new byte[] { 192, 168, 0, 1 };
            var end = new byte[] { 192, 168, 0, 31 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var expected = new[]
            {
                "192.168.0.1/32",
                "192.168.0.2/31",
                "192.168.0.4/30",
                "192.168.0.8/29",
                "192.168.0.16/28"
            };
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ParseRange_IPv4_ClassCRange_ReturnsCorrectCIDRs()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var expected = new[]
            {
                "192.168.1.1/32",
                "192.168.1.2/31",
                "192.168.1.4/30",
                "192.168.1.8/29",
                "192.168.1.16/28",
                "192.168.1.32/27",
                "192.168.1.64/26",
                "192.168.1.128/25"
            };
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ParseRange_IPv4_ClassBRange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 10, 0, 0, 0 };
            var end = new byte[] { 10, 0, 255, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("10.0.0.0/16", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_ClassARange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 10, 0, 0, 0 };
            var end = new byte[] { 10, 255, 255, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("10.0.0.0/8", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_PrivateClassBRange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 172, 16, 0, 0 };
            var end = new byte[] { 172, 31, 255, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("172.16.0.0/12", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_FullRange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 0, 0, 0, 0 };
            var end = new byte[] { 255, 255, 255, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("0.0.0.0/0", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_ArbitraryRange_ReturnsCorrectCIDRs()
        {
            var start = new byte[] { 192, 168, 1, 100 };
            var end = new byte[] { 192, 168, 1, 200 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var expected = new[]
            {
                "192.168.1.100/30",
                "192.168.1.104/29",
                "192.168.1.112/28",
                "192.168.1.128/26",
                "192.168.1.192/29",
                "192.168.1.200/32"
            };
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ParseRange_IPv4_InvalidRange_ThrowsException()
        {
            var start = new byte[] { 192, 168, 1, 100 };
            var end = new byte[] { 192, 168, 1, 50 };
            Assert.Throws<ArgumentException>(() => IPRangeFastParser.ParseRange(start, end).ToList());
        }

        [Fact]
        public void ParseRange_IPv4_ZeroRange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 0, 0, 0, 0 };
            var end = new byte[] { 0, 0, 0, 0 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("0.0.0.0/32", result[0]);
        }

        [Fact]
        public void ParseRange_IPv4_BroadcastRange_ReturnsCorrectCIDR()
        {
            var start = new byte[] { 255, 255, 255, 255 };
            var end = new byte[] { 255, 255, 255, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("255.255.255.255/32", result[0]);
        }

        #endregion

        #region IPv4 Coverage Verification Tests

        [Fact]
        public void ParseRange_IPv4_CIDRBlocks_NoOverlaps()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 255 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var ranges = new List<(uint Start, uint End)>();
            uint startVal = (uint)((start[0] << 24) | (start[1] << 16) | (start[2] << 8) | start[3]);
            uint endVal = (uint)((end[0] << 24) | (end[1] << 16) | (end[2] << 8) | end[3]);

            foreach (var block in result)
            {
                var parts = block.Split('/');
                var ip = IPAddress.Parse(parts[0]).GetAddressBytes();
                var cidr = int.Parse(parts[1]);

                uint ipVal = (uint)((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]);
                uint blockSize = 1u << (32 - cidr);
                uint blockEnd = ipVal + blockSize - 1;

                Assert.True(ipVal >= startVal && blockEnd <= endVal,
                    $"Block {block} is outside the range");

                foreach (var existing in ranges)
                {
                    Assert.True(existing.End < ipVal || existing.Start > blockEnd,
                        $"Overlap detected: {existing.Start} - {existing.End} overlaps with {ipVal} - {blockEnd}");
                }

                ranges.Add((ipVal, blockEnd));
            }

            uint totalSize = 0;
            foreach (var range in ranges)
            {
                totalSize += range.End - range.Start + 1;
            }
            Assert.Equal(endVal - startVal + 1, totalSize);

            for (int i = 1; i < ranges.Count; i++)
            {
                Assert.True(ranges[i - 1].End < ranges[i].Start,
                    $"Blocks not properly sorted: {result[i - 1]} then {result[i]}");
            }
        }

        [Fact]
        public void ParseRange_IPv4_CIDRBlocks_NoGaps()
        {
            var start = new byte[] { 192, 168, 1, 100 };
            var end = new byte[] { 192, 168, 1, 200 };
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var ranges = new List<(uint Start, uint End)>();
            uint startVal = (uint)((start[0] << 24) | (start[1] << 16) | (start[2] << 8) | start[3]);
            uint endVal = (uint)((end[0] << 24) | (end[1] << 16) | (end[2] << 8) | end[3]);

            foreach (var block in result)
            {
                var parts = block.Split('/');
                var ip = IPAddress.Parse(parts[0]).GetAddressBytes();
                var cidr = int.Parse(parts[1]);

                uint ipVal = (uint)((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]);
                uint blockSize = 1u << (32 - cidr);
                uint blockEnd = ipVal + blockSize - 1;

                ranges.Add((ipVal, blockEnd));
            }

            ranges.Sort((a, b) => a.Start.CompareTo(b.Start));

            for (int i = 1; i < ranges.Count; i++)
            {
                Assert.Equal(ranges[i - 1].End + 1, ranges[i].Start);
            }

            Assert.Equal(startVal, ranges[0].Start);
            Assert.Equal(endVal, ranges[^1].End);
        }

        [Fact]
        public void ParseRange_IPv4_CIDRBlocks_ExactCoverage()
        {
            var testRanges = new[]
            {
                new { Start = new byte[] { 192, 168, 0, 1 }, End = new byte[] { 192, 168, 0, 31 } },
                new { Start = new byte[] { 10, 0, 0, 0 }, End = new byte[] { 10, 0, 255, 255 } },
                new { Start = new byte[] { 192, 168, 1, 100 }, End = new byte[] { 192, 168, 1, 200 } },
            };

            foreach (var test in testRanges)
            {
                var result = IPRangeFastParser.ParseRange(test.Start, test.End).ToList();
                uint totalIPs = 0;

                foreach (var block in result)
                {
                    var parts = block.Split('/');
                    var cidr = int.Parse(parts[1]);
                    totalIPs += 1u << (32 - cidr);
                }

                uint startVal = (uint)((test.Start[0] << 24) | (test.Start[1] << 16) | (test.Start[2] << 8) | test.Start[3]);
                uint endVal = (uint)((test.End[0] << 24) | (test.End[1] << 16) | (test.End[2] << 8) | test.End[3]);
                uint expectedIPs = endVal - startVal + 1;

                Assert.Equal(expectedIPs, totalIPs);
            }
        }

        #endregion

        #region IPv6 Tests

        [Fact]
        public void ParseRange_IPv6_SingleIP_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 1);
            var end = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 1);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("::1/128", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_TwoIPs_ReturnsCorrectCIDRs()
        {
            var start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 1);
            var end = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 2);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var expected = new[] { "::1/128", "::2/128" };
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ParseRange_IPv6_124Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 15);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("::/124", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_120Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 255);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("::/120", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_112Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/112", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_96Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/96", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_64Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/64", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_48Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/48", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_32Range_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/32", result[0]);
        }

        [Fact]
        public void ParseRange_IPv6_InvalidRange_ThrowsException()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 10);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 5);
            var ex = Assert.Throws<ArgumentException>(() => IPRangeFastParser.ParseRange(start, end).ToList());
            Assert.Contains("Start IP must be <= End IP", ex.Message);
        }

        [Fact]
        public void ParseRange_IPv6_ZeroRange_ReturnsCorrectCIDR()
        {
            var start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 0);
            var end = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 0);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("::/128", result[0]);
        }

        #endregion

        #region IPv6 Coverage Verification Tests

        [Fact]
        public void ParseRange_IPv6_CIDRBlocks_NoOverlaps()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var ranges = new List<(System.Numerics.BigInteger Start, System.Numerics.BigInteger End)>();
            var startVal = new System.Numerics.BigInteger(start, isUnsigned: true, isBigEndian: true);
            var endVal = new System.Numerics.BigInteger(end, isUnsigned: true, isBigEndian: true);

            foreach (var block in result)
            {
                var parts = block.Split('/');
                var ip = IPAddress.Parse(parts[0]).GetAddressBytes();
                var cidr = int.Parse(parts[1]);

                var ipVal = new System.Numerics.BigInteger(ip, isUnsigned: true, isBigEndian: true);
                var blockSize = System.Numerics.BigInteger.Pow(2, 128 - cidr);
                var blockEnd = ipVal + blockSize - 1;

                Assert.True(ipVal >= startVal && blockEnd <= endVal,
                    $"Block {block} is outside the range");

                foreach (var existing in ranges)
                {
                    Assert.True(existing.End < ipVal || existing.Start > blockEnd,
                        $"Overlap detected: {existing.Start} - {existing.End} overlaps with {ipVal} - {blockEnd}");
                }

                ranges.Add((ipVal, blockEnd));
            }

            var totalSize = System.Numerics.BigInteger.Zero;
            foreach (var range in ranges)
            {
                totalSize += range.End - range.Start + 1;
            }
            Assert.Equal(endVal - startVal + 1, totalSize);

            for (int i = 1; i < ranges.Count; i++)
            {
                Assert.True(ranges[i - 1].End < ranges[i].Start,
                    $"Blocks not properly sorted: {result[i - 1]} then {result[i]}");
            }
        }

        [Fact]
        public void ParseRange_IPv6_CIDRBlocks_NoGaps()
        {
            var start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
            var end = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0xffff, 0xffff);
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            var ranges = new List<(System.Numerics.BigInteger Start, System.Numerics.BigInteger End)>();
            var startVal = new System.Numerics.BigInteger(start, isUnsigned: true, isBigEndian: true);

            foreach (var block in result)
            {
                var parts = block.Split('/');
                var ip = IPAddress.Parse(parts[0]).GetAddressBytes();
                var cidr = int.Parse(parts[1]);

                var ipVal = new System.Numerics.BigInteger(ip, isUnsigned: true, isBigEndian: true);
                var blockSize = System.Numerics.BigInteger.Pow(2, 128 - cidr);
                var blockEnd = ipVal + blockSize - 1;

                ranges.Add((ipVal, blockEnd));
            }

            ranges.Sort((a, b) => a.Start.CompareTo(b.Start));

            for (int i = 1; i < ranges.Count; i++)
            {
                Assert.Equal(ranges[i - 1].End + 1, ranges[i].Start);
            }

            Assert.Equal(startVal, ranges[0].Start);
        }

        [Fact]
        public void ParseRange_IPv6_CIDRBlocks_ExactCoverage()
        {
            var testRanges = new[]
            {
                new { Start = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 0), End = CreateIPv6Address(0, 0, 0, 0, 0, 0, 0, 15) },
                new { Start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), End = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xffff) },
                new { Start = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), End = CreateIPv6Address(0x2001, 0x0db8, 0, 0, 0, 0, 0xffff, 0xffff) },
            };

            foreach (var test in testRanges)
            {
                var result = IPRangeFastParser.ParseRange(test.Start, test.End).ToList();
                System.Numerics.BigInteger totalIPs = 0;

                foreach (var block in result)
                {
                    var parts = block.Split('/');
                    var cidr = int.Parse(parts[1]);
                    totalIPs += System.Numerics.BigInteger.Pow(2, 128 - cidr);
                }

                var startVal = new System.Numerics.BigInteger(test.Start, isUnsigned: true, isBigEndian: true);
                var endVal = new System.Numerics.BigInteger(test.End, isUnsigned: true, isBigEndian: true);
                var expectedIPs = endVal - startVal + 1;

                Assert.Equal(expectedIPs, totalIPs);
            }
        }

        #endregion

        #region Mixed/IPAddress Tests

        [Fact]
        public void ParseRange_FromIPAddress_IPv4_ReturnsCorrectCIDRs()
        {
            var startIP = IPAddress.Parse("192.168.1.1");
            var endIP = IPAddress.Parse("192.168.1.255");
            var start = startIP.GetAddressBytes();
            var end = endIP.GetAddressBytes();
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Equal(8, result.Count);
            Assert.Equal("192.168.1.1/32", result[0]);
            Assert.Equal("192.168.1.128/25", result[^1]);
        }

        [Fact]
        public void ParseRange_FromIPAddress_IPv6_ReturnsCorrectCIDR()
        {
            var startIP = IPAddress.Parse("2001:db8::");
            var endIP = IPAddress.Parse("2001:db8::ffff");
            var start = startIP.GetAddressBytes();
            var end = endIP.GetAddressBytes();
            var result = IPRangeFastParser.ParseRange(start, end).ToList();

            Assert.Single(result);
            Assert.Equal("2001:db8::/112", result[0]);
        }

        #endregion

        #region Cache Tests

        [Fact]
        public void Cache_IPv4_RepeatedRange_UsesCache()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 255 };

            IPRangeFastParserPooled.Clear();
            var (ipv4Before, ipv6Before) = IPRangeFastParserPooled.GetCacheSize();

            var result1 = IPRangeFastParserPooled.ParseRange(start, end).ToList();
            var (ipv4After1, ipv6After1) = IPRangeFastParserPooled.GetCacheSize();

            var result2 = IPRangeFastParserPooled.ParseRange(start, end).ToList();
            var (ipv4After2, ipv6After2) = IPRangeFastParserPooled.GetCacheSize();

            Assert.Equal(0, ipv4Before);
            Assert.True(ipv4After1 > 0);
            Assert.Equal(ipv4After1, ipv4After2);
            Assert.Equal(result1, result2);
        }

        [Fact]
        public void Cache_ClearCache_ResetsAllCaches()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 255 };
            _ = IPRangeFastParserPooled.ParseRange(start, end).ToList();

            var (beforeIpv4, beforeIpv6) = IPRangeFastParserPooled.GetCacheSize();
            IPRangeFastParserPooled.Clear();
            var (afterIpv4, afterIpv6) = IPRangeFastParserPooled.GetCacheSize();

            Assert.True(beforeIpv4 > 0);
            Assert.Equal(0, afterIpv4);
            Assert.Equal(0, afterIpv6);
        }

        #endregion

        #region Edge Cases

        [Fact]
        public void ParseRange_InvalidArrayLength_ThrowsException()
        {
            var start = new byte[] { 192, 168, 1, 1 };
            var end = new byte[] { 192, 168, 1, 1, 1 };
            Assert.Throws<ArgumentException>(() => IPRangeFastParser.ParseRange(start, end).ToList());
        }

        [Fact]
        public void ParseRange_UnsupportedAddressFamily_ThrowsException()
        {
            var start = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            var end = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            Assert.Throws<ArgumentException>(() => IPRangeFastParser.ParseRange(start, end).ToList());
        }

        [Fact]
        public void ParseRange_NullBytes_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                IPRangeFastParser.ParseRange((byte[])null!, new byte[4]).ToList());

            Assert.Throws<ArgumentNullException>(() =>
                IPRangeFastParser.ParseRange(new byte[4], (byte[])null!).ToList());
        }

        [Fact]
        public void ParseRange_EmptyRangeString_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => IPRangeFastParser.ParseRange(""));
        }

        [Fact]
        public void ParseRange_InvalidRangeFormat_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => IPRangeFastParser.ParseRange("invalid-range").ToList());
        }

        [Fact]
        public void ParseRange_RangeWithInvalidIP_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => IPRangeFastParser.ParseRange("999.999.999.999 - 192.168.1.255").ToList());
        }

        #endregion

        #region Helper Methods

        private static byte[] CreateIPv6Address(ushort p0, ushort p1, ushort p2, ushort p3, ushort p4, ushort p5, ushort p6, ushort p7)
        {
            var bytes = new byte[16];
            bytes[0] = (byte)(p0 >> 8);
            bytes[1] = (byte)(p0 & 0xFF);
            bytes[2] = (byte)(p1 >> 8);
            bytes[3] = (byte)(p1 & 0xFF);
            bytes[4] = (byte)(p2 >> 8);
            bytes[5] = (byte)(p2 & 0xFF);
            bytes[6] = (byte)(p3 >> 8);
            bytes[7] = (byte)(p3 & 0xFF);
            bytes[8] = (byte)(p4 >> 8);
            bytes[9] = (byte)(p4 & 0xFF);
            bytes[10] = (byte)(p5 >> 8);
            bytes[11] = (byte)(p5 & 0xFF);
            bytes[12] = (byte)(p6 >> 8);
            bytes[13] = (byte)(p6 & 0xFF);
            bytes[14] = (byte)(p7 >> 8);
            bytes[15] = (byte)(p7 & 0xFF);
            return bytes;
        }

        #endregion
    }
}