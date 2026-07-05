using System;
using System.Collections.Generic;
using System.Net;
using Nexus.NetTools.IPRangeParser.Core;
using Nexus.NetTools.IPRangeParser.Helpers;

namespace Nexus.NetTools.IPRangeParser
{
    /// <summary>
    /// Ultra-fast IP range parser - Core logic without caching
    /// </summary>
    public static class IPRangeFastParser
    {
        /// <summary>
        /// Parses an IP range from byte arrays and returns CIDR blocks
        /// </summary>
        public static IEnumerable<string> ParseRange(byte[] startBytes, byte[] endBytes)
        {
            RangeParserHelper.ValidateByteArrays(startBytes, endBytes);

            return startBytes.Length switch
            {
                4 => IPRangeParserCore.ParseIPv4Range(IPRangeParserCore.BytesToUInt32(startBytes), IPRangeParserCore.BytesToUInt32(endBytes)),
                16 => IPRangeParserCore.ParseIPv6Range(startBytes, endBytes),
                _ => throw new ArgumentException("Only IPv4 (4 bytes) and IPv6 (16 bytes) supported")
            };
        }

        /// <summary>
        /// Parses an IP range from IPAddress objects and returns CIDR blocks
        /// </summary>
        public static IEnumerable<string> ParseRange(IPAddress startIp, IPAddress endIp)
        {
            RangeParserHelper.ValidateIpAddresses(startIp, endIp);

            var startBytes = startIp.GetAddressBytes();
            var endBytes = endIp.GetAddressBytes();

            return startBytes.Length switch
            {
                4 => IPRangeParserCore.ParseIPv4Range(IPRangeParserCore.BytesToUInt32(startBytes), IPRangeParserCore.BytesToUInt32(endBytes)),
                16 => IPRangeParserCore.ParseIPv6Range(startBytes, endBytes),
                _ => throw new ArgumentException("Only IPv4 (4 bytes) and IPv6 (16 bytes) supported")
            };
        }

        /// <summary>
        /// Parses an IP range from string addresses and returns CIDR blocks
        /// </summary>
        public static IEnumerable<string> ParseRange(string startIp, string endIp)
        {
            return ParseRange(IPAddress.Parse(startIp), IPAddress.Parse(endIp));
        }

        /// <summary>
        /// Parses an IP range from a string in the format "startIP - endIP" and returns CIDR blocks
        /// </summary>
        public static IEnumerable<string> ParseRange(string range)
        {
            var (start, end) = RangeParserHelper.ParseRangeParts(range);
            return ParseRange(start, end);
        }
    }
}