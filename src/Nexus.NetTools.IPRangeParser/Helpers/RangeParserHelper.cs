using System;

namespace Nexus.NetTools.IPRangeParser.Helpers
{
    /// <summary>
    /// Helper utilities for IP range parsing
    /// </summary>
    internal static class RangeParserHelper
    {
        // Static readonly array for range separators - allocated once
        private static readonly string[] _rangeSeparators = new[] { " - ", "–", "-" };

        /// <summary>
        /// Parses a range string into start and end IP strings
        /// </summary>
        internal static (string Start, string End) ParseRangeParts(string range)
        {
            if (string.IsNullOrEmpty(range))
                throw new ArgumentException("Range cannot be null or empty");

            var parts = range.Split(_rangeSeparators, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2)
                throw new ArgumentException("Range must be in format 'startIP - endIP'");

            return (parts[0].Trim(), parts[1].Trim());
        }

        /// <summary>
        /// Validates that two byte arrays have the same length and are valid IP addresses
        /// </summary>
        internal static void ValidateByteArrays(byte[] startBytes, byte[] endBytes)
        {
            if (startBytes is null)
                throw new ArgumentNullException(nameof(startBytes));
            if (endBytes is null)
                throw new ArgumentNullException(nameof(endBytes));

            if (startBytes.Length != endBytes.Length)
                throw new ArgumentException("Arrays must have same length");

            if (startBytes.Length != 4 && startBytes.Length != 16)
                throw new ArgumentException("Only IPv4 (4 bytes) and IPv6 (16 bytes) supported");
        }

        /// <summary>
        /// Validates that two IP addresses are of the same address family
        /// </summary>
        internal static void ValidateIpAddresses(System.Net.IPAddress startIp, System.Net.IPAddress endIp)
        {
            if (startIp.AddressFamily != endIp.AddressFamily)
                throw new ArgumentException("Both IP addresses must be of the same address family");
        }
    }
}