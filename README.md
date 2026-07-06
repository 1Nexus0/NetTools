# IPRangeParser

Ultra-fast IP range parser with LRU caching. Converts IP ranges to minimal CIDR blocks. Supports IPv4 and IPv6.

[![NuGet Version](https://img.shields.io/nuget/v/Nexus.NetTools.IPRangeParser.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/Nexus.NetTools.IPRangeParser/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Nexus.NetTools.IPRangeParser.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/Nexus.NetTools.IPRangeParser/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![.NET](https://img.shields.io/badge/.NET-6.0%20%7C%208.0%20%7C%2010.0-blueviolet)](https://dotnet.microsoft.com/)

## Features

- 🚀 **Blazing fast** - Microsecond-level parsing (up to 1.6M ops/sec)
- 💾 **LRU Cache** - Optional caching for repeated IPs (IPv4 only)
- 🔒 **Thread-safe** - Safe for concurrent use
- 📦 **No dependencies** - Pure .NET implementation
- 🌐 **IPv4 & IPv6** - Full support for both address families
- 🎯 **Optimal CIDR** - Generates minimal CIDR blocks
- 📱 **Multi-target** - Supports .NET 6, .NET 8, and .NET 10

## Installation

```bash
dotnet add package Nexus.NetTools.IPRangeParser
```

Or add to your project file:

```
<PackageReference Include="Nexus.NetTools.IPRangeParser" Version="1.0.0" />
```

## Quick Start

```csharp
using Nexus.NetTools.IPRangeParser;

// Parse a range and iterate over CIDR blocks
var result = IPRangeFastParser.ParseRange("192.168.1.1 - 192.168.1.255");
foreach (var cidr in result)
{
    Console.WriteLine(cidr);
}
// Output:
// 192.168.1.1/32
// 192.168.1.2/31
// 192.168.1.4/30
// 192.168.1.8/29
// 192.168.1.16/28
// 192.168.1.32/27
// 192.168.1.64/26
// 192.168.1.128/25
```

## Usage Examples

### Different Input Formats

```csharp
using Nexus.NetTools.IPRangeParser;

// From individual IP strings
var result1 = IPRangeFastParser.ParseRange("10.0.0.0", "10.0.0.255");
// Result: 10.0.0.0/24

// From IPAddress objects
var start = IPAddress.Parse("172.16.0.0");
var end = IPAddress.Parse("172.31.255.255");
var result2 = IPRangeFastParser.ParseRange(start, end);
// Result: 172.16.0.0/12

// From byte arrays
var startBytes = new byte[] { 192, 168, 1, 1 };
var endBytes = new byte[] { 192, 168, 1, 1 };
var result3 = IPRangeFastParser.ParseRange(startBytes, endBytes);
// Result: 192.168.1.1/32

// From range string
var result4 = IPRangeFastParser.ParseRange("192.168.0.1 - 192.168.0.31");
// Result:
// 192.168.0.1/32
// 192.168.0.2/31
// 192.168.0.4/30
// 192.168.0.8/29
// 192.168.0.16/28
```

### IPv6 Support

```csharp
using Nexus.NetTools.IPRangeParser;

// IPv6 ranges
var result = IPRangeFastParser.ParseRange("2001:db8::1 - 2001:db8::ffff");
foreach (var cidr in result)
{
    Console.WriteLine(cidr);
}
// Output:
// 2001:db8::1/128
// 2001:db8::2/127
// 2001:db8::4/126
// 2001:db8::8/125
// 2001:db8::10/124
// 2001:db8::20/123
// 2001:db8::40/122
// 2001:db8::80/121
// 2001:db8::100/120
// 2001:db8::200/119
// 2001:db8::400/118
// 2001:db8::800/117
// 2001:db8::1000/116
// 2001:db8::2000/115
// 2001:db8::4000/114
// 2001:db8::8000/113
// 2001:db8::/112
```

### Using the Cached Version

```csharp
using Nexus.NetTools.IPRangeParser;

// First call - populates cache
var result1 = IPRangeFastParserPooled.ParseRange("192.168.1.1 - 192.168.1.255");
// Cache size: IPv4=8, IPv6=0

// Second call - uses cache (faster)
var result2 = IPRangeFastParserPooled.ParseRange("192.168.1.1 - 192.168.1.255");
// Results are identical, but faster

// Clear cache when needed
IPRangeFastParserPooled.Clear();

// Check current cache size
var (ipv4Count, ipv6Count) = IPRangeFastParserPooled.GetCacheSize();
Console.WriteLine($"IPv4 cache: {ipv4Count}, IPv6 cache: {ipv6Count}");
```

### Real-World Examples

#### Nginx Configuration Generator

```csharp
using Nexus.NetTools.IPRangeParser;

var customerRanges = new[]
{
    "192.168.1.0 - 192.168.1.255",
    "10.0.0.0 - 10.0.0.255",
    "172.16.0.0 - 172.31.255.255"
};

var nginxConfig = new StringBuilder();
foreach (var range in customerRanges)
{
    foreach (var cidr in IPRangeFastParser.ParseRange(range))
    {
        nginxConfig.AppendLine($"allow {cidr};");
    }
}
nginxConfig.AppendLine("deny all;");

Console.WriteLine(nginxConfig.ToString());
// Output:
// allow 192.168.1.0/24;
// allow 10.0.0.0/24;
// allow 172.16.0.0/12;
// deny all;
```

#### IP Range Summary

```csharp
using Nexus.NetTools.IPRangeParser;

public static string SummarizeRange(string startIp, string endIp)
{
    var cidrs = IPRangeFastParser.ParseRange(startIp, endIp).ToList();
    var totalIps = cidrs.Sum(cidr => 
    {
        var prefix = int.Parse(cidr.Split('/')[1]);
        return (long)Math.Pow(2, 32 - prefix);
    });

    return $"{startIp} - {endIp} can be summarized as:\n" +
           $"  {cidrs.Count} CIDR block(s)\n" +
           $"  Total IPs: {totalIps:N0}\n" +
           $"  Blocks: {string.Join(", ", cidrs)}";
}

// Usage
Console.WriteLine(SummarizeRange("192.168.1.1", "192.168.1.255"));
// Output:
// 192.168.1.1 - 192.168.1.255 can be summarized as:
//   8 CIDR block(s)
//   Total IPs: 255
//   Blocks: 192.168.1.1/32, 192.168.1.2/31, 192.168.1.4/30, 192.168.1.8/29, 192.168.1.16/28, 192.168.1.32/27, 192.168.1.64/26, 192.168.1.128/25
```

#### Concurrent Processing

```csharp
using Nexus.NetTools.IPRangeParser;

var ranges = new[]
{
    "10.0.0.0 - 10.0.0.255",
    "192.168.1.0 - 192.168.1.255",
    "172.16.0.0 - 172.31.255.255",
    "2001:db8:: - 2001:db8::ffff"
};

// Process ranges in parallel (thread-safe)
Parallel.ForEach(ranges, range =>
{
    var cidrs = IPRangeFastParserPooled.ParseRange(range).ToList();
    Console.WriteLine($"{range}: {cidrs.Count} CIDR blocks");
});
// Output:
// 10.0.0.0 - 10.0.0.255: 1 CIDR blocks
// 192.168.1.0 - 192.168.1.255: 1 CIDR blocks
// 172.16.0.0 - 172.31.255.255: 1 CIDR blocks
// 2001:db8:: - 2001:db8::ffff: 1 CIDR blocks
```

## API Reference

### IPRangeFastParser

| Method                           | Description                    |
|----------------------------------|--------------------------------|
| ParseRange(byte[], byte[])       | Parse from byte arrays         |
| ParseRange(IPAddress, IPAddress) | Parse from IPAddress objects   |
| ParseRange(string, string)       | Parse from string addresses    |
| ParseRange(string)               | Parse from "start - end" format|

### IPRangeFastParserPooled

| Method          | Description                                   |
|-----------------|-----------------------------------------------|
| ParseRange(...) | Same as above with LRU caching (IPv4 only)    |
| Clear()         | Clear all caches                              |
| GetCacheSize()  | Get current cache size (Ipv4Count, Ipv6Count) |

### Supported IP Formats

| Format           | Example                                 |
|------------------|-----------------------------------------|
| IPv4             | 192.168.1.1                             |
| IPv4 with range  | 192.168.1.1 - 192.168.1.255             |
| IPv6             | 2001:db8::1                             |
| IPv6 with range  | 2001:db8::1 - 2001:db8::ffff            |
| IPv6 compressed  | ::1                                     |
| IPv6 full        | 2001:0db8:0000:0000:0000:0000:0000:0001 |

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

- Fork the repository

- Create your feature branch (git checkout -b features/amazing-feature)

- Commit your changes (git commit -m 'Add some amazing feature')

- Push to the branch (git push origin features/amazing-feature)

- Open a Pull Request

## Support

If you encounter any issues, please open an issue on GitHub.
