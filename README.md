# Nexus.NetTools.IPRangeParser

Ultra-fast IP range parser with LRU caching. Converts IP ranges to minimal CIDR blocks. Supports IPv4 and IPv6.

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

# Usage
## Basic Usage

```csharp
```