package main
import (
    "net"
    "encoding/binary"
)
func getCountryByIP(ipStr string) string {
    host, _, err := net.SplitHostPort(ipStr)
    if err != nil {
        host = ipStr
    }
    ip := net.ParseIP(host)
    if ip == nil {
        return "UNKNOWN"
    }
    ipv4 := ip.To4()
    if ipv4 == nil {
        return "UNKNOWN"
    }
    ipInt := binary.BigEndian.Uint32(ipv4)
    if ipInt >= 0x01000000 && ipInt < 0x02000000 {
        return "US"
    }
    if ipInt >= 0x02000000 && ipInt < 0x03000000 {
        return "US"
    }
    if ipInt >= 0x05000000 && ipInt < 0x06000000 {
        return "DE"
    }
    if ipInt >= 0x1E000000 && ipInt < 0x1F000000 {
        return "US"
    }
    if ipInt >= 0x2D000000 && ipInt < 0x2E000000 {
        return "US"
    }
    if ipInt >= 0x37000000 && ipInt < 0x38000000 {
        return "US"
    }
    if ipInt >= 0x3E000000 && ipInt < 0x3F000000 {
        return "RU"
    }
    if ipInt >= 0x40000000 && ipInt < 0x41000000 {
        return "US"
    }
    if ipInt >= 0x5A000000 && ipInt < 0x5B000000 {
        return "GB"
    }
    if ipInt >= 0x5B000000 && ipInt < 0x5C000000 {
        return "DE"
    }
    if ipInt >= 0x77000000 && ipInt < 0x78000000 {
        return "CN"
    }
    if ipInt >= 0x7A000000 && ipInt < 0x7B000000 {
        return "CN"
    }
    if ipInt >= 0x80000000 && ipInt < 0x81000000 {
        return "US"
    }
    if ipInt >= 0x81000000 && ipInt < 0x82000000 {
        return "US"
    }
    if ipInt >= 0x82000000 && ipInt < 0x83000000 {
        return "US"
    }
    if ipInt >= 0x83000000 && ipInt < 0x84000000 {
        return "US"
    }
    if ipInt >= 0x84000000 && ipInt < 0x85000000 {
        return "US"
    }
    if ipInt >= 0x85000000 && ipInt < 0x86000000 {
        return "JP"
    }
    if ipInt >= 0x86000000 && ipInt < 0x87000000 {
        return "DE"
    }
    if ipInt >= 0x87000000 && ipInt < 0x88000000 {
        return "DE"
    }
    if ipInt >= 0x88000000 && ipInt < 0x89000000 {
        return "US"
    }
    if ipInt >= 0x89000000 && ipInt < 0x8A000000 {
        return "AT"
    }
    if ipInt >= 0x8A000000 && ipInt < 0x8B000000 {
        return "US"
    }
    if ipInt >= 0x8B000000 && ipInt < 0x8C000000 {
        return "US"
    }
    if ipInt >= 0x8C000000 && ipInt < 0x8D000000 {
        return "US"
    }
    if ipInt >= 0x8D000000 && ipInt < 0x8E000000 {
        return "DE"
    }
    if ipInt >= 0x8E000000 && ipInt < 0x8F000000 {
        return "CA"
    }
    if ipInt >= 0x8F000000 && ipInt < 0x90000000 {
        return "US"
    }
    if ipInt >= 0x90000000 && ipInt < 0x91000000 {
        return "US"
    }
    if ipInt >= 0x91000000 && ipInt < 0x92000000 {
        return "NL"
    }
    if ipInt >= 0x92000000 && ipInt < 0x93000000 {
        return "US"
    }
    if ipInt >= 0x93000000 && ipInt < 0x94000000 {
        return "US"
    }
    if ipInt >= 0x94000000 && ipInt < 0x95000000 {
        return "US"
    }
    if ipInt >= 0x95000000 && ipInt < 0x96000000 {
        return "US"
    }
    if ipInt >= 0x96000000 && ipInt < 0x97000000 {
        return "JP"
    }
    if ipInt >= 0x97000000 && ipInt < 0x98000000 {
        return "IT"
    }
    if ipInt >= 0x98000000 && ipInt < 0x99000000 {
        return "US"
    }
    if ipInt >= 0x99000000 && ipInt < 0x9A000000 {
        return "DE"
    }
    if ipInt >= 0x9A000000 && ipInt < 0x9B000000 {
        return "US"
    }
    if ipInt >= 0x9B000000 && ipInt < 0x9C000000 {
        return "US"
    }
    if ipInt >= 0x9C000000 && ipInt < 0x9D000000 {
        return "US"
    }
    if ipInt >= 0x9D000000 && ipInt < 0x9E000000 {
        return "US"
    }
    if ipInt >= 0x9E000000 && ipInt < 0x9F000000 {
        return "US"
    }
    if ipInt >= 0x9F000000 && ipInt < 0xA0000000 {
        return "US"
    }
    if ipInt >= 0xA0000000 && ipInt < 0xA1000000 {
        return "US"
    }
    if ipInt >= 0xA1000000 && ipInt < 0xA2000000 {
        return "US"
    }
    if ipInt >= 0xA2000000 && ipInt < 0xA3000000 {
        return "US"
    }
    if ipInt >= 0xA3000000 && ipInt < 0xA4000000 {
        return "US"
    }
    if ipInt >= 0xA4000000 && ipInt < 0xA5000000 {
        return "US"
    }
    if ipInt >= 0xA5000000 && ipInt < 0xA6000000 {
        return "US"
    }
    if ipInt >= 0xA6000000 && ipInt < 0xA7000000 {
        return "US"
    }
    if ipInt >= 0xA7000000 && ipInt < 0xA8000000 {
        return "US"
    }
    if ipInt >= 0xA8000000 && ipInt < 0xA9000000 {
        return "US"
    }
    if ipInt >= 0xA9000000 && ipInt < 0xAA000000 {
        return "US"
    }
    if ipInt >= 0xAA000000 && ipInt < 0xAB000000 {
        return "US"
    }
    if ipInt >= 0xAB000000 && ipInt < 0xAC000000 {
        return "US"
    }
    if ipInt >= 0xAC000000 && ipInt < 0xAD000000 {
        return "US"
    }
    if ipInt >= 0xAD000000 && ipInt < 0xAE000000 {
        return "US"
    }
    if ipInt >= 0xAE000000 && ipInt < 0xAF000000 {
        return "US"
    }
    if ipInt >= 0xAF000000 && ipInt < 0xB0000000 {
        return "US"
    }
    if ipInt >= 0xB0000000 && ipInt < 0xB1000000 {
        return "RU"
    }
    if ipInt >= 0xB1000000 && ipInt < 0xB2000000 {
        return "RU"
    }
    if ipInt >= 0xB2000000 && ipInt < 0xB3000000 {
        return "RU"
    }
    if ipInt >= 0xB3000000 && ipInt < 0xB4000000 {
        return "BR"
    }
    if ipInt >= 0xB4000000 && ipInt < 0xB5000000 {
        return "CN"
    }
    if ipInt >= 0xB5000000 && ipInt < 0xB6000000 {
        return "BR"
    }
    if ipInt >= 0xB6000000 && ipInt < 0xB7000000 {
        return "CN"
    }
    if ipInt >= 0xB7000000 && ipInt < 0xB8000000 {
        return "CN"
    }
    if ipInt >= 0xB8000000 && ipInt < 0xB9000000 {
        return "US"
    }
    if ipInt >= 0xB9000000 && ipInt < 0xBA000000 {
        return "RU"
    }
    if ipInt >= 0xBA000000 && ipInt < 0xBB000000 {
        return "BR"
    }
    if ipInt >= 0xBB000000 && ipInt < 0xBC000000 {
        return "BR"
    }
    if ipInt >= 0xBC000000 && ipInt < 0xBD000000 {
        return "RU"
    }
    if ipInt >= 0xBD000000 && ipInt < 0xBE000000 {
        return "MX"
    }
    if ipInt >= 0xBE000000 && ipInt < 0xBF000000 {
        return "MX"
    }
    if ipInt >= 0xBF000000 && ipInt < 0xC0000000 {
        return "BR"
    }
    if ipInt >= 0xC0000000 && ipInt < 0xC1000000 {
        return "US"
    }
    if ipInt >= 0xC1000000 && ipInt < 0xC2000000 {
        return "DE"
    }
    if ipInt >= 0xC2000000 && ipInt < 0xC3000000 {
        return "DE"
    }
    if ipInt >= 0xC3000000 && ipInt < 0xC4000000 {
        return "FR"
    }
    if ipInt >= 0xC4000000 && ipInt < 0xC5000000 {
        return "ZA"
    }
    if ipInt >= 0xC5000000 && ipInt < 0xC6000000 {
        return "ZA"
    }
    if ipInt >= 0xC6000000 && ipInt < 0xC7000000 {
        return "US"
    }
    if ipInt >= 0xC7000000 && ipInt < 0xC8000000 {
        return "US"
    }
    if ipInt >= 0xC8000000 && ipInt < 0xC9000000 {
        return "BR"
    }
    if ipInt >= 0xC9000000 && ipInt < 0xCA000000 {
        return "MX"
    }
    if ipInt >= 0xCA000000 && ipInt < 0xCB000000 {
        return "CN"
    }
    if ipInt >= 0xCB000000 && ipInt < 0xCC000000 {
        return "AU"
    }
    if ipInt >= 0xCC000000 && ipInt < 0xCD000000 {
        return "US"
    }
    if ipInt >= 0xCD000000 && ipInt < 0xCE000000 {
        return "US"
    }
    if ipInt >= 0xCE000000 && ipInt < 0xCF000000 {
        return "US"
    }
    if ipInt >= 0xCF000000 && ipInt < 0xD0000000 {
        return "US"
    }
    if ipInt >= 0xD0000000 && ipInt < 0xD1000000 {
        return "US"
    }
    if ipInt >= 0xD1000000 && ipInt < 0xD2000000 {
        return "US"
    }
    if ipInt >= 0xD2000000 && ipInt < 0xD3000000 {
        return "AU"
    }
    if ipInt >= 0xD3000000 && ipInt < 0xD4000000 {
        return "CN"
    }
    if ipInt >= 0xD4000000 && ipInt < 0xD5000000 {
        return "CH"
    }
    if ipInt >= 0xD5000000 && ipInt < 0xD6000000 {
        return "SE"
    }
    if ipInt >= 0xD6000000 && ipInt < 0xD7000000 {
        return "US"
    }
    if ipInt >= 0xD7000000 && ipInt < 0xD8000000 {
        return "US"
    }
    if ipInt >= 0xD8000000 && ipInt < 0xD9000000 {
        return "US"
    }
    if ipInt >= 0xD9000000 && ipInt < 0xDA000000 {
        return "DE"
    }
    if ipInt >= 0xDA000000 && ipInt < 0xDB000000 {
        return "CN"
    }
    if ipInt >= 0xDB000000 && ipInt < 0xDC000000 {
        return "JP"
    }
    if ipInt >= 0xDC000000 && ipInt < 0xDD000000 {
        return "CN"
    }
    if ipInt >= 0xDD000000 && ipInt < 0xDE000000 {
        return "JP"
    }
    if ipInt >= 0xDE000000 && ipInt < 0xDF000000 {
        return "JP"
    }
    if ipInt >= 0xDF000000 && ipInt < 0xE0000000 {
        return "JP"
    }
    if ipInt >= 0x0A000000 && ipInt < 0x0B000000 {
        return "PRIVATE"
    }
    if ipInt >= 0xAC100000 && ipInt < 0xAC200000 {
        return "PRIVATE"
    }
    if ipInt >= 0xC0A80000 && ipInt < 0xC0A90000 {
        return "PRIVATE"
    }
    firstOctet := ipv4[0]
    if firstOctet < 128 {
        return "US"
    } else if firstOctet < 192 {
        return "EU"
    } else if firstOctet < 224 {
        return "ASIA"
    }
    return "UNKNOWN"
}
func getCountryCoords(country string) (int, int) {
    coords := map[string][2]int{
        "US": {20, 10},
        "RU": {50, 5},
        "CN": {60, 12},
        "DE": {45, 8},
        "GB": {42, 8},
        "FR": {44, 9},
        "JP": {65, 11},
        "BR": {15, 20},
        "MX": {12, 15},
        "CA": {15, 6},
        "AU": {65, 25},
        "IT": {46, 10},
        "NL": {44, 8},
        "SE": {47, 5},
        "CH": {45, 9},
        "AT": {45, 9},
        "ZA": {48, 28},
        "EU": {45, 8},
        "ASIA": {60, 12},
    }
    if c, ok := coords[country]; ok {
        return c[0], c[1]
    }
    return 30, 15
}
func getCountryName(code string) string {
    names := map[string]string{
        "US": "United States",
        "RU": "Russia",
        "CN": "China",
        "DE": "Germany",
        "GB": "United Kingdom",
        "FR": "France",
        "JP": "Japan",
        "BR": "Brazil",
        "MX": "Mexico",
        "CA": "Canada",
        "AU": "Australia",
        "IT": "Italy",
        "NL": "Netherlands",
        "SE": "Sweden",
        "CH": "Switzerland",
        "AT": "Austria",
        "ZA": "South Africa",
        "EU": "Europe",
        "ASIA": "Asia",
        "PRIVATE": "Private Network",
        "UNKNOWN": "Unknown",
    }
    if name, ok := names[code]; ok {
        return name
    }
    return code
}
