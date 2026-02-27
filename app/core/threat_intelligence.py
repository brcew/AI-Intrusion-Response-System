"""
Threat Intelligence Module.
Enriches IP addresses with geolocation and reputation data.
Uses ip-api.com (free, no API key required) for real lookups.
Falls back to simulated data if network is unavailable.
"""

import random
import hashlib
from dataclasses import dataclass
from typing import Dict, Optional
from datetime import datetime

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class IPIntelligence:
    ip: str
    country: str
    country_code: str
    city: str
    region: str
    latitude: float
    longitude: float
    isp: str
    is_known_bad: bool          # flagged by threat intel
    reputation_score: int       # 0-100, higher = more suspicious
    tags: list                  # e.g. ["TOR", "VPN", "Datacenter"]
    lookup_time: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "city": self.city,
            "region": self.region,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "is_known_bad": self.is_known_bad,
            "reputation_score": self.reputation_score,
            "tags": ", ".join(self.tags) if self.tags else "None",
            "lookup_time": self.lookup_time,
        }


# Simulated geo data for private/internal IPs and fallback
_SIMULATED_LOCATIONS = [
    ("United States", "US", "New York", "NY", 40.7128, -74.0060, "DigitalOcean LLC"),
    ("China", "CN", "Beijing", "Beijing", 39.9042, 116.4074, "China Telecom"),
    ("Russia", "RU", "Moscow", "Moscow", 55.7558, 37.6173, "Rostelecom"),
    ("Germany", "DE", "Frankfurt", "Hesse", 50.1109, 8.6821, "Hetzner Online GmbH"),
    ("Brazil", "BR", "São Paulo", "SP", -23.5505, -46.6333, "Claro NXT"),
    ("India", "IN", "Mumbai", "Maharashtra", 19.0760, 72.8777, "Reliance Jio"),
    ("Netherlands", "NL", "Amsterdam", "NH", 52.3676, 4.9041, "LeaseWeb"),
    ("United Kingdom", "GB", "London", "England", 51.5074, -0.1278, "BT Group"),
    ("France", "FR", "Paris", "IDF", 48.8566, 2.3522, "OVH SAS"),
    ("South Korea", "KR", "Seoul", "Seoul", 37.5665, 126.9780, "SK Broadband"),
    ("Ukraine", "UA", "Kyiv", "Kyiv", 50.4501, 30.5234, "Kyivstar"),
    ("Iran", "IR", "Tehran", "Tehran", 35.6892, 51.3890, "TCI"),
    ("Nigeria", "NG", "Lagos", "Lagos", 6.5244, 3.3792, "MTN Nigeria"),
    ("United States", "US", "Los Angeles", "CA", 34.0522, -118.2437, "Cloudflare Inc"),
    ("Singapore", "SG", "Singapore", "SG", 1.3521, 103.8198, "Singtel"),
]

_KNOWN_BAD_ISPS = ["DigitalOcean LLC", "Hetzner Online GmbH", "LeaseWeb",
                   "OVH SAS", "Cloudflare Inc", "TCI", "Rostelecom"]

_TAGS_POOL = {
    "DigitalOcean LLC": ["Datacenter", "VPS"],
    "Hetzner Online GmbH": ["Datacenter", "VPS"],
    "LeaseWeb": ["Datacenter", "Hosting"],
    "OVH SAS": ["Datacenter", "Hosting"],
    "Cloudflare Inc": ["CDN", "Proxy"],
    "TCI": ["State-owned ISP"],
    "Rostelecom": ["State-owned ISP"],
    "China Telecom": ["State-owned ISP"],
    "Kyivstar": [],
    "MTN Nigeria": [],
}


def _deterministic_choice(ip: str, options: list):
    """Pick consistently from a list based on IP hash — same IP always gets same data."""
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    return options[h % len(options)]


def _simulate_intel(ip: str, is_attacker: bool) -> IPIntelligence:
    """Generate realistic but simulated threat intelligence for an IP."""
    location = _deterministic_choice(ip, _SIMULATED_LOCATIONS)
    country, country_code, city, region, lat, lon, isp = location

    # Attacker IPs get more suspicious profiles
    if is_attacker:
        is_known_bad = isp in _KNOWN_BAD_ISPS or random.random() > 0.4
        reputation_score = random.randint(60, 95)
        tags = _TAGS_POOL.get(isp, []) + (["TOR"] if random.random() > 0.7 else [])
    else:
        is_known_bad = False
        reputation_score = random.randint(5, 25)
        tags = []

    return IPIntelligence(
        ip=ip,
        country=country,
        country_code=country_code,
        city=city,
        region=region,
        latitude=lat,
        longitude=lon,
        isp=isp,
        is_known_bad=is_known_bad,
        reputation_score=reputation_score,
        tags=tags,
        lookup_time=datetime.utcnow().isoformat(),
    )


def _real_lookup(ip: str) -> Optional[IPIntelligence]:
    """Try real IP geolocation via ip-api.com (free, no key needed)."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp",
            timeout=2,
        )
        if resp.status_code == 200:
            d = resp.json()
            if d.get("status") == "success":
                return IPIntelligence(
                    ip=ip,
                    country=d.get("country", "Unknown"),
                    country_code=d.get("countryCode", "??"),
                    city=d.get("city", "Unknown"),
                    region=d.get("regionName", "Unknown"),
                    latitude=d.get("lat", 0.0),
                    longitude=d.get("lon", 0.0),
                    isp=d.get("isp", "Unknown"),
                    is_known_bad=False,
                    reputation_score=20,
                    tags=[],
                    lookup_time=datetime.utcnow().isoformat(),
                )
    except Exception:
        pass
    return None


class ThreatIntelligence:
    """
    Enriches IPs with geolocation and reputation data.
    Caches results to avoid duplicate lookups.
    """

    def __init__(self):
        self._cache: Dict[str, IPIntelligence] = {}

    def lookup(self, ip: str, is_attacker: bool = False) -> IPIntelligence:
        """Look up threat intelligence for an IP. Results are cached."""
        if ip in self._cache:
            return self._cache[ip]

        # Try real lookup for non-private IPs
        intel = None
        is_private = ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

        if not is_private and REQUESTS_AVAILABLE:
            intel = _real_lookup(ip)

        # Fall back to simulation
        if intel is None:
            intel = _simulate_intel(ip, is_attacker)

        self._cache[ip] = intel
        return intel

    def get_cached(self, ip: str) -> Optional[IPIntelligence]:
        return self._cache.get(ip)

    def get_all_cached(self) -> Dict[str, IPIntelligence]:
        return dict(self._cache)

    def reset(self) -> None:
        self._cache.clear()