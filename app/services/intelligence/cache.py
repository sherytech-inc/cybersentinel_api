"""
CyberSentinel — Intelligence Cache Service
TTL + LRU in-memory cache. No Redis dependency.
Swap for aioredis in multi-worker production deployments.
"""
import asyncio, logging, time
from collections import OrderedDict
from typing import Optional
from app.schemas.intelligence import IntelligenceResponse

logger = logging.getLogger(__name__)

class IntelligenceCache:
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10_000):
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._store: OrderedDict[str, tuple] = OrderedDict()
        self._lock = asyncio.Lock()
        self._hits = self._misses = 0

    async def get(self, ip: str) -> Optional[IntelligenceResponse]:
        async with self._lock:
            entry = self._store.get(ip)
            if entry is None:
                self._misses += 1; return None
            result, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[ip]; self._misses += 1; return None
            self._store.move_to_end(ip)
            self._hits += 1
            return result

    async def set(self, ip: str, result: IntelligenceResponse) -> None:
        async with self._lock:
            expires_at = time.monotonic() + self._ttl
            if ip in self._store:
                self._store.move_to_end(ip)
            elif len(self._store) >= self._max_size:
                self._store.popitem(last=False)
            self._store[ip] = (result, expires_at)

    async def invalidate(self, ip: str) -> bool:
        async with self._lock:
            if ip in self._store:
                del self._store[ip]; return True
            return False

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    @property
    def size(self) -> int: return len(self._store)
    @property
    def hits(self) -> int: return self._hits
    @property
    def misses(self) -> int: return self._misses
    @property
    def hit_rate(self) -> float:
        t = self._hits + self._misses
        return round(self._hits / t, 4) if t else 0.0

    def stats(self) -> dict:
        return {"size": self.size, "max_size": self._max_size,
                "ttl_seconds": self._ttl, "hits": self._hits,
                "misses": self._misses, "hit_rate": self.hit_rate}

_cache_instance: Optional[IntelligenceCache] = None

def init_cache(ttl_seconds: int, max_size: int) -> IntelligenceCache:
    global _cache_instance
    _cache_instance = IntelligenceCache(ttl_seconds, max_size)
    return _cache_instance

def get_cache() -> IntelligenceCache:
    if _cache_instance is None:
        raise RuntimeError("Cache not initialised. Call init_cache() at startup.")
    return _cache_instance