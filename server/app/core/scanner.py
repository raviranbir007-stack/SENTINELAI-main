import asyncio
import hashlib
import math
import socket
from pathlib import Path
from typing import Dict, List


class NetworkScanner:
    _DEFAULT_PORTS = [
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1433,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
    ]

    @staticmethod
    async def scan_network(target: str) -> Dict:
        """Resolve target and run a safe default TCP service scan."""
        resolved_ip = ""
        try:
            resolved_ip = socket.gethostbyname(target)
        except Exception:
            resolved_ip = target

        result = await NetworkScanner.port_scan(resolved_ip, NetworkScanner._DEFAULT_PORTS)
        result["target"] = target
        result["resolved_ip"] = resolved_ip
        return result

    @staticmethod
    async def _probe_port(ip: str, port: int, timeout: float = 0.45) -> Dict:
        started = asyncio.get_running_loop().time()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, int(port)), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            elapsed = (asyncio.get_running_loop().time() - started) * 1000.0
            return {"port": int(port), "state": "open", "latency_ms": round(elapsed, 2)}
        except Exception:
            elapsed = (asyncio.get_running_loop().time() - started) * 1000.0
            return {"port": int(port), "state": "closed", "latency_ms": round(elapsed, 2)}

    @staticmethod
    async def port_scan(ip: str, ports: List[int]) -> Dict:
        """Scan ports with bounded concurrency for responsive live monitoring."""
        cleaned_ports = sorted({int(p) for p in ports if isinstance(p, int) or str(p).isdigit()})[:256]
        if not cleaned_ports:
            return {"ip": ip, "ports": [], "results": [], "open_ports": [], "risk": "low", "score": 0.0}

        semaphore = asyncio.Semaphore(64)

        async def _bounded_probe(port: int) -> Dict:
            async with semaphore:
                return await NetworkScanner._probe_port(ip, port)

        results = await asyncio.gather(*[_bounded_probe(p) for p in cleaned_ports])
        open_ports = [r["port"] for r in results if r.get("state") == "open"]

        sensitive_ports = {21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379}
        exposed_sensitive = sorted(p for p in open_ports if p in sensitive_ports)

        score = min(1.0, (len(open_ports) * 0.03) + (len(exposed_sensitive) * 0.08))
        risk = "high" if score >= 0.75 else "medium" if score >= 0.38 else "low"

        return {
            "ip": ip,
            "ports": cleaned_ports,
            "results": results,
            "open_ports": open_ports,
            "exposed_sensitive_ports": exposed_sensitive,
            "risk": risk,
            "score": round(score, 3),
            "status": "completed",
        }


class FileScanner:
    _SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".js",
        ".vbs",
        ".scr",
        ".hta",
        ".jar",
        ".apk",
    }

    @staticmethod
    def _byte_entropy(sample: bytes) -> float:
        if not sample:
            return 0.0
        freq = [0] * 256
        for b in sample:
            freq[b] += 1
        total = float(len(sample))
        return -sum((count / total) * math.log2(count / total) for count in freq if count)

    @staticmethod
    async def scan_file(filepath: str) -> Dict:
        """Perform a lightweight forensic file scan (hashes, entropy, extension risk)."""
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return {"filepath": filepath, "status": "error", "error": "File not found"}

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        size = path.stat().st_size
        first_chunk = b""

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(8192)
                if not chunk:
                    break
                if not first_chunk:
                    first_chunk = chunk[:16384]
                sha256.update(chunk)
                md5.update(chunk)

        entropy = FileScanner._byte_entropy(first_chunk)
        ext = path.suffix.lower()
        high_entropy = entropy >= 7.2
        suspicious_ext = ext in FileScanner._SUSPICIOUS_EXTENSIONS

        score = min(1.0, (0.55 if suspicious_ext else 0.0) + (0.35 if high_entropy else 0.0))
        risk = "high" if score >= 0.75 else "medium" if score >= 0.35 else "low"

        return {
            "filepath": str(path),
            "filename": path.name,
            "size_bytes": int(size),
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
            "extension": ext,
            "entropy": round(entropy, 3),
            "suspicious_extension": suspicious_ext,
            "high_entropy": high_entropy,
            "risk": risk,
            "score": round(score, 3),
            "status": "completed",
        }
