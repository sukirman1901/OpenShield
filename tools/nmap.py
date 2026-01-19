"""
Nmap tool wrapper for port scanning and service detection
Includes Python socket-based fallback when nmap CLI is not available
"""

import re
import json
import socket
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from tools.base_tool import BaseTool


# Common ports to scan when using Python fallback
COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
    8888,
    9090,
]

# Top 100 ports for more thorough scans
TOP_100_PORTS = [
    7,
    9,
    13,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
]

# Service detection patterns based on banner
SERVICE_PATTERNS = {
    "ssh": [r"SSH-", r"OpenSSH"],
    "http": [r"HTTP/", r"Apache", r"nginx", r"Microsoft-IIS"],
    "ftp": [r"FTP", r"220.*FTP", r"vsftpd", r"ProFTPD"],
    "smtp": [r"SMTP", r"220.*ESMTP", r"Postfix", r"Sendmail"],
    "mysql": [r"mysql", r"MariaDB", r"\x00\x00\x00\x0a"],
    "postgresql": [r"PostgreSQL"],
    "redis": [r"REDIS", r"-ERR"],
    "mongodb": [r"MongoDB"],
    "telnet": [r"Telnet", r"\xff\xfb"],
    "pop3": [r"\+OK.*POP3", r"Dovecot"],
    "imap": [r"\* OK.*IMAP", r"Dovecot"],
    "dns": [r"BIND", r"dnsmasq"],
    "rdp": [r"\x03\x00\x00"],
    "smb": [r"SMB", r"\x00\x00\x00\x45"],
}

# Default ports for services
SERVICE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    27017: "mongodb",
}


class NmapTool(BaseTool):
    """Nmap port scanner wrapper with Python socket fallback"""

    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "nmap"
        self._cli_available = self._check_cli_available()

    def _check_cli_available(self) -> bool:
        """Check if nmap CLI is installed"""
        import shutil

        return shutil.which("nmap") is not None

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build nmap command"""
        if not self._cli_available:
            return ["echo", "Using Python socket fallback"]

        config = self.config.get("tools", {}).get("nmap", {})

        # Base command
        command = ["nmap"]

        # Add default args from config
        default_args = config.get("default_args", "-sV -sC")
        if default_args:
            command.extend(default_args.split())

        # Timing template
        timing = config.get("timing", "T4")
        command.append(f"-{timing}")

        # XML output for parsing
        command.extend(["-oX", "-"])

        # Custom args from kwargs
        if "ports" in kwargs:
            command.extend(["-p", kwargs["ports"]])

        if "scan_type" in kwargs:
            command.append(kwargs["scan_type"])

        # Target
        command.append(target)

        return command

    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute nmap - uses Python fallback if CLI not available"""
        if self._cli_available:
            return await super().execute(target, **kwargs)
        else:
            return await self._execute_python_scanner(target, **kwargs)

    async def _execute_python_scanner(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute port scan using Python sockets"""
        start_time = datetime.now()

        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            return {
                "tool": self.tool_name,
                "target": target,
                "command": f"python_socket_scan({target})",
                "exit_code": 1,
                "duration": 0,
                "timestamp": start_time.isoformat(),
                "raw_output": "",
                "error": f"Could not resolve hostname: {e}",
                "parsed": {},
            }

        # Determine ports to scan
        ports_arg = kwargs.get("ports", "")
        if ports_arg:
            ports = self._parse_port_arg(ports_arg)
        elif kwargs.get("thorough", False):
            ports = TOP_100_PORTS
        else:
            ports = COMMON_PORTS

        # Get timeout
        timeout = kwargs.get("timeout", 1.0)

        # Scan ports concurrently
        open_ports = await self._scan_ports(ip, ports, timeout)

        # Get service info for open ports
        services = await self._detect_services(ip, open_ports, timeout)

        duration = (datetime.now() - start_time).total_seconds()

        parsed = {
            "open_ports": open_ports,
            "services": services,
            "os_detection": None,  # Not available in Python fallback
            "vulnerabilities": [],
            "host_ip": ip,
            "scan_method": "python_socket",
        }

        # Build human-readable output
        output_lines = [
            f"Python Socket Scan for {target} ({ip})",
            f"Scanned {len(ports)} ports in {duration:.2f}s",
            "",
            "PORT      STATE   SERVICE     VERSION",
            "-" * 50,
        ]

        for svc in services:
            port_str = f"{svc['port']}/tcp".ljust(10)
            state = "open".ljust(8)
            service = svc["service"].ljust(12)
            product = svc.get("product", "")
            output_lines.append(f"{port_str}{state}{service}{product}")

        raw_output = "\n".join(output_lines)

        return {
            "tool": self.tool_name,
            "target": target,
            "command": f"python_socket_scan({target}, ports={len(ports)})",
            "exit_code": 0,
            "duration": duration,
            "timestamp": start_time.isoformat(),
            "raw_output": raw_output,
            "error": None,
            "parsed": parsed,
        }

    def _parse_port_arg(self, ports_arg: str) -> List[int]:
        """Parse port argument like '22,80,443' or '1-1000'"""
        ports = []
        for part in ports_arg.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-")
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        return ports

    async def _scan_ports(self, ip: str, ports: List[int], timeout: float) -> List[int]:
        """Scan ports concurrently using asyncio"""
        open_ports = []

        async def check_port(port: int) -> Optional[int]:
            try:
                # Use asyncio for non-blocking socket connection
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return port
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

        # Run all port checks concurrently with semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(100)  # Max 100 concurrent connections

        async def limited_check(port: int) -> Optional[int]:
            async with semaphore:
                return await check_port(port)

        tasks = [limited_check(port) for port in ports]
        results = await asyncio.gather(*tasks)

        open_ports = [port for port in results if port is not None]
        return sorted(open_ports)

    async def _detect_services(
        self, ip: str, ports: List[int], timeout: float
    ) -> List[Dict[str, Any]]:
        """Detect services on open ports by grabbing banners"""
        services = []

        for port in ports:
            service_info = {
                "port": port,
                "service": SERVICE_PORTS.get(port, "unknown"),
                "product": "",
                "version": "",
            }

            # Try to grab banner
            banner = await self._grab_banner(ip, port, timeout)
            if banner:
                # Detect service from banner
                detected = self._detect_service_from_banner(banner)
                if detected:
                    service_info["service"] = detected
                service_info["product"] = self._clean_banner(banner)

            services.append(service_info)

        return services

    async def _grab_banner(self, ip: str, port: int, timeout: float) -> str:
        """Grab banner from a service"""
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            # Send HTTP request for web ports
            if port in [80, 443, 8080, 8443, 8000, 8888, 3000]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                await writer.drain()

            # Try to read banner
            try:
                banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                writer.close()
                await writer.wait_closed()
                return banner.decode("utf-8", errors="replace")
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
                return ""
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return ""

    def _detect_service_from_banner(self, banner: str) -> Optional[str]:
        """Detect service type from banner content"""
        for service, patterns in SERVICE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, banner, re.IGNORECASE):
                    return service
        return None

    def _clean_banner(self, banner: str) -> str:
        """Clean banner for display"""
        # Remove control characters and truncate
        cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", banner)
        cleaned = cleaned.strip()
        # Get first line and truncate
        first_line = cleaned.split("\n")[0] if cleaned else ""
        return first_line[:60] if len(first_line) > 60 else first_line

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output"""
        results = {"open_ports": [], "services": [], "os_detection": None, "vulnerabilities": []}

        # Simple regex parsing (in production, use proper XML parser)
        # Extract open ports
        port_pattern = r'portid="(\d+)".*?service name="([^"]*)".*?product="([^"]*)"'
        for match in re.finditer(port_pattern, output, re.DOTALL):
            port = match.group(1)
            service = match.group(2)
            product = match.group(3) if match.group(3) else "unknown"

            results["open_ports"].append(int(port))
            results["services"].append({"port": int(port), "service": service, "product": product})

        # Extract OS if available
        os_match = re.search(r'osclass type="([^"]*)".*?osfamily="([^"]*)"', output)
        if os_match:
            results["os_detection"] = {"type": os_match.group(1), "family": os_match.group(2)}

        return results
