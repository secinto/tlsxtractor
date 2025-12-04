"""
Protocol-specific handlers for TLS connections.

Supports different protocols that require specific handshakes before TLS:
- Direct TLS (HTTPS on 443, IMAPS on 993, POP3S on 995)
- STARTTLS (SMTP on 587, IMAP on 143, POP3 on 110)
- SSH (port 22) - Note: SSH doesn't use X.509 certificates like TLS
"""

import asyncio
import logging
import ssl
from abc import ABC, abstractmethod
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class ProtocolHandler(ABC):
    """Base class for protocol-specific TLS connection handlers."""

    def __init__(self, timeout: int = 5):
        """
        Initialize protocol handler.

        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout

    @abstractmethod
    async def establish_tls_connection(
        self,
        ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish TLS connection for this protocol.

        Args:
            ip: Target IP address
            port: Target port
            ssl_context: SSL context to use
            server_hostname: SNI hostname

        Returns:
            Tuple of (reader, writer) for the TLS connection

        Raises:
            Various exceptions on failure
        """
        pass

    @abstractmethod
    def get_protocol_name(self) -> str:
        """Get the protocol name for logging."""
        pass


class DirectTLSHandler(ProtocolHandler):
    """Handler for direct TLS connections (HTTPS, IMAPS, POP3S)."""

    def __init__(self, protocol_name: str = "HTTPS", timeout: int = 5):
        """
        Initialize direct TLS handler.

        Args:
            protocol_name: Name of the protocol for logging
            timeout: Connection timeout in seconds
        """
        super().__init__(timeout)
        self.protocol_name = protocol_name

    async def establish_tls_connection(
        self,
        ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish direct TLS connection.

        This is the simplest case - TLS is initiated immediately.
        """
        logger.debug(f"Establishing direct TLS connection to {ip}:{port}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=ssl_context,
                server_hostname=server_hostname,
            ),
            timeout=self.timeout,
        )

        return reader, writer

    def get_protocol_name(self) -> str:
        return self.protocol_name


class SMTPSTARTTLSHandler(ProtocolHandler):
    """Handler for SMTP with STARTTLS (port 587, 25)."""

    async def establish_tls_connection(
        self,
        ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish SMTP STARTTLS connection.

        SMTP Flow:
        1. Connect in plaintext
        2. Receive server greeting (220)
        3. Send EHLO command
        4. Receive EHLO response with capabilities
        5. Send STARTTLS command
        6. Receive 220 Ready to start TLS
        7. Upgrade to TLS
        """
        logger.debug(f"Establishing SMTP STARTTLS connection to {ip}:{port}")

        # Step 1: Connect in plaintext
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.timeout,
        )

        try:
            # Step 2: Read server greeting (220 ...)
            greeting = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"SMTP greeting: {greeting.decode().strip()}")

            if not greeting.startswith(b"220"):
                raise OSError(f"Unexpected SMTP greeting: {greeting.decode().strip()}")

            # Step 3: Send EHLO
            ehlo_domain = server_hostname or "tlsxtractor.local"
            writer.write(f"EHLO {ehlo_domain}\r\n".encode())
            await writer.drain()

            # Step 4: Read EHLO response (multi-line, ends with code without hyphen)
            while True:
                line = await asyncio.wait_for(
                    reader.readline(),
                    timeout=self.timeout,
                )
                logger.debug(f"SMTP EHLO response: {line.decode().strip()}")
                # Last line of EHLO response has format "250 " (space, not hyphen)
                if line.startswith(b"250 "):
                    break
                if not line.startswith(b"250-"):
                    raise OSError(f"Unexpected EHLO response: {line.decode().strip()}")

            # Step 5: Send STARTTLS
            writer.write(b"STARTTLS\r\n")
            await writer.drain()

            # Step 6: Read STARTTLS response
            response = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"SMTP STARTTLS response: {response.decode().strip()}")

            if not response.startswith(b"220"):
                raise OSError(f"STARTTLS not ready: {response.decode().strip()}")

            # Step 7: Upgrade to TLS
            transport = writer.transport
            protocol = transport.get_protocol()

            # Create new TLS transport
            loop = asyncio.get_event_loop()
            new_transport = await loop.start_tls(
                transport,
                protocol,
                ssl_context,
                server_hostname=server_hostname,
            )

            # Update writer with new transport
            writer._transport = new_transport  # type: ignore[attr-defined]

            return reader, writer

        except Exception as e:
            writer.close()
            await writer.wait_closed()
            raise OSError(f"SMTP STARTTLS failed: {e}")

    def get_protocol_name(self) -> str:
        return "SMTP"


class IMAPSTARTTLSHandler(ProtocolHandler):
    """Handler for IMAP with STARTTLS (port 143)."""

    async def establish_tls_connection(
        self,
        ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish IMAP STARTTLS connection.

        IMAP Flow:
        1. Connect in plaintext
        2. Receive server greeting (* OK)
        3. Send STARTTLS command with tag
        4. Receive OK response
        5. Upgrade to TLS
        """
        logger.debug(f"Establishing IMAP STARTTLS connection to {ip}:{port}")

        # Step 1: Connect in plaintext
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.timeout,
        )

        try:
            # Step 2: Read server greeting
            greeting = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"IMAP greeting: {greeting.decode().strip()}")

            if not greeting.startswith(b"* OK"):
                raise OSError(f"Unexpected IMAP greeting: {greeting.decode().strip()}")

            # Step 3: Send STARTTLS command
            writer.write(b"A001 STARTTLS\r\n")
            await writer.drain()

            # Step 4: Read STARTTLS response
            response = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"IMAP STARTTLS response: {response.decode().strip()}")

            if not response.startswith(b"A001 OK"):
                raise OSError(f"STARTTLS not ready: {response.decode().strip()}")

            # Step 5: Upgrade to TLS
            transport = writer.transport
            protocol = transport.get_protocol()

            loop = asyncio.get_event_loop()
            new_transport = await loop.start_tls(
                transport,
                protocol,
                ssl_context,
                server_hostname=server_hostname,
            )

            writer._transport = new_transport  # type: ignore[attr-defined]

            return reader, writer

        except Exception as e:
            writer.close()
            await writer.wait_closed()
            raise OSError(f"IMAP STARTTLS failed: {e}")

    def get_protocol_name(self) -> str:
        return "IMAP"


class POP3STARTTLSHandler(ProtocolHandler):
    """Handler for POP3 with STARTTLS (port 110)."""

    async def establish_tls_connection(
        self,
        ip: str,
        port: int,
        ssl_context: ssl.SSLContext,
        server_hostname: Optional[str] = None,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Establish POP3 STARTTLS connection.

        POP3 Flow:
        1. Connect in plaintext
        2. Receive server greeting (+OK)
        3. Send STLS command
        4. Receive +OK response
        5. Upgrade to TLS
        """
        logger.debug(f"Establishing POP3 STARTTLS connection to {ip}:{port}")

        # Step 1: Connect in plaintext
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.timeout,
        )

        try:
            # Step 2: Read server greeting
            greeting = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"POP3 greeting: {greeting.decode().strip()}")

            if not greeting.startswith(b"+OK"):
                raise OSError(f"Unexpected POP3 greeting: {greeting.decode().strip()}")

            # Step 3: Send STLS command (note: POP3 uses STLS, not STARTTLS)
            writer.write(b"STLS\r\n")
            await writer.drain()

            # Step 4: Read STLS response
            response = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout,
            )
            logger.debug(f"POP3 STLS response: {response.decode().strip()}")

            if not response.startswith(b"+OK"):
                raise OSError(f"STLS not ready: {response.decode().strip()}")

            # Step 5: Upgrade to TLS
            transport = writer.transport
            protocol = transport.get_protocol()

            loop = asyncio.get_event_loop()
            new_transport = await loop.start_tls(
                transport,
                protocol,
                ssl_context,
                server_hostname=server_hostname,
            )

            writer._transport = new_transport  # type: ignore[attr-defined]

            return reader, writer

        except Exception as e:
            writer.close()
            await writer.wait_closed()
            raise OSError(f"POP3 STLS failed: {e}")

    def get_protocol_name(self) -> str:
        return "POP3"


class ProtocolDetector:
    """
    Automatically detect and return appropriate protocol handler for a port.
    """

    # Port to protocol mapping
    PORT_PROTOCOLS = {
        # Direct TLS
        443: ("HTTPS", DirectTLSHandler),
        8443: ("HTTPS", DirectTLSHandler),
        993: ("IMAPS", DirectTLSHandler),  # IMAP over SSL
        995: ("POP3S", DirectTLSHandler),  # POP3 over SSL
        # STARTTLS
        25: ("SMTP", SMTPSTARTTLSHandler),  # SMTP with STARTTLS
        587: ("SMTP", SMTPSTARTTLSHandler),  # SMTP submission with STARTTLS
        143: ("IMAP", IMAPSTARTTLSHandler),  # IMAP with STARTTLS
        110: ("POP3", POP3STARTTLSHandler),  # POP3 with STARTTLS
    }

    @classmethod
    def get_handler(cls, port: int, timeout: int = 5) -> ProtocolHandler:
        """
        Get appropriate protocol handler for a port.

        Args:
            port: Target port number
            timeout: Connection timeout

        Returns:
            ProtocolHandler instance for the port
        """
        if port in cls.PORT_PROTOCOLS:
            protocol_name, handler_class = cls.PORT_PROTOCOLS[port]
            handler: ProtocolHandler
            if handler_class == DirectTLSHandler:
                handler = DirectTLSHandler(protocol_name=protocol_name, timeout=timeout)
            else:
                handler = handler_class(timeout=timeout)
            return handler
        else:
            # Default to direct TLS for unknown ports
            return DirectTLSHandler(protocol_name="TLS", timeout=timeout)

    @classmethod
    def get_protocol_name(cls, port: int) -> str:
        """
        Get protocol name for a port.

        Args:
            port: Target port number

        Returns:
            Protocol name string
        """
        if port in cls.PORT_PROTOCOLS:
            return cls.PORT_PROTOCOLS[port][0]
        return "TLS"

    @classmethod
    def get_default_scan_ports(cls) -> list[int]:
        """
        Get default ports to scan when no port is specified.

        Returns:
            List of default ports: [443, 993, 995, 587]
        """
        return [443, 993, 995, 587]
