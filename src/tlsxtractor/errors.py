"""
Error classification for TLS scanning.

Provides detailed error categorization, error codes, and classification
functions for enhanced failure diagnostics.
"""

import errno as err_mod
import socket
import ssl
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Tuple


class ErrorCategory(str, Enum):
    """High-level error categories for scan failures."""

    NETWORK = "network"
    TLS = "tls"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    CERTIFICATE = "certificate"
    DNS = "dns"
    SOCKET = "socket"
    UNKNOWN = "unknown"


class ErrorCode(str, Enum):
    """Specific error codes for detailed failure diagnostics."""

    # Connection errors
    CONN_TIMEOUT = "CONN_TIMEOUT"
    CONN_REFUSED = "CONN_REFUSED"
    CONN_RESET = "CONN_RESET"
    CONN_ABORTED = "CONN_ABORTED"
    CONN_BROKEN_PIPE = "CONN_BROKEN_PIPE"

    # Network errors
    NET_UNREACHABLE = "NET_UNREACHABLE"
    NET_HOST_DOWN = "NET_HOST_DOWN"
    NET_HOST_UNREACHABLE = "NET_HOST_UNREACHABLE"
    NET_NO_ROUTE = "NET_NO_ROUTE"
    NET_ADDR_IN_USE = "NET_ADDR_IN_USE"
    NET_ADDR_NOT_AVAILABLE = "NET_ADDR_NOT_AVAILABLE"

    # DNS/Address errors
    DNS_RESOLUTION_FAILED = "DNS_RESOLUTION_FAILED"
    DNS_NAME_NOT_FOUND = "DNS_NAME_NOT_FOUND"
    DNS_NO_DATA = "DNS_NO_DATA"
    DNS_TEMPORARY_FAILURE = "DNS_TEMPORARY_FAILURE"

    # Socket errors
    SOCKET_ERROR = "SOCKET_ERROR"
    SOCKET_CLOSED = "SOCKET_CLOSED"
    SOCKET_TIMEOUT = "SOCKET_TIMEOUT"

    # TLS/SSL errors
    TLS_HANDSHAKE_FAILED = "TLS_HANDSHAKE_FAILED"
    TLS_PROTOCOL_ERROR = "TLS_PROTOCOL_ERROR"
    TLS_VERSION_MISMATCH = "TLS_VERSION_MISMATCH"
    TLS_CIPHER_MISMATCH = "TLS_CIPHER_MISMATCH"
    TLS_EOF = "TLS_EOF"
    TLS_SYSCALL_ERROR = "TLS_SYSCALL_ERROR"
    TLS_ALERT_RECEIVED = "TLS_ALERT_RECEIVED"
    PLAIN_HTTP_NO_TLS = "PLAIN_HTTP_NO_TLS"  # Server not running TLS (plain HTTP, wrong port, etc.)
    TLS_WRONG_VERSION = "TLS_WRONG_VERSION"  # SSL WRONG_VERSION_NUMBER error

    # Certificate errors
    CERT_VERIFICATION_FAILED = "CERT_VERIFICATION_FAILED"
    CERT_NOT_FOUND = "CERT_NOT_FOUND"
    CERT_EXPIRED = "CERT_EXPIRED"
    CERT_INVALID = "CERT_INVALID"
    CERT_SELF_SIGNED = "CERT_SELF_SIGNED"
    CERT_HOSTNAME_MISMATCH = "CERT_HOSTNAME_MISMATCH"

    # General
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    MAX_RETRIES = "MAX_RETRIES"
    CANCELLED = "CANCELLED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    FILE_NOT_FOUND = "FILE_NOT_FOUND"


@dataclass
class TLSScanError(Exception):
    """
    Custom exception for TLS scan errors with detailed classification.

    Preserves error code, category, and detailed information for
    downstream error handling and statistics.
    """

    message: str
    error_code: ErrorCode
    error_category: ErrorCategory
    error_details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


def classify_ssl_error(e: ssl.SSLError) -> Tuple[ErrorCode, ErrorCategory, Dict[str, Any]]:
    """
    Extract detailed information from SSL errors and classify them.

    Args:
        e: The SSL error to classify

    Returns:
        Tuple of (ErrorCode, ErrorCategory, error_details dict)
    """
    details: Dict[str, Any] = {
        "exception_type": type(e).__name__,
        "raw_message": str(e),
    }

    # Extract SSL-specific attributes
    if hasattr(e, "library"):
        details["ssl_library"] = e.library
    if hasattr(e, "reason"):
        details["ssl_reason"] = e.reason
    if hasattr(e, "verify_code"):
        details["ssl_verify_code"] = e.verify_code
    if hasattr(e, "verify_message"):
        details["ssl_verify_message"] = e.verify_message

    # Classify based on exception type
    if isinstance(e, ssl.SSLCertVerificationError):
        # Check for specific cert errors
        msg = str(e).lower()
        if "self signed" in msg or "self-signed" in msg:
            return ErrorCode.CERT_SELF_SIGNED, ErrorCategory.CERTIFICATE, details
        elif "expired" in msg:
            return ErrorCode.CERT_EXPIRED, ErrorCategory.CERTIFICATE, details
        elif "hostname" in msg:
            return ErrorCode.CERT_HOSTNAME_MISMATCH, ErrorCategory.CERTIFICATE, details
        return ErrorCode.CERT_VERIFICATION_FAILED, ErrorCategory.CERTIFICATE, details
    elif isinstance(e, ssl.SSLEOFError):
        return ErrorCode.TLS_EOF, ErrorCategory.TLS, details
    elif isinstance(e, ssl.SSLSyscallError):
        return ErrorCode.TLS_SYSCALL_ERROR, ErrorCategory.TLS, details
    elif isinstance(e, ssl.SSLZeroReturnError):
        return ErrorCode.TLS_EOF, ErrorCategory.TLS, details
    elif isinstance(e, ssl.SSLWantReadError) or isinstance(e, ssl.SSLWantWriteError):
        return ErrorCode.TLS_PROTOCOL_ERROR, ErrorCategory.TLS, details

    # Check ssl_reason attribute for specific error types
    ssl_reason = getattr(e, "reason", "")
    if ssl_reason:
        details["ssl_reason"] = ssl_reason
        # WRONG_VERSION_NUMBER typically means server isn't running TLS
        # (e.g., plain HTTP server, or completely different protocol)
        if ssl_reason == "WRONG_VERSION_NUMBER":
            return ErrorCode.PLAIN_HTTP_NO_TLS, ErrorCategory.TLS, details
        elif ssl_reason == "NO_PROTOCOLS_AVAILABLE":
            return ErrorCode.TLS_VERSION_MISMATCH, ErrorCategory.TLS, details
        elif ssl_reason == "SSLV3_ALERT_HANDSHAKE_FAILURE":
            return ErrorCode.TLS_HANDSHAKE_FAILED, ErrorCategory.TLS, details
        elif "CIPHER" in ssl_reason:
            return ErrorCode.TLS_CIPHER_MISMATCH, ErrorCategory.TLS, details
        elif "ALERT" in ssl_reason:
            return ErrorCode.TLS_ALERT_RECEIVED, ErrorCategory.TLS, details
        elif "PROTOCOL" in ssl_reason:
            return ErrorCode.TLS_PROTOCOL_ERROR, ErrorCategory.TLS, details

    # Parse message for additional hints
    msg = str(e).lower()
    if "handshake" in msg:
        return ErrorCode.TLS_HANDSHAKE_FAILED, ErrorCategory.TLS, details
    elif "protocol" in msg or "version" in msg or "unsupported" in msg:
        return ErrorCode.TLS_VERSION_MISMATCH, ErrorCategory.TLS, details
    elif "cipher" in msg:
        return ErrorCode.TLS_CIPHER_MISMATCH, ErrorCategory.TLS, details
    elif "alert" in msg:
        return ErrorCode.TLS_ALERT_RECEIVED, ErrorCategory.TLS, details
    elif "certificate" in msg:
        return ErrorCode.CERT_INVALID, ErrorCategory.CERTIFICATE, details
    elif "eof" in msg or "unexpected eof" in msg:
        return ErrorCode.TLS_EOF, ErrorCategory.TLS, details

    return ErrorCode.TLS_PROTOCOL_ERROR, ErrorCategory.TLS, details


def classify_socket_error(e: socket.error) -> Tuple[ErrorCode, ErrorCategory, Dict[str, Any]]:
    """
    Extract detailed information from socket errors and classify them.

    Args:
        e: The socket error to classify

    Returns:
        Tuple of (ErrorCode, ErrorCategory, error_details dict)
    """
    details: Dict[str, Any] = {
        "exception_type": type(e).__name__,
        "raw_message": str(e),
    }

    # socket.gaierror - getaddrinfo() errors (DNS-related)
    if isinstance(e, socket.gaierror):
        error_code_num = e.args[0] if e.args else None
        details["gaierror_code"] = error_code_num

        # Common gaierror codes
        if error_code_num == socket.EAI_NONAME:
            return ErrorCode.DNS_NAME_NOT_FOUND, ErrorCategory.DNS, details
        elif error_code_num == socket.EAI_NODATA:
            return ErrorCode.DNS_NO_DATA, ErrorCategory.DNS, details
        elif error_code_num == socket.EAI_AGAIN:
            return ErrorCode.DNS_TEMPORARY_FAILURE, ErrorCategory.DNS, details
        elif error_code_num == socket.EAI_FAIL:
            return ErrorCode.DNS_RESOLUTION_FAILED, ErrorCategory.DNS, details
        return ErrorCode.DNS_RESOLUTION_FAILED, ErrorCategory.DNS, details

    # socket.herror - legacy address errors
    if isinstance(e, socket.herror):
        details["herror_code"] = e.args[0] if e.args else None
        return ErrorCode.DNS_RESOLUTION_FAILED, ErrorCategory.DNS, details

    # socket.timeout
    if isinstance(e, socket.timeout):
        return ErrorCode.SOCKET_TIMEOUT, ErrorCategory.TIMEOUT, details

    # Generic socket error - check errno
    if hasattr(e, "errno") and e.errno is not None:
        details["errno"] = e.errno
        details["errno_name"] = err_mod.errorcode.get(e.errno, "UNKNOWN")

    return ErrorCode.SOCKET_ERROR, ErrorCategory.SOCKET, details


def classify_os_error(e: OSError) -> Tuple[ErrorCode, ErrorCategory, Dict[str, Any]]:
    """
    Extract detailed information from OS/network errors and classify them.

    Args:
        e: The OS error to classify

    Returns:
        Tuple of (ErrorCode, ErrorCategory, error_details dict)
    """
    details: Dict[str, Any] = {
        "exception_type": type(e).__name__,
        "raw_message": str(e),
    }

    # Handle specific OSError subclasses first
    if isinstance(e, ConnectionResetError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNRESET)
        details["errno_name"] = "ECONNRESET"
        return ErrorCode.CONN_RESET, ErrorCategory.NETWORK, details

    if isinstance(e, ConnectionAbortedError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNABORTED)
        details["errno_name"] = "ECONNABORTED"
        return ErrorCode.CONN_ABORTED, ErrorCategory.NETWORK, details

    if isinstance(e, ConnectionRefusedError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNREFUSED)
        details["errno_name"] = "ECONNREFUSED"
        return ErrorCode.CONN_REFUSED, ErrorCategory.REFUSED, details

    if isinstance(e, BrokenPipeError):
        details["errno"] = getattr(e, "errno", err_mod.EPIPE)
        details["errno_name"] = "EPIPE"
        return ErrorCode.CONN_BROKEN_PIPE, ErrorCategory.NETWORK, details

    if isinstance(e, TimeoutError):
        details["errno"] = getattr(e, "errno", err_mod.ETIMEDOUT)
        details["errno_name"] = "ETIMEDOUT"
        return ErrorCode.CONN_TIMEOUT, ErrorCategory.TIMEOUT, details

    if isinstance(e, PermissionError):
        details["errno"] = getattr(e, "errno", err_mod.EACCES)
        details["errno_name"] = "EACCES"
        return ErrorCode.PERMISSION_DENIED, ErrorCategory.UNKNOWN, details

    if isinstance(e, FileNotFoundError):
        details["errno"] = getattr(e, "errno", err_mod.ENOENT)
        details["errno_name"] = "ENOENT"
        return ErrorCode.FILE_NOT_FOUND, ErrorCategory.UNKNOWN, details

    # Check for socket-specific errors (gaierror, herror are NOT aliases for OSError)
    if isinstance(e, socket.gaierror):
        return classify_socket_error(e)
    if isinstance(e, socket.herror):
        return classify_socket_error(e)

    # Extract errno info
    if hasattr(e, "errno") and e.errno is not None:
        details["errno"] = e.errno
        details["errno_name"] = err_mod.errorcode.get(e.errno, f"ERRNO_{e.errno}")

    # Map errno to specific codes
    errno_val = getattr(e, "errno", None)

    errno_mapping = {
        err_mod.ENETUNREACH: (ErrorCode.NET_UNREACHABLE, ErrorCategory.NETWORK),
        err_mod.EHOSTUNREACH: (ErrorCode.NET_HOST_UNREACHABLE, ErrorCategory.NETWORK),
        err_mod.EHOSTDOWN: (ErrorCode.NET_HOST_DOWN, ErrorCategory.NETWORK),
        err_mod.ECONNRESET: (ErrorCode.CONN_RESET, ErrorCategory.NETWORK),
        err_mod.ECONNABORTED: (ErrorCode.CONN_ABORTED, ErrorCategory.NETWORK),
        err_mod.ECONNREFUSED: (ErrorCode.CONN_REFUSED, ErrorCategory.REFUSED),
        err_mod.ENETDOWN: (ErrorCode.NET_NO_ROUTE, ErrorCategory.NETWORK),
        err_mod.ETIMEDOUT: (ErrorCode.CONN_TIMEOUT, ErrorCategory.TIMEOUT),
        err_mod.EPIPE: (ErrorCode.CONN_BROKEN_PIPE, ErrorCategory.NETWORK),
        err_mod.EADDRINUSE: (ErrorCode.NET_ADDR_IN_USE, ErrorCategory.NETWORK),
        err_mod.EADDRNOTAVAIL: (ErrorCode.NET_ADDR_NOT_AVAILABLE, ErrorCategory.NETWORK),
        err_mod.EACCES: (ErrorCode.PERMISSION_DENIED, ErrorCategory.UNKNOWN),
        err_mod.ENOENT: (ErrorCode.FILE_NOT_FOUND, ErrorCategory.UNKNOWN),
    }

    if errno_val in errno_mapping:
        code, category = errno_mapping[errno_val]
        return code, category, details

    # Check message for hints
    msg = str(e).lower()
    message_patterns = [
        (["ssl", "tls"], ErrorCode.TLS_PROTOCOL_ERROR, ErrorCategory.TLS),
        (["timeout", "timed out"], ErrorCode.CONN_TIMEOUT, ErrorCategory.TIMEOUT),
        (["refused", "reject"], ErrorCode.CONN_REFUSED, ErrorCategory.REFUSED),
        (["reset"], ErrorCode.CONN_RESET, ErrorCategory.NETWORK),
        (["unreachable"], ErrorCode.NET_UNREACHABLE, ErrorCategory.NETWORK),
        (["broken pipe"], ErrorCode.CONN_BROKEN_PIPE, ErrorCategory.NETWORK),
        (["permission", "denied", "access"], ErrorCode.PERMISSION_DENIED, ErrorCategory.UNKNOWN),
        (["no route"], ErrorCode.NET_NO_ROUTE, ErrorCategory.NETWORK),
        (["host down", "host is down"], ErrorCode.NET_HOST_DOWN, ErrorCategory.NETWORK),
    ]

    for patterns, code, category in message_patterns:
        if any(p in msg for p in patterns):
            return code, category, details

    # If we still don't know, include more diagnostic info
    details["unclassified_errno"] = errno_val
    details["exception_class"] = e.__class__.__name__
    details["exception_bases"] = [b.__name__ for b in e.__class__.__mro__[1:5]]

    return ErrorCode.UNKNOWN_ERROR, ErrorCategory.UNKNOWN, details


def classify_exception(e: Exception) -> Tuple[ErrorCode, ErrorCategory, Dict[str, Any]]:
    """
    Classify any exception into error code and category.

    Args:
        e: The exception to classify

    Returns:
        Tuple of (ErrorCode, ErrorCategory, error_details dict)
    """
    details: Dict[str, Any] = {
        "exception_type": type(e).__name__,
        "exception_module": type(e).__module__,
        "raw_message": str(e),
        "exception_bases": [b.__name__ for b in type(e).__mro__[1:5]],
    }

    # SSL errors (check first as SSLError is subclass of OSError)
    if isinstance(e, ssl.SSLError):
        return classify_ssl_error(e)

    # Check specific connection error types BEFORE socket.error
    # (because socket.error is an alias for OSError in Python 3)
    if isinstance(e, ConnectionResetError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNRESET)
        details["errno_name"] = "ECONNRESET"
        return ErrorCode.CONN_RESET, ErrorCategory.NETWORK, details

    if isinstance(e, ConnectionAbortedError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNABORTED)
        details["errno_name"] = "ECONNABORTED"
        return ErrorCode.CONN_ABORTED, ErrorCategory.NETWORK, details

    if isinstance(e, ConnectionRefusedError):
        details["errno"] = getattr(e, "errno", err_mod.ECONNREFUSED)
        details["errno_name"] = "ECONNREFUSED"
        return ErrorCode.CONN_REFUSED, ErrorCategory.REFUSED, details

    if isinstance(e, BrokenPipeError):
        details["errno"] = getattr(e, "errno", err_mod.EPIPE)
        details["errno_name"] = "EPIPE"
        return ErrorCode.CONN_BROKEN_PIPE, ErrorCategory.NETWORK, details

    if isinstance(e, TimeoutError):
        details["errno"] = getattr(e, "errno", err_mod.ETIMEDOUT)
        details["errno_name"] = "ETIMEDOUT"
        return ErrorCode.CONN_TIMEOUT, ErrorCategory.TIMEOUT, details

    # Socket-specific errors (gaierror, herror, timeout)
    if isinstance(e, socket.gaierror):
        return classify_socket_error(e)

    if isinstance(e, socket.herror):
        return classify_socket_error(e)

    if isinstance(e, socket.timeout):
        return ErrorCode.SOCKET_TIMEOUT, ErrorCategory.TIMEOUT, details

    # General OS errors
    if isinstance(e, OSError):
        return classify_os_error(e)

    # asyncio.CancelledError
    if type(e).__name__ == "CancelledError":
        return ErrorCode.CANCELLED, ErrorCategory.UNKNOWN, details

    # EOFError
    if isinstance(e, EOFError):
        return ErrorCode.TLS_EOF, ErrorCategory.TLS, details

    # Check message for hints even on unknown exceptions
    msg = str(e).lower()
    if "timeout" in msg or "timed out" in msg:
        return ErrorCode.CONN_TIMEOUT, ErrorCategory.TIMEOUT, details
    elif "refused" in msg:
        return ErrorCode.CONN_REFUSED, ErrorCategory.REFUSED, details
    elif "reset" in msg:
        return ErrorCode.CONN_RESET, ErrorCategory.NETWORK, details
    elif "ssl" in msg or "tls" in msg:
        return ErrorCode.TLS_PROTOCOL_ERROR, ErrorCategory.TLS, details
    elif "certificate" in msg or "cert" in msg:
        return ErrorCode.CERT_INVALID, ErrorCategory.CERTIFICATE, details
    elif "dns" in msg or "resolve" in msg or "getaddrinfo" in msg:
        return ErrorCode.DNS_RESOLUTION_FAILED, ErrorCategory.DNS, details

    return ErrorCode.UNKNOWN_ERROR, ErrorCategory.UNKNOWN, details
