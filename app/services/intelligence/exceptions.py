"""
CyberSentinel — Intelligence Exceptions
"""

class ProviderError(Exception):
    """Base exception for provider lookup failures."""
    pass

class ProviderNotFoundError(ProviderError):
    """Provider found no intelligence for the requested IP."""
    pass

class ProviderQuotaExceededError(ProviderError):
    """Provider API limits exhausted."""
    pass

class ProviderUnavailableError(ProviderError):
    """Provider could not be reached (timeouts, upstream 5xx)."""
    pass

class InvalidIntelTargetError(Exception):
    """Requested IP is invalid, private, or loopback."""
    pass
