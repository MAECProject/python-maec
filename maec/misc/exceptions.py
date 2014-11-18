"""Common exception classes used by MAEC conversion tools."""

"""Indicates a failure caused by a rejected API key."""
class APIKeyException(Exception):
    pass

"""Indicates a failure caused by a rejected API key."""
class NetworkFailureException(Exception):
    pass

"""Indicates a failure caused by a request for a resource unknown to some service.
(e.g., asking for a report from ThreatExpert by MD5, but the MD5 is unknown to ThreatExpert)"""
class LookupNotFoundException(Exception):
    pass
