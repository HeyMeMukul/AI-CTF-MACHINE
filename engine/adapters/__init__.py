"""Platform adapters."""

from .ctfd import CTFdAdapter, CTFdOracle, parse_attempt, parse_challenge_list
from .local import LocalAdapter

__all__ = ["CTFdAdapter", "CTFdOracle", "LocalAdapter", "parse_attempt", "parse_challenge_list"]
