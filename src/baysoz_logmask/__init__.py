"""Public API for the log masking library."""

from .masker import Masker, mask_stream, merge_stats
from .rules import RULES, Rule

__version__ = "0.1.0"

__all__ = ["RULES", "Masker", "Rule", "__version__", "mask_stream", "merge_stats"]
