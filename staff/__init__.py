"""
Staff of the Grey Pilgrim
~~~~~~~~~~~~~~~~~~~~~~~~~

A Gandalf-themed security assessment CLI that wraps real security tools
and generates narrative reports written in the Grey Pilgrim's voice.

"All that is gold does not glitter,
Not all those who wander are lost;
The old that is strong does not wither,
Deep roots are not reached by the frost."

Basic usage:
    >>> from staff import illuminate, shadowfax, delve, scry
    >>> results = illuminate.discover_hosts("192.168.1.0/24")

:copyright: (c) 2024 Grey Pilgrim Security
:license: MIT, see LICENSE for more details.
"""

__version__ = "0.3.0"
__author__ = "Grey Pilgrim Security"
__license__ = "MIT"

from staff.config import settings, get_quote

__all__ = ["__version__", "settings", "get_quote"]
