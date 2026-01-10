"""
Reporting Modules
~~~~~~~~~~~~~~~~~

Report generation and output formatting.

Modules:
    - council: Generate final markdown report from scan data

"The tale is now told. May this counsel serve you well."
"""

from staff.reporting.council import generate_report

__all__ = ["generate_report"]
