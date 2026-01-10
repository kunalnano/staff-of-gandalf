"""
Analysis Modules
~~~~~~~~~~~~~~~~

Security analysis and threat assessment modules.

Modules:
    - threat_assess: Analyze scan results and flag concerns by severity
    - port_wisdom: Knowledge base mapping ports to risk levels and commentary

"The wise speak only of what they know."
"""

from staff.analysis.threat_assess import assess_threats
from staff.analysis.port_wisdom import PORT_WISDOM, get_port_info

__all__ = ["assess_threats", "PORT_WISDOM", "get_port_info"]
