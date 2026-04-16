"""
SOC (Security Operations Center) Integration Module
Connects Wazuh SIEM to the ICOC-Lite VOC/NOC system
"""

from .soc_wazuh_bridge import WazuhBridge, get_wazuh_bridge
from .soc_pipeline import SOCPipeline, start_soc_pipeline

__all__ = ['WazuhBridge', 'get_wazuh_bridge', 'SOCPipeline', 'start_soc_pipeline']
