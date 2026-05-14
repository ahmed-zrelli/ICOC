import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Lab Mode
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"
    
    # Victim VMs
    VICTIM_IP = os.getenv("VICTIM_IP", "192.168.234.129")
    VICTIM_HOSTNAME = os.getenv("VICTIM_HOSTNAME", "metasploitable3")
    WINDOWS_VICTIM_IP = os.getenv("WINDOWS_VICTIM_IP", "192.168.234.130")
    WINDOWS_VICTIM_HOSTNAME = os.getenv("WINDOWS_VICTIM_HOSTNAME", "windows2012")
    
    # Attacker
    ATTACKER_IP = os.getenv("ATTACKER_IP", "192.168.234.200")
    ATTACKER_SERVER_URL = os.getenv("ATTACKER_SERVER_URL", "http://192.168.234.200:5000")
    
    # Network
    LAB_NETWORK = os.getenv("LAB_NETWORK", "192.168.234.0/24")
    LAB_HOSTS = os.getenv("LAB_HOSTS", "").split(",")
    LAB_OFFLINE_MODE = os.getenv("LAB_OFFLINE_MODE", "false").lower() == "true"
    
    # Victim SSH
    VICTIM_SSH_USER = os.getenv("VICTIM_SSH_USER", "msfadmin")
    VICTIM_SSH_PASS = os.getenv("VICTIM_SSH_PASS", "msfadmin")
    VICTIM_SSH_PORT = int(os.getenv("VICTIM_SSH_PORT", "22"))
    
    # Database
    POSTGRES_URL = os.getenv("POSTGRES_URL", "postgresql://icoc:icoc2026@db:5432/icoc")
    
    # API Keys
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    NVD_API_KEY = os.getenv("NVD_API_KEY")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    # NOC Module (Zabbix)
    ZABBIX_API_URL = os.getenv("ZABBIX_API_URL", "http://noc-zabbix-web:8080/api_jsonrpc.php")
    ZABBIX_USER = os.getenv("ZABBIX_USER", "Admin")
    ZABBIX_PASS = os.getenv("ZABBIX_PASS", "zabbix")
    
    # SOC Module (Wazuh)
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://192.168.100.10:55000")
    WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.100.10:9200")
    WAZUH_USER = os.getenv("WAZUH_USER", "admin")
    WAZUH_PASS = os.getenv("WAZUH_PASS", "SecretPassword")
    WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "false").lower() == "true"
    WAZUH_POLL_INTERVAL_SECONDS = int(os.getenv("WAZUH_POLL_INTERVAL_SECONDS", "10"))
    WAZUH_INDEXER_INDEX = os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-4.x-*")
    WAZUH_MAX_ALERT_AGE_HOURS = int(os.getenv("WAZUH_MAX_ALERT_AGE_HOURS", "720"))

config = Config()
