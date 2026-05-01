from fastapi import APIRouter

from soc.wazuh_poller import get_wazuh_poller_status


soc_router = APIRouter(prefix="/soc", tags=["SOC"])


@soc_router.get("/status")
def soc_status():
    return {
        "wazuh": get_wazuh_poller_status(),
        "module": "ICOC SOC Module",
    }
