"""Network Scan wrapper."""
from elpati.elpati_network_guard import ElpatiNetworkGuard
def run(target="127.0.0.1"):
    return ElpatiNetworkGuard().port_scan(target)
