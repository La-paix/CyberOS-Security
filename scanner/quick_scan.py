"""Quick Scan wrapper - standalone usage."""
from core.engine import CyberEngine
def run(callback=None):
    return CyberEngine().quick_scan(callback=callback)
