"""Full Scan wrapper - standalone usage."""
from core.engine import CyberEngine
def run(path=None, callback=None):
    return CyberEngine().full_scan(root_path=path, callback=callback)
