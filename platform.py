#!/usr/bin/env python3
"""Assignment-required launcher and standard-library compatibility shim.

When imported by NumPy/joblib this file proxies the real standard-library
module. When executed as `python platform.py`, it launches SentinelForge.
"""
import importlib.util
import sys
import sysconfig

stdlib_platform = sysconfig.get_path('stdlib') + '/platform.py'
if __name__ == 'platform':
    with open(stdlib_platform, encoding='utf-8') as _f:
        exec(compile(_f.read(), stdlib_platform, 'exec'), globals())
else:
    if 'platform' not in sys.modules:
        spec = importlib.util.spec_from_file_location('platform', stdlib_platform)
        module = importlib.util.module_from_spec(spec)
        sys.modules['platform'] = module
        spec.loader.exec_module(module)
    from sentinelforge.orchestrator import main
    if __name__ == '__main__':
        main()
