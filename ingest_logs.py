from sentinelforge.ingest_logs import *

if __name__ == '__main__':
    import argparse
    from sentinelforge.utils import load_config, ensure_runtime
    p = argparse.ArgumentParser(); p.add_argument('--input', default='data/sample_logs.jsonl'); p.add_argument('--output', default=None)
    a = p.parse_args(); cfg = load_config(); ensure_runtime(cfg); ingest_file(a.input, a.output or cfg['storage']['events_file'])

# Core implementation: sentinelforge/ingest_logs.py

# This file intentionally preserves the assignment's requested module name while
# keeping the implementation importable and independently testable.

# Assignment contract: accept log files, normalize records, and write JSONL.
