#!/usr/bin/env python
"""CrabAV Backend Starter — đảm bảo load đúng code."""
import sys, os
sys.dont_write_bytecode = True
os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, '.')

from src.api_server import app
import uvicorn

if __name__ == "__main__":
    print("Starting CrabAV Backend on http://127.0.0.1:19527")
    uvicorn.run(app, host="127.0.0.1", port=19527, log_level="info")
