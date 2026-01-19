# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# run.py
#!/usr/bin/env python3
"""
Relational Azure DevOps Runner
Run this script to start the FastAPI server with configurable options.
"""
import argparse
import uvicorn
import logging
import sys
from pathlib import Path

# Ensure project root is in path
sys.path.append(str(Path(__file__).resolve().parent))

def main():
    parser = argparse.ArgumentParser(description="Run Relational Azure DevOps Runner")
    parser.add_argument(
        "--host", 
        default="0.0.0.0",
        help="Bind socket to this host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=8000,
        help="Bind socket to this port (default: 8000)"
    )
    parser.add_argument(
        "--reload", 
        action="store_true",
        help="Enable auto-reload (development only)"
    )
    parser.add_argument(
        "--log-level", 
        default="info",
        choices=["critical", "error", "warning", "info", "debug"],
        help="Set logging level (default: info)"
    )
    args = parser.parse_args()

    # Configure logging to suppress uvicorn access logs in higher log levels
    if args.log_level in ["critical", "error", "warning"]:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    
    # Suppress excessive Azure SDK logs
    azure_logger = logging.getLogger("azure")
    azure_logger.setLevel(logging.WARNING)

    http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    http_logger.setLevel(logging.WARNING)

    # Start server
    uvicorn.run(
        "app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level=args.log_level,
    )

if __name__ == "__main__":
    main()