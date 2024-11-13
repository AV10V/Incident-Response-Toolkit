#!/usr/bin/env python3

import subprocess
import argparse

# Display header and instructions to run from the console
"""
### Incident-Response-Toolkit: Memory Analyzer ###
### Usage: python3 memory_analyzer.py --file <memory_dump_file> ###
### Example: python3 memory_analyzer.py --file memdump.raw ###
### Author: AV10V ###
"""

def analyze_processes(memory_file):
    """Analyze processes in a memory dump for suspicious activity."""
    print("[*] Analyzing processes...")
    subprocess.run(["volatility", "-f", memory_file, "--profile=Win10x64_18362", "pslist"])

def analyze_connections(memory_file):
    """Analyze network connections in a memory dump."""
    print("[*] Analyzing network connections...")
    subprocess.run(["volatility", "-f", memory_file, "--profile=Win10x64_18362", "netscan"])

def main():
    parser = argparse.ArgumentParser(description="Analyze memory dumps for indicators of compromise.")
    parser.add_argument("--file", "-f", required=True, help="Path to the memory dump file")
    parser.add_argument("--all", action="store_true", help="Run all analysis modules")

    args = parser.parse_args()
    
    if args.all:
        analyze_processes(args.file)
        analyze_connections(args.file)
    else:
        print("Specify an analysis type or use --all to run all analyses")

if __name__ == "__main__":
    main()
