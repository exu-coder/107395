#!/usr/bin/env python3
"""
EXUCODER PROXY - Launcher
"""

import os
import sys
import subprocess
import time

def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██╗  ██╗██╗   ██╗    ██████╗ ██████╗ ██████╗ ███████╗
║  ██╔════╝╚██╗██╔╝██║   ██║   ██╔════╝██╔═══██╗██╔══██╗██╔════╝
║  █████╗   ╚███╔╝ ██║   ██║   ██║     ██║   ██║██║  ██║█████╗  
║  ██╔══╝   ██╔██╗ ██║   ██║   ██║     ██║   ██║██║  ██║██╔══╝  
║  ███████╗██╔╝ ██╗╚██████╔╝   ╚██████╗╚██████╔╝██████╔╝███████╗
║  ╚══════╝╚═╝  ╚═╝ ╚═════╝     ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
║                                                             ║
║              𝐄𝐗𝐔𝐂𝐎𝐃𝐄𝐑 𝐏𝐑𝐎𝐗𝐘 𝐕𝟐.𝟎                         ║
║         𝐉𝐖𝐓 𝐂𝐚𝐩𝐭𝐮𝐫𝐞 & 𝐒𝐰𝐢𝐩𝐞 𝐒𝐲𝐬𝐭𝐞𝐦                       ║
╚═══════════════════════════════════════════════════════════════╝
    """)

def main():
    print_banner()
    
    # Change to backend directory
    backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
    os.chdir(backend_dir)
    
    print("[+] Starting EXUCODER Proxy Backend...")
    print("[+] Server will be available at: http://localhost:5000")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        subprocess.run([sys.executable, 'app.py'])
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()