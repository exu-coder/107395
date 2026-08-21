#!/usr/bin/env python3
"""
EXUCODER PROXY - Main Entry Point for Render
"""

import os
import sys

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
    
    # Add backend directory to Python path
    backend_dir = os.path.join(os.path.dirname(__file__), 'backend')
    sys.path.insert(0, backend_dir)
    
    # Change to backend directory
    os.chdir(backend_dir)
    
    print("[+] Starting EXUCODER Proxy Backend...")
    print("[+] Server will be available at: http://localhost:5000")
    print("[+] Press Ctrl+C to stop\n")
    
    try:
        from app import app
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
