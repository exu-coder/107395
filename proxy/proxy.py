#!/usr/bin/env python3
"""
EXUCODER FF PROXY - JWT Capture & Swipe Proxy
Captures JWT → Checks backend → Replaces with user's JWT
"""

import os
import sys
import json
import time
import socket
import threading
import requests
import base64
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# =============================================================================
# COLORS
# =============================================================================

class Colors:
    GREEN = '\033[1;92m'
    YELLOW = '\033[1;93m'
    RED = '\033[1;91m'
    CYAN = '\033[1;96m'
    END = '\033[0m'
    WHITE = '\033[1;97m'
    BLUE = '\033[1;94m'
    PURPLE = '\033[1;95m'
    BOLD = '\033[1m'

# =============================================================================
# CONFIGURATION
# =============================================================================

BACKEND_URL = "http://localhost:5000"
API_KEY = None  # Will be set by user

class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    
    def do_CONNECT(self):
        try:
            host, port = self.path.split(':')
            port = int(port)
            
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.settimeout(30)
            target_sock.connect((host, port))
            
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            client_sock = self.connection
            threading.Thread(target=self._forward, args=(client_sock, target_sock), daemon=True).start()
            threading.Thread(target=self._forward, args=(target_sock, client_sock), daemon=True).start()
            
        except Exception as e:
            self.send_error(502)
    
    def _forward(self, src, dst):
        try:
            while True:
                data = src.recv(8192)
                if not data:
                    break
                dst.send(data)
        except:
            pass
    
    def do_GET(self):
        self._handle()
    
    def do_POST(self):
        self._handle()
    
    def _check_backend_for_swipe(self):
        """Check if user has a swipe JWT configured"""
        try:
            headers = {'X-API-Key': API_KEY} if API_KEY else {}
            response = requests.get(f"{BACKEND_URL}/api/proxy/check", headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('has_swipe_jwt', False), data.get('swipe_jwt')
            return False, None
        except Exception as e:
            print(f"{Colors.RED}[!] Backend check failed: {e}{Colors.END}")
            return False, None
    
    def _report_captured_jwt(self, jwt_token, source, account_id=None, nickname=None, region=None, country=None):
        """Report captured JWT to backend"""
        try:
            headers = {'X-API-Key': API_KEY, 'Content-Type': 'application/json'} if API_KEY else {'Content-Type': 'application/json'}
            data = {
                'jwt_token': jwt_token,
                'source': source,
                'account_id': account_id,
                'nickname': nickname,
                'region': region,
                'country': country
            }
            response = requests.post(f"{BACKEND_URL}/api/proxy/capture", json=data, headers=headers, timeout=5)
            if response.status_code == 200:
                result = response.json()
                return result.get('should_swipe', False), result.get('swipe_jwt')
            return False, None
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to report JWT: {e}{Colors.END}")
            return False, None
    
    def _log_proxy_activity(self, method, url, action, details=None):
        """Log proxy activity to backend"""
        try:
            headers = {'X-API-Key': API_KEY, 'Content-Type': 'application/json'} if API_KEY else {'Content-Type': 'application/json'}
            data = {
                'method': method,
                'url': url,
                'action': action,
                'details': details
            }
            requests.post(f"{BACKEND_URL}/api/proxy/log", json=data, headers=headers, timeout=3)
        except:
            pass
    
    def _handle(self):
        try:
            parsed = urlparse(self.path)
            host = self.headers.get('Host', '')
            
            if self.path.startswith('http'):
                full_url = self.path
            else:
                full_url = f"https://{host}{self.path}"
            
            content_length = int(self.headers.get('Content-Length', 0))
            body = None
            if content_length > 0:
                body = self.rfile.read(content_length)
            
            print(f"{Colors.CYAN}─── {Colors.WHITE}{Colors.BOLD}{self.command}{Colors.END} {Colors.WHITE}{full_url[:100]}{Colors.END}")
            
            # ===== CAPTURE ACCESS TOKEN REQUEST =====
            if '/oauth/guest/token/grant' in full_url:
                print(f"\n{Colors.BLUE}{Colors.BOLD}✅ 𝐀𝐂𝐂𝐄𝐒𝐒 𝐓𝐎𝐊𝐄𝐍 𝐑𝐄𝐐𝐔𝐄𝐒𝐓 𝐃𝐄𝐓𝐄𝐂𝐓𝐄𝐃!{Colors.END}")
                if body:
                    try:
                        body_str = body.decode('utf-8')
                        params = parse_qs(body_str)
                        uid = params.get('uid', [''])[0]
                        print(f"{Colors.WHITE}{Colors.BOLD}   𝐔𝐈𝐃: {Colors.END}{Colors.GREEN}{uid}{Colors.END}")
                    except:
                        pass
            
            # Forward request
            response_data = self._forward_request(full_url, self.headers, body)
            
            # ===== CAPTURE ACCESS TOKEN FROM RESPONSE =====
            if '/oauth/guest/token/grant' in full_url and response_data:
                try:
                    resp_json = json.loads(response_data)
                    access_token = resp_json.get('access_token')
                    open_id = resp_json.get('open_id')
                    if access_token:
                        print(f"\n{Colors.BLUE}{Colors.BOLD}✅ 𝐀𝐂𝐂𝐄𝐒𝐒 𝐓𝐎𝐊𝐄𝐍 𝐂𝐀𝐏𝐓𝐔𝐑𝐄𝐃!{Colors.END}")
                        print(f"{Colors.WHITE}{Colors.BOLD}   𝐓𝐨𝐤𝐞𝐧: {Colors.END}{Colors.GREEN}{access_token[:50]}...{Colors.END}")
                        print(f"{Colors.WHITE}{Colors.BOLD}   𝐎𝐩𝐞𝐧 𝐈𝐃: {Colors.END}{Colors.GREEN}{open_id}{Colors.END}")
                        
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        with open(f"access_token_{timestamp}.txt", 'w') as f:
                            f.write(f"Access Token: {access_token}\n")
                            f.write(f"Open ID: {open_id}\n")
                            f.write(f"Time: {datetime.now().isoformat()}\n")
                        print(f"{Colors.GREEN}{Colors.BOLD}💾 𝐒𝐚𝐯𝐞𝐝: {Colors.END}{Colors.WHITE}access_token_{timestamp}.txt{Colors.END}")
                except Exception as e:
                    pass
            
            # ===== CAPTURE JWT FROM MAJORLOGIN RESPONSE =====
            if '/MajorLogin' in full_url and response_data:
                print(f"\n{Colors.PURPLE}{Colors.BOLD}📡 𝐌𝐀𝐉𝐎𝐑𝐋𝐎𝐆𝐈𝐍 𝐑𝐄𝐒𝐏𝐎𝐍𝐒𝐄 𝐑𝐄𝐂𝐄𝐈𝐕𝐄𝐃{Colors.END}")
                
                # Parse MajorLoginRes to extract JWT
                parsed = self._parse_majorlogin_response(response_data)
                if parsed and parsed.get('jwt'):
                    jwt = parsed['jwt']
                    account_uid = parsed.get('account_uid')
                    region = parsed.get('region')
                    url = parsed.get('url')
                    
                    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ 𝐉𝐖𝐓 𝐂𝐀𝐏𝐓𝐔𝐑𝐄𝐃! (𝐟𝐫𝐨𝐦 𝐌𝐚𝐣𝐨𝐫𝐋𝐨𝐠𝐢𝐧){Colors.END}")
                    print(f"{Colors.WHITE}{Colors.BOLD}   𝐉𝐖𝐓: {Colors.END}{Colors.GREEN}{jwt[:80]}...{Colors.END}")
                    if account_uid:
                        print(f"{Colors.WHITE}{Colors.BOLD}   𝐀𝐜𝐜𝐨𝐮𝐧𝐭 𝐔𝐈𝐃: {Colors.END}{Colors.GREEN}{account_uid}{Colors.END}")
                    if region:
                        print(f"{Colors.WHITE}{Colors.BOLD}   𝐑𝐞𝐠𝐢𝐨𝐧: {Colors.END}{Colors.GREEN}{region}{Colors.END}")
                    
                    # Report to backend and check for swipe
                    should_swipe, swipe_jwt = self._report_captured_jwt(
                        jwt, 'MajorLogin', account_uid, None, region, None
                    )
                    
                    # Save JWT
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    with open(f"jwt_{timestamp}.txt", 'w') as f:
                        f.write(f"JWT: {jwt}\n")
                        f.write(f"Account UID: {account_uid}\n")
                        f.write(f"Region: {region}\n")
                        f.write(f"Time: {datetime.now().isoformat()}\n")
                    print(f"{Colors.GREEN}{Colors.BOLD}💾 𝐒𝐚𝐯𝐞𝐝: {Colors.END}{Colors.WHITE}jwt_{timestamp}.txt{Colors.END}")
                    
                    # Decode and display JWT info
                    result, error = self._decode_jwt_data(jwt)
                    if result:
                        self._display_jwt_result(result)
                    
                    # If should swipe, replace the response
                    if should_swipe and swipe_jwt:
                        print(f"\n{Colors.YELLOW}{Colors.BOLD}🔄 𝐒𝐖𝐈𝐏𝐈𝐍𝐆 𝐉𝐖𝐓...{Colors.END}")
                        # Replace JWT in response
                        response_data = self._replace_jwt_in_response(response_data, jwt, swipe_jwt)
                        print(f"{Colors.GREEN}{Colors.BOLD}✅ 𝐉𝐖𝐓 𝐒𝐖𝐈𝐏𝐄𝐃 𝐒𝐔𝐂𝐂𝐄𝐒𝐒𝐅𝐔𝐋𝐋𝐘!{Colors.END}")
            
            # ===== CAPTURE JWT FROM AUTHORIZATION HEADER =====
            auth = self.headers.get('Authorization', '')
            if auth and auth.startswith('Bearer '):
                jwt = auth[7:]
                if len(jwt.split('.')) == 3:
                    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ 𝐉𝐖𝐓 𝐂𝐀𝐏𝐓𝐔𝐑𝐄𝐃! (𝐟𝐫𝐨𝐦 𝐀𝐮𝐭𝐡𝐨𝐫𝐢𝐳𝐚𝐭𝐢𝐨𝐧){Colors.END}")
                    print(f"{Colors.WHITE}{Colors.BOLD}   {Colors.END}{Colors.GREEN}{jwt[:80]}...{Colors.END}")
                    
                    # Report to backend
                    self._report_captured_jwt(jwt, 'Authorization Header')
                    
                    # Check if we should swipe
                    should_swipe, swipe_jwt = self._check_backend_for_swipe()
                    if should_swipe and swipe_jwt:
                        print(f"\n{Colors.YELLOW}{Colors.BOLD}🔄 𝐒𝐖𝐈𝐏𝐈𝐍𝐆 𝐉𝐖𝐓...{Colors.END}")
                        # Replace in headers
                        self.headers['Authorization'] = f'Bearer {swipe_jwt}'
                        print(f"{Colors.GREEN}{Colors.BOLD}✅ 𝐉𝐖𝐓 𝐒𝐖𝐈𝐏𝐄𝐃 𝐒𝐔𝐂𝐂𝐄𝐒𝐒𝐅𝐔𝐋𝐋𝐘!{Colors.END}")
            
            # ===== SHOW HEADERS =====
            print(f"{Colors.PURPLE}{Colors.BOLD}📋 𝐇𝐞𝐚𝐝𝐞𝐫𝐬:{Colors.END}")
            for key, value in self.headers.items():
                if key.lower() in ['authorization', 'cookie']:
                    print(f"   {Colors.WHITE}{Colors.BOLD}{key}:{Colors.END} {Colors.YELLOW}{value[:50]}...{Colors.END}")
                else:
                    print(f"   {Colors.WHITE}{Colors.BOLD}{key}:{Colors.END} {Colors.WHITE}{value}{Colors.END}")
            
            # Send response
            if response_data:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response_data)))
                self.end_headers()
                self.wfile.write(response_data)
            else:
                self.send_error(502)
            
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}[!] 𝐄𝐫𝐫𝐨𝐫: {Colors.END}{Colors.WHITE}{e}{Colors.END}")
            self.send_error(500)
    
    def _forward_request(self, url, headers, body):
        try:
            headers_dict = {}
            for k, v in headers.items():
                k_lower = k.lower()
                if k_lower not in ['host', 'content-length', 'connection', 'proxy-connection']:
                    headers_dict[k] = v
            
            headers_dict['User-Agent'] = 'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36'
            
            response = requests.request(
                method=self.command,
                url=url,
                headers=headers_dict,
                data=body,
                verify=False,
                timeout=30,
                allow_redirects=True
            )
            return response.content
        except Exception as e:
            print(f"{Colors.RED}{Colors.BOLD}[!] 𝐅𝐨𝐫𝐰𝐚𝐫𝐝 𝐞𝐫𝐫𝐨𝐫: {Colors.END}{Colors.WHITE}{e}{Colors.END}")
            return None
    
    def _parse_majorlogin_response(self, data):
        """Parse MajorLoginRes protobuf to extract JWT"""
        try:
            result = {}
            pos = 0
            data_len = len(data)
            
            while pos < data_len:
                if pos >= data_len:
                    break
                
                tag = data[pos]
                field_num = tag >> 3
                wire_type = tag & 0x07
                pos += 1
                
                if wire_type == 0:
                    value = 0
                    shift = 0
                    while pos < data_len:
                        byte = data[pos]
                        value |= (byte & 0x7F) << shift
                        pos += 1
                        shift += 7
                        if not (byte & 0x80):
                            break
                    result[field_num] = value
                    
                elif wire_type == 2:
                    length = 0
                    shift = 0
                    while pos < data_len:
                        byte = data[pos]
                        length |= (byte & 0x7F) << shift
                        pos += 1
                        shift += 7
                        if not (byte & 0x80):
                            break
                    
                    if pos + length <= data_len:
                        value = data[pos:pos + length]
                        pos += length
                        
                        if field_num == 8:
                            try:
                                result['jwt'] = value.decode('utf-8')
                            except:
                                result['jwt'] = value.hex()
                        elif field_num == 2:
                            try:
                                result['region'] = value.decode('utf-8')
                            except:
                                pass
                        elif field_num == 10:
                            try:
                                result['url'] = value.decode('utf-8')
                            except:
                                pass
                        else:
                            try:
                                result[field_num] = value.decode('utf-8')
                            except:
                                result[field_num] = value.hex()
            
            if 'jwt' not in result and 8 in result:
                result['jwt'] = result[8]
            if 1 in result:
                result['account_uid'] = result[1]
            
            # Fallback: search for JWT pattern
            if not result.get('jwt'):
                jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
                match = re.search(jwt_pattern, data.decode('utf-8', errors='ignore'))
                if match:
                    result['jwt'] = match.group()
            
            return result if result.get('jwt') else None
        except Exception as e:
            return None
    
    def _replace_jwt_in_response(self, response_data, old_jwt, new_jwt):
        """Replace JWT in response data"""
        try:
            # Try to replace in protobuf response
            response_str = response_data.decode('utf-8', errors='ignore')
            if old_jwt in response_str:
                response_str = response_str.replace(old_jwt, new_jwt)
                return response_str.encode('utf-8')
            return response_data
        except:
            return response_data
    
    def _decode_jwt_data(self, jwt):
        """Decode JWT data"""
        try:
            parts = jwt.split('.')
            if len(parts) != 3:
                return None, "Invalid JWT format"
            
            payload = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            data = json.loads(payload)
            
            nickname_encrypted = data.get('nickname')
            nickname_decrypted = None
            if nickname_encrypted:
                try:
                    xor_key = "1e5898ccb8dfdd921f9bdea848768b64a20"
                    encrypted = base64.b64decode(nickname_encrypted)
                    key_bytes = xor_key.encode('ascii')
                    decrypted = bytes([encrypted[i] ^ key_bytes[i % len(key_bytes)] 
                                      for i in range(len(encrypted))])
                    nickname_decrypted = decrypted.decode('utf-8')
                except:
                    pass
            
            expiry_readable = None
            if data.get('exp'):
                try:
                    expiry_readable = datetime.fromtimestamp(data['exp']).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    expiry_readable = str(data['exp'])
            
            return {
                'raw_data': data,
                'account_id': data.get('account_id'),
                'nickname_encrypted': nickname_encrypted,
                'nickname_decrypted': nickname_decrypted,
                'region': data.get('noti_region'),
                'country': data.get('country_code'),
                'client_version': data.get('client_version'),
                'release_version': data.get('release_version'),
                'expiry_readable': expiry_readable
            }, None
            
        except Exception as e:
            return None, str(e)
    
    def _display_jwt_result(self, result):
        if not result:
            return
        
        print(f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗
║{Colors.WHITE}{Colors.BOLD}                    𝐀𝐂𝐂𝐎𝐔𝐍𝐓 𝐃𝐄𝐓𝐀𝐈𝐋𝐒                         {Colors.CYAN}║
╚══════════════════════════════════════════════════════════════════╝{Colors.END}
""")
        
        fields = [
            ('account_id', '𝐀𝐜𝐜𝐨𝐮𝐧𝐭 𝐈𝐃'),
            ('nickname_decrypted', '𝐍𝐢𝐜𝐤𝐧𝐚𝐦𝐞'),
            ('region', '𝐑𝐞𝐠𝐢𝐨𝐧'),
            ('country', '𝐂𝐨𝐮𝐧𝐭𝐫𝐲'),
            ('client_version', '𝐂𝐥𝐢𝐞𝐧𝐭 𝐕𝐞𝐫𝐬𝐢𝐨𝐧'),
            ('release_version', '𝐑𝐞𝐥𝐞𝐚𝐬𝐞 𝐕𝐞𝐫𝐬𝐢𝐨𝐧'),
            ('expiry_readable', '𝐄𝐱𝐩𝐢𝐫𝐞𝐬')
        ]
        
        for key, label in fields:
            value = result.get(key)
            if value:
                print(f"{Colors.WHITE}{Colors.BOLD}   {label}:{Colors.END} {Colors.GREEN}{value}{Colors.END}")

# =============================================================================
# START PROXY
# =============================================================================

def start_proxy():
    print(f"""
{Colors.GREEN}{Colors.BOLD}🚀 𝐏𝐫𝐨𝐱𝐲 𝐬𝐭𝐚𝐫𝐭𝐞𝐝 𝐨𝐧 127.0.0.1:8080{Colors.END}
{Colors.CYAN}{Colors.BOLD}   🔄 𝐅𝐨𝐫𝐰𝐚𝐫𝐝𝐢𝐧𝐠 𝐭𝐨: {Colors.END}{Colors.WHITE}https://clientbp.ggpolarbear.com{Colors.END}
{Colors.YELLOW}{Colors.BOLD}   𝐒𝐞𝐭 𝐀𝐧𝐝𝐫𝐨𝐢𝐝 𝐩𝐫𝐨𝐱𝐲 𝐭𝐨: 127.0.0.1:8080{Colors.END}
{Colors.PURPLE}{Colors.BOLD}   🎯 𝐂𝐚𝐩𝐭𝐮𝐫𝐢𝐧𝐠: 𝐀𝐜𝐜𝐞𝐬𝐬 𝐓𝐨𝐤𝐞𝐧 → 𝐌𝐚𝐣𝐨𝐫𝐋𝐨𝐠𝐢𝐧 → 𝐉𝐖𝐓 → 𝐆𝐞𝐭𝐋𝐨𝐠𝐢𝐧𝐃𝐚𝐭𝐚{Colors.END}
{Colors.RED}{Colors.BOLD}   𝐏𝐫𝐞𝐬𝐬 Ctrl+C 𝐭𝐨 𝐬𝐭𝐨𝐩{Colors.END}\n
""")
    
    try:
        server = HTTPServer(('127.0.0.1', 8080), ProxyHandler)
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}{Colors.BOLD}👋 𝐒𝐭𝐨𝐩𝐩𝐢𝐧𝐠...{Colors.END}")

def main():
    global API_KEY
    print(f"""
{Colors.CYAN}{Colors.BOLD}┌─────────────────────────────────────────────────────────────┐
│{Colors.WHITE}{Colors.BOLD}                    𝐏𝐑𝐎𝐗𝐘 𝐒𝐄𝐓𝐔𝐏                           {Colors.CYAN}│
├─────────────────────────────────────────────────────────────┤
│  {Colors.WHITE}{Colors.BOLD}Enter your API key from the dashboard:{Colors.END}               │
└─────────────────────────────────────────────────────────────┘{Colors.END}
""")
    
    API_KEY = input(f"{Colors.GREEN}{Colors.BOLD}🔑 API Key: {Colors.END}").strip()
    
    if not API_KEY:
        print(f"{Colors.RED}{Colors.BOLD}❌ API key required!{Colors.END}")
        return
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ API key set!{Colors.END}")
    start_proxy()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}{Colors.BOLD}👋 𝐄𝐱𝐢𝐭𝐢𝐧𝐠...{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}[!] 𝐄𝐫𝐫𝐨𝐫: {Colors.END}{Colors.WHITE}{e}{Colors.END}")