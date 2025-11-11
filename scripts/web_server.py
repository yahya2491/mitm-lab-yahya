#!/usr/bin/env python3

import argparse
import http.server
import socketserver
import os
import sys
from datetime import datetime

class LoggingHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        message = format % args
        log_entry = f"[{timestamp}] {client_ip} - {message}"
        print(log_entry)
        
        with open('/home/yahya/mitm-lab-yahya/evidence/web_server.log', 'a') as f:
            f.write(log_entry + '\n')
    
    def do_GET(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        user_agent = self.headers.get('User-Agent', 'Unknown')
        
        log_entry = f"[{timestamp}] GET {self.path} from {client_ip} - User-Agent: {user_agent}"
        print(log_entry)
        
        with open('/home/yahya/mitm-lab-yahya/evidence/web_server.log', 'a') as f:
            f.write(log_entry + '\n')
        
        super().do_GET()
    
    def do_HEAD(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_ip = self.client_address[0]
        
        log_entry = f"[{timestamp}] HEAD {self.path} from {client_ip}"
        print(log_entry)
        
        with open('/home/yahya/mitm-lab-yahya/evidence/web_server.log', 'a') as f:
            f.write(log_entry + '\n')
        
        super().do_HEAD()

def main():
    parser = argparse.ArgumentParser(description="Simple HTTP server for DNS spoofing demo")
    parser.add_argument('--host', default='10.0.0.5', help='IP address to bind to')
    parser.add_argument('--port', type=int, default=80, help='Port to listen on')
    parser.add_argument('--directory', default='/home/yahya/mitm-lab-yahya/www', 
                       help='Directory to serve files from')
    args = parser.parse_args()
    
    if args.directory:
        try:
            os.chdir(args.directory)
            print(f"Serving files from: {os.getcwd()}")
        except FileNotFoundError:
            print(f"Error: Directory {args.directory} not found")
            sys.exit(1)
    
    os.makedirs('/home/yahya/mitm-lab-yahya/evidence', exist_ok=True)
    
    try:
        with socketserver.TCPServer((args.host, args.port), LoggingHTTPRequestHandler) as httpd:
            print(f"Starting HTTP server on {args.host}:{args.port}")
            print(f"Logs will be written to /home/yahya/mitm-lab-yahya/evidence/web_server.log")
            print("Press Ctrl+C to stop the server")
            httpd.serve_forever()
    except PermissionError:
        print(f"Error: Permission denied to bind to {args.host}:{args.port}")
        print("Try running with sudo if binding to port 80, or use a different port (e.g., 8080)")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()