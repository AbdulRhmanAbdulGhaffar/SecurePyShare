import http.server
import http.cookies
import socketserver
import socket
import ssl
import threading
import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import webbrowser
from urllib.parse import quote, unquote, parse_qs
import subprocess
import re
import html
import io
import sys
import mimetypes
import time
import random
import shutil
import datetime
import json  # Added for delete functionality

# --- Global Config ---
APP_INSTANCE = None
SERVER_CONTEXT = {
    "auth_enabled": False,
    "upload_enabled": False,
    "username": "",
    "password": "",
    "sessions": set(),
    "root_dir": os.getcwd()
}

# --- High Performance Server ---
class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

# --- Network Tools ---
def get_ip_map():
    ip_map = {}
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, startupinfo=startupinfo)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line: continue
            if line.endswith(':'):
                name = line[:-1].replace("Ethernet adapter ", "").replace("Wireless LAN adapter ", "")
                current_adapter = name
            if "IPv4 Address" in line and current_adapter:
                match = re.search(r':\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if match: ip_map[match.group(1)] = current_adapter
    except: pass
    return ip_map

def format_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024: return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

# --- Enterprise Request Handler ---
def create_auth_handler(served_filename=None):
    class EnterpriseHandler(http.server.SimpleHTTPRequestHandler):
        target_file = served_filename

        def log_message(self, format, *args):
            if "Broken pipe" in str(args) or "Connection reset" in str(args): return
            msg = f"[{self.log_date_time_string()}] {self.client_address[0]} : {format % args}\n"
            if APP_INSTANCE: APP_INSTANCE.log_to_gui(msg)

        def check_auth(self):
            if not SERVER_CONTEXT["auth_enabled"]: return True
            if "Cookie" in self.headers:
                c = http.cookies.SimpleCookie(self.headers["Cookie"])
                if "auth_token" in c and c["auth_token"].value in SERVER_CONTEXT["sessions"]:
                    return True
            return False

        def do_POST(self):
            # 1. Login Logic
            if self.path == '/login':
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8')
                params = parse_qs(body)
                u = params.get('username', [''])[0].strip()
                p = params.get('password', [''])[0].strip()
                
                if u == SERVER_CONTEXT["username"] and p == SERVER_CONTEXT["password"]:
                    token = str(random.getrandbits(128))
                    SERVER_CONTEXT["sessions"].add(token)
                    self.send_response(303)
                    self.send_header('Set-Cookie', f'auth_token={token}; Path=/; HttpOnly')
                    self.send_header('Location', '/')
                    self.end_headers()
                else:
                    self.send_login_page(error="Access Denied: Invalid Credentials")
                return

            # 2. Upload Logic
            if self.path == '/upload':
                if not self.check_auth(): return self.send_login_page()
                if not SERVER_CONTEXT["upload_enabled"]:
                    self.send_error(403, "Uploads Disabled")
                    return
                try:
                    content_type = self.headers.get('Content-Type', '')
                    if 'multipart/form-data' not in content_type:
                        self.send_error(400, "Bad Request")
                        return
                    
                    boundary = content_type.split("boundary=")[1].encode()
                    content_length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(content_length)
                    parts = body.split(boundary)
                    
                    # Determine path (Root for simplicity/security in this context)
                    upload_dir = SERVER_CONTEXT["root_dir"]

                    for part in parts:
                        if b'filename="' in part:
                            if b'\r\n\r\n' in part:
                                headers_part, file_data = part.split(b'\r\n\r\n', 1)
                                file_data = file_data.rstrip(b'\r\n--')
                                headers = headers_part.decode()
                                filename_match = re.search(r'filename="([^"]+)"', headers)
                                
                                if filename_match:
                                    filename = filename_match.group(1)
                                    safe_name = os.path.basename(filename)
                                    save_path = os.path.join(upload_dir, safe_name)
                                    with open(save_path, 'wb') as f:
                                        f.write(file_data)
                                    APP_INSTANCE.log_to_gui(f"[*] Uploaded: {safe_name}\n")
                    
                    self.send_response(200)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"OK") # Response handled by JS
                    return
                except Exception as e:
                    APP_INSTANCE.log_to_gui(f"[!] Upload Error: {e}\n")
                    self.send_error(500, "Upload Failed")
                    return

            # 3. Delete Logic (NEW)
            if self.path == '/delete':
                if not self.check_auth(): 
                    self.send_error(401)
                    return
                if not SERVER_CONTEXT["upload_enabled"]: # Use same perm for delete
                    self.send_error(403, "Delete Disabled")
                    return
                
                try:
                    length = int(self.headers.get('Content-Length', 0))
                    body = self.rfile.read(length).decode('utf-8')
                    data = json.loads(body)
                    filename = os.path.basename(data.get('filename'))
                    target_path = os.path.join(SERVER_CONTEXT["root_dir"], filename)
                    
                    if os.path.exists(target_path):
                        if os.path.isdir(target_path):
                            shutil.rmtree(target_path)
                        else:
                            os.remove(target_path)
                        APP_INSTANCE.log_to_gui(f"[*] Deleted: {filename}\n")
                        self.send_response(200)
                        self.end_headers()
                        self.wfile.write(b'{"status":"success"}')
                    else:
                        self.send_error(404)
                except Exception as e:
                    self.send_error(500, str(e))
                return

            return super().do_POST()

        def do_GET(self):
            if self.path == '/logout':
                self.send_response(303)
                self.send_header('Set-Cookie', 'auth_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
                self.send_header('Location', '/')
                self.end_headers()
                return

            if not self.check_auth():
                self.send_login_page()
                return

            try:
                # SINGLE FILE LOGIC FIX
                if self.target_file:
                    req_path_unquoted = unquote(self.path.lstrip('/'))
                    
                    if self.path == '/' or self.path == '/index.html':
                        self.send_single_file_page()
                        return
                    
                    if req_path_unquoted == self.target_file:
                        return super().do_GET()
                    elif "favicon.ico" in req_path_unquoted:
                         self.send_error(404)
                         return
                    else:
                        self.send_error(403, "Access Denied")
                        return
                        
                return super().do_GET()
            except: pass

        def get_common_assets(self):
            # Optimized SVGs
            ic_li = '<svg width="20" height="20" fill="#0077b5" viewBox="0 0 24 24"><path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z"/></svg>'
            ic_gh = '<svg width="20" height="20" fill="#333" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>'
            ic_em = '<svg width="20" height="20" fill="#ea4335" viewBox="0 0 24 24"><path d="M0 3v18h24v-18h-24zm21.518 2l-9.518 7.713-9.518-7.713h19.036zm-19.518 14v-11.817l10 8.104 10-8.104v11.817h-20z"/></svg>'
            
            css = """
            <style>
                @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap');
                :root { --primary:#4f46e5; --bg:#f8fafc; --surface:#ffffff; --text:#0f172a; --border:#e2e8f0; --danger:#ef4444; }
                * { box-sizing: border-box; }
                body { font-family: 'Plus Jakarta Sans', sans-serif; background: var(--bg); color: var(--text); margin: 0; min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
                
                /* Animations */
                @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
                @keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }
                @keyframes gradientBG { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }

                /* Animated Background */
                .animated-bg {
                    background: linear-gradient(-45deg, #ee7752, #e73c7e, #23a6d5, #23d5ab);
                    background-size: 400% 400%;
                    animation: gradientBG 15s ease infinite;
                    position: absolute;
                    top: 0; left: 0; width: 100%; height: 100%;
                    z-index: -1;
                }

                /* Toast Notification */
                .toast { position: fixed; bottom: 20px; right: 20px; background: #10b981; color: white; padding: 12px 24px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); transform: translateY(100px); transition: 0.3s; z-index: 1000; font-weight: 600; }
                .toast.show { transform: translateY(0); }
                .toast.error { background: #ef4444; }

                nav { background: rgba(255,255,255,0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); padding: 0.8rem 5%; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 50; animation: fadeIn 0.5s ease-out; }
                .brand { font-weight: 800; color: var(--primary); font-size: 1.3rem; letter-spacing: -0.5px; display: flex; align-items: center; gap: 8px; }
                .logout-btn { color: #ef4444; background: #fef2f2; padding: 0.5rem 1rem; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 0.875rem; transition:0.2s; border: 1px solid transparent; }
                .logout-btn:hover { border-color: #fecaca; background: #fee2e2; }

                main { max-width: 1200px; margin: 0 auto; padding: 2rem 5%; width: 100%; flex: 1; animation: fadeIn 0.8s ease-out; }
                
                .banner { background: linear-gradient(135deg, rgba(79, 70, 229, 0.9), rgba(59, 130, 246, 0.9)); border-radius: 20px; padding: 3rem; color: white; margin-bottom: 2.5rem; text-align: center; box-shadow: 0 20px 25px -5px rgba(79, 70, 229, 0.3); backdrop-filter: blur(5px); }
                .banner h1 { margin: 0 0 0.5rem 0; font-size: 2rem; font-weight: 800; text-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .banner p { margin: 0; opacity: 0.95; font-size: 1.1rem; }

                .toolbar { display: flex; gap: 1rem; margin-bottom: 1.5rem; align-items: center; flex-wrap: wrap; background: rgba(255,255,255,0.9); padding: 1rem; border-radius: 12px; border: 1px solid var(--border); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); backdrop-filter: blur(10px); }
                .path-display { font-family: monospace; color: #64748b; font-weight: 600; flex-grow: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
                .search-input { padding: 0.7rem 1rem; border: 1px solid var(--border); border-radius: 10px; width: 250px; transition: 0.2s; background: #f8fafc; }
                .search-input:focus { border-color: var(--primary); background: white; box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1); }

                .upload-zone { border: 2px dashed #cbd5e1; border-radius: 16px; padding: 2.5rem; text-align: center; cursor: pointer; transition: 0.3s; margin-bottom: 2.5rem; background: rgba(255,255,255,0.6); position: relative; overflow: hidden; }
                .upload-zone:hover { border-color: var(--primary); background: #eff6ff; transform: scale(1.01); }
                .upload-icon { font-size: 2.5rem; margin-bottom: 0.5rem; display: block; animation: float 3s ease-in-out infinite; }
                .progress-bar { height: 4px; background: #e2e8f0; width: 100%; position: absolute; bottom: 0; left: 0; display: none; }
                .progress-fill { height: 100%; background: #10b981; width: 0%; transition: width 0.2s; }

                .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 1.5rem; }
                .card { background: rgba(255,255,255,0.9); border: 1px solid var(--border); border-radius: 16px; padding: 1.5rem; transition: 0.3s; display: flex; flex-direction: column; position: relative; opacity: 0; animation: fadeIn 0.5s ease-out forwards; backdrop-filter: blur(5px); }
                .card:hover { transform: translateY(-5px); box-shadow: 0 15px 30px -10px rgba(0,0,0,0.1); border-color: #bfdbfe; }
                
                .card-header { display: flex; align-items: flex-start; gap: 1rem; margin-bottom: 1rem; }
                .file-icon { font-size: 2.5rem; transition: 0.3s; }
                .card:hover .file-icon { transform: scale(1.1); }
                .file-info { min-width: 0; flex: 1; }
                .file-name { font-weight: 700; color: var(--text); font-size: 1rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 0.2rem; }
                .file-meta { font-size: 0.8rem; color: #94a3b8; }
                
                .card-actions { margin-top: auto; display: flex; gap: 8px; }
                .btn { padding: 8px 12px; border-radius: 8px; text-decoration: none; font-size: 0.85rem; font-weight: 600; text-align: center; transition: 0.2s; cursor: pointer; flex: 1; border: none; }
                .btn-preview { background: #f1f5f9; color: var(--primary); } .btn-preview:hover { background: #e2e8f0; }
                .btn-download { background: #ecfdf5; color: #059669; } .btn-download:hover { background: #d1fae5; }
                .btn-delete { background: #fef2f2; color: #ef4444; flex: 0; padding: 8px 12px; } .btn-delete:hover { background: #fee2e2; transform: scale(1.05); }
                .btn-open { background: #fff7ed; color: #ea580c; width: 100%; }

                footer { text-align: center; padding: 3rem 0; border-top: 1px solid var(--border); background: white; margin-top: auto; position: relative; z-index: 10; }
                .footer-links { display: flex; justify-content: center; gap: 1.5rem; margin-top: 1.5rem; }
                .footer-links a { color: #64748b; text-decoration: none; font-weight: 500; display: flex; align-items: center; gap: 6px; transition: 0.2s; }
                .footer-links a:hover { color: var(--primary); transform: translateY(-2px); }
                
                @media (max-width: 640px) { .search-input { width: 100%; order: 3; } .toolbar { gap: 0.5rem; } .banner { padding: 2rem 1.5rem; } }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
            """
            return css, ic_li, ic_gh, ic_em

        def send_login_page(self, error=""):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            css, li, gh, em = self.get_common_assets()
            
            html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title>{css}
            <style>
                body {{ justify-content: center; align-items: center; padding: 20px; height: 100vh; overflow: hidden; }}
                .login-box {{ background: rgba(255,255,255,0.85); backdrop-filter: blur(15px); padding: 3rem; border-radius: 24px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.15); width: 100%; max-width: 400px; text-align: center; border: 1px solid rgba(255,255,255,0.5); animation: fadeIn 0.8s cubic-bezier(0.2, 0.8, 0.2, 1); position: relative; z-index: 10; }}
                .inp {{ width: 100%; padding: 1rem; border: 2px solid #e2e8f0; border-radius: 12px; margin-bottom: 1rem; font-size: 1rem; transition: 0.2s; background: rgba(255,255,255,0.8); }}
                .inp:focus {{ border-color: var(--primary); background: white; box-shadow: 0 0 0 4px rgba(79, 70, 229, 0.1); transform: scale(1.01); }}
                .btn-login {{ width: 100%; padding: 1rem; background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%); color: white; border: none; border-radius: 12px; font-weight: 700; font-size: 1rem; cursor: pointer; transition: 0.3s; box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.3); }}
                .btn-login:hover {{ transform: translateY(-2px); box-shadow: 0 20px 25px -5px rgba(79, 70, 229, 0.4); }}
            </style></head><body>
            <div class="animated-bg"></div>
            <div class="login-box">
                <div style="font-size:4rem;margin-bottom:1rem;animation:float 3s ease-in-out infinite">🔐</div>
                <h1 style="color:var(--text);margin:0 0 0.5rem;font-size:1.8rem;font-weight:800">Secure Access</h1>
                <p style="color:#64748b;margin-bottom:2rem;line-height:1.6">Welcome to AbdulRhman's V3.0 Portal<br>Please authenticate to continue.</p>
                {f'<div style="background:#fef2f2;color:#ef4444;padding:0.8rem;border-radius:8px;margin-bottom:1.5rem;font-size:0.9rem;border:1px solid #fee2e2;font-weight:600;animation:fadeIn 0.3s">⚠️ {error}</div>' if error else ''}
                <form method="POST" action="/login">
                    <input type="text" name="username" class="inp" placeholder="Username" required autofocus>
                    <input type="password" name="password" class="inp" placeholder="Password" required>
                    <button type="submit" class="btn-login">Unlock Workspace</button>
                </form>
                <div style="margin-top:2.5rem;border-top:1px solid #e2e8f0;padding-top:1.5rem;font-size:0.85rem;color:#64748b;font-weight:500">
                    Connect with Developer
                    <div class="footer-links" style="margin-top:0.75rem">
                        <a href="https://www.linkedin.com/in/abdulrhmanabdulghaffar/" target="_blank">{li}</a>
                        <a href="https://github.com/AbdulRhmanAbdulGhaffar" target="_blank">{gh}</a>
                        <a href="mailto:abdulrhman.abdulghaffar001@gmail.com">{em}</a>
                    </div>
                </div>
            </div></body></html>"""
            self.wfile.write(html.encode('utf-8'))

        def guess_icon(self, path, is_dir):
            if is_dir: return "📁", "#f59e0b"
            ext = os.path.splitext(path)[1].lower()
            if ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp']: return "🖼️", "#ec4899"
            if ext in ['.mp4', '.mkv', '.avi', '.mov']: return "🎥", "#8b5cf6"
            if ext in ['.mp3', '.wav']: return "🎵", "#10b981"
            if ext in ['.pdf']: return "📕", "#ef4444"
            if ext in ['.zip', '.rar']: return "📦", "#f97316"
            return "📄", "#94a3b8"

        def list_directory(self, path):
            try: list_dir = os.listdir(path)
            except: self.send_error(404); return None
            list_dir.sort(key=lambda a: (not os.path.isdir(os.path.join(path, a)), a.lower()))
            display_path = html.escape(unquote(self.path))
            f = io.BytesIO()
            css, li, gh, em = self.get_common_assets()
            
            upload_html = ""
            if SERVER_CONTEXT["upload_enabled"]:
                upload_html = """
                <div class="upload-zone" onclick="document.getElementById('file-input').click()">
                    <div class="upload-icon">☁️</div>
                    <div class="up-text" style="color:#64748b;font-weight:500"><strong>Click to Upload</strong> or Drag & Drop here</div>
                    <div class="progress-bar"><div class="progress-fill"></div></div>
                    <input id="file-input" type="file" onchange="uploadFile(this)" style="display:none">
                </div>
                """

            f.write(f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>AbdulRhman Cloud V3.0</title>{css}
            <script>
                function showToast(msg, isError=false) {{
                    const t = document.getElementById('toast');
                    t.innerText = msg;
                    t.className = isError ? 'toast show error' : 'toast show';
                    setTimeout(() => {{ t.className = t.className.replace('show', ''); }}, 3000);
                }}
                function filter() {{ let val = document.getElementById('search').value.toLowerCase(); document.querySelectorAll('.card').forEach(el => {{ el.style.display = el.getAttribute('data-name').includes(val) ? 'flex' : 'none'; }}); }}
                
                function uploadFile(input) {{ 
                    if(input.files.length > 0) {{ 
                        let fd = new FormData(); fd.append("file", input.files[0]); 
                        let xhr = new XMLHttpRequest(); 
                        xhr.open("POST", "/upload", true); 
                        xhr.upload.onprogress = function(e) {{ if (e.lengthComputable) {{ let pct = (e.loaded / e.total) * 100; document.querySelector('.progress-bar').style.display = 'block'; document.querySelector('.progress-fill').style.width = pct + '%'; }} }};
                        xhr.onload = function() {{ 
                            if(xhr.status == 200) {{ 
                                Swal.fire({{ title: 'Success!', text: 'File Uploaded Successfully', icon: 'success', confirmButtonColor: '#4f46e5' }}).then(() => window.location.reload());
                            }} else {{ Swal.fire('Error', 'Upload Failed', 'error'); }}
                        }}; 
                        xhr.send(fd); 
                    }} 
                }}
                
                function deleteFile(name) {{
                    Swal.fire({{
                        title: 'Are you sure?', text: "You won't be able to revert this!", icon: 'warning',
                        showCancelButton: true, confirmButtonColor: '#ef4444', cancelButtonColor: '#cbd5e1', confirmButtonText: 'Yes, delete it!'
                    }}).then((result) => {{
                        if (result.isConfirmed) {{
                            fetch('/delete', {{
                                method: 'POST', headers: {{'Content-Type': 'application/json'}},
                                body: JSON.stringify({{filename: name}})
                            }}).then(r => {{
                                if(r.ok) {{ Swal.fire('Deleted!', 'File has been deleted.', 'success').then(() => window.location.reload()); }}
                                else {{ Swal.fire('Error', 'Could not delete file.', 'error'); }}
                            }});
                        }}
                    }})
                }}
            </script>
            </head><body>
            <div class="animated-bg"></div>
            <div id="toast" class="toast"></div>
            <nav><div class="brand"><span>💎</span> SecurePyShare V3.0 </div><a href="/logout" class="logout-btn">Sign Out</a></nav>
            <main>
                <div class="banner"><h1>Welcome to SecurePyShareWorkspace 🚀</h1><p>Managed by AbdulRhman AbdulGhaffar • Complete Control</p></div>
                <div class="toolbar">
                    {f'<a href="../" style="text-decoration:none;background:white;padding:0.7rem;border-radius:10px;border:1px solid #e2e8f0;font-size:1.2rem;display:flex;align-items:center">⬅️</a>' if self.path != '/' else ''}
                    <div class="path-display">{display_path}</div>
                    <input id="search" class="search-input" onkeyup="filter()" placeholder="Search files...">
                </div>
                {upload_html}
                <div class="grid">
            """.encode('utf-8'))

            # Staggered animation index
            anim_delay = 0
            for name in list_dir:
                if name.startswith('.'): continue
                fullname = os.path.join(path, name)
                is_dir = os.path.isdir(fullname)
                link = quote(name) + ("/" if is_dir else "")
                icon, color = self.guess_icon(fullname, is_dir)
                try:
                    stat = os.stat(fullname)
                    meta = "-" if is_dir else f"{format_size(stat.st_size)} • {datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d')}"
                except: meta = ""

                del_btn = ""
                if SERVER_CONTEXT["upload_enabled"]: # Show delete if upload (modify) is enabled
                     del_btn = f'<button onclick="deleteFile(\'{name}\')" class="btn btn-delete" title="Delete">🗑️</button>'

                if is_dir:
                    btns = f'<a href="{link}" class="btn btn-open">Open Folder</a>'
                else:
                    btns = f'<a href="{link}" target="_blank" class="btn btn-preview">Preview</a> <a href="{link}" download class="btn btn-download">Download</a>'

                f.write(f"""
                <div class="card" style="animation-delay: {anim_delay}s" data-name="{html.escape(name.lower())}">
                    <div class="card-header">
                        <div class="file-icon" style="color:{color}">{icon}</div>
                        <div class="file-info">
                            <div class="file-name" title="{html.escape(name)}">{html.escape(name)}</div>
                            <div class="file-meta">{meta}</div>
                        </div>
                    </div>
                    <div class="card-actions">{btns} {del_btn}</div>
                </div>
                """.encode('utf-8'))
                anim_delay += 0.05 # Increment delay for staggered effect

            f.write(f"""</div>
            <footer>
                <div style="font-weight:700;color:#0f172a;margin-bottom:5px;font-size:1.1rem">SecurePyShare V 3.0 </div>
                <div class="copyright">Designed with ❤️ by AbdulRhman AbdulGhaffar</div>
                <div class="footer-links">
                    <a href="https://www.linkedin.com/in/abdulrhmanabdulghaffar/" target="_blank">{li} LinkedIn</a>
                    <a href="https://github.com/AbdulRhmanAbdulGhaffar" target="_blank">{gh} GitHub</a>
                    <a href="mailto:abdulrhman.abdulghaffar001@gmail.com">{em} Email</a>
                </div>
            </footer>
            </main></body></html>""".encode('utf-8'))
            
            f.seek(0)
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(f.getbuffer().nbytes))
            self.end_headers()
            return f

        def send_single_file_page(self):
            encoded_name = quote(self.target_file)
            icon, color = self.guess_icon(self.target_file, False)
            try: size = format_size(os.stat(self.target_file).st_size)
            except: size = "Unknown"
            css, li, gh, em = self.get_common_assets()

            html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Download</title>{css}
            <style>body{{display:flex;align-items:center;justify-content:center;flex-direction:column;background:radial-gradient(#e2e8f0 1px, transparent 1px);background-size:20px 20px}} .card{{background:white;padding:3rem;border-radius:24px;text-align:center;box-shadow:0 10px 40px -10px rgba(0,0,0,0.1);max-width:420px;width:90%;border:1px solid #ffffff;animation:fadeIn 0.5s ease-out}} .btn-dl{{display:block;width:100%;margin-top:1.5rem;padding:1rem;background:linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%);color:white}} .btn-prev{{display:block;width:100%;margin-top:0.5rem;background:transparent;color:#64748b;font-weight:500;border:none;cursor:pointer}} .btn-prev:hover{{color:var(--primary)}} .logout-link{{position:absolute;top:1.5rem;right:1.5rem;color:#ef4444;text-decoration:none;font-weight:600;font-size:0.9rem}}</style></head><body>
            <div class="card">
                <a href="/logout" class="logout-link">Logout</a>
                <div style="font-size:5rem;margin-bottom:1.5rem;color:{color};animation:float 3s ease-in-out infinite">{icon}</div>
                <h2 style="color:#0f172a;margin:0 0 0.5rem 0;font-size:1.5rem;word-break:break-all">{self.target_file}</h2>
                <div style="color:#64748b;font-size:0.9rem;background:#f1f5f9;padding:6px 12px;border-radius:20px;display:inline-block">{size}</div>
                <a href="{encoded_name}" download class="btn btn-download btn-dl">⬇️ Download File</a>
                <a href="{encoded_name}" target="_blank" class="btn btn-prev">👁️ Preview Content</a>
            </div>
            <div class="footer-links" style="margin-top:2rem;opacity:0.8">
                <a href="https://www.linkedin.com/in/abdulrhmanabdulghaffar/" target="_blank">{li}</a>
                <a href="https://github.com/AbdulRhmanAbdulGhaffar" target="_blank">{gh}</a>
                <a href="mailto:abdulrhman.abdulghaffar001@gmail.com">{em}</a>
            </div>
            <div class="copyright" style="margin-top:1rem">Designed with ❤️ by AbdulRhman AbdulGhaffar</div>
            </body></html>"""
            self.wfile.write(html.encode('utf-8'))

    return EnterpriseHandler

# --- Desktop Application ---
class FileShareApp:
    def __init__(self, root):
        global APP_INSTANCE
        APP_INSTANCE = self
        self.root = root
        self.root.title("SafeShare Pro V3.0 🛡️")
        self.root.geometry("600x800")
        self.root.configure(bg="#ffffff")
        self.server = None
        self.is_running = False
        style = ttk.Style()
        style.theme_use('clam')
        self.create_ui()

    def create_ui(self):
        header = tk.Frame(self.root, bg="#ffffff")
        header.pack(fill="x", pady=25)
        tk.Label(header, text="SafeShare Pro", font=("Segoe UI", 26, "bold"), bg="#ffffff", fg="#4f46e5").pack()
        tk.Label(header, text="V3.0 • Complete Control Edition", font=("Segoe UI", 10), bg="#ffffff", fg="#5f6368").pack()

        main = tk.Frame(self.root, bg="#ffffff")
        main.pack(fill="both", expand=True, padx=40)

        # Mode
        mode_lf = tk.LabelFrame(main, text=" Mode ", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#4f46e5", bd=1, relief="solid")
        mode_lf.pack(fill="x", pady=5)
        self.share_mode = tk.StringVar(value="folder")
        tk.Radiobutton(mode_lf, text="Folder", variable=self.share_mode, value="folder", command=self.update_ui, bg="#ffffff").pack(side="left", padx=20)
        tk.Radiobutton(mode_lf, text="File", variable=self.share_mode, value="file", command=self.update_ui, bg="#ffffff").pack(side="left", padx=20)

        # Config
        conf_lf = tk.LabelFrame(main, text=" Config ", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#4f46e5", bd=1, relief="solid")
        conf_lf.pack(fill="x", pady=5)
        
        tk.Label(conf_lf, text="Path:", bg="#ffffff").pack(anchor="w", padx=10)
        path_row = tk.Frame(conf_lf, bg="#ffffff"); path_row.pack(fill="x", padx=10, pady=(0,5))
        self.path_entry = tk.Entry(path_row, relief="solid", bd=1); self.path_entry.pack(side="left", fill="x", expand=True)
        self.path_entry.insert(0, os.getcwd())
        tk.Button(path_row, text="Browse", command=self.browse, bg="#f1f3f4", relief="flat").pack(side="left", padx=5)

        tk.Label(conf_lf, text="Network:", bg="#ffffff").pack(anchor="w", padx=10)
        net_row = tk.Frame(conf_lf, bg="#ffffff"); net_row.pack(fill="x", padx=10, pady=(0,5))
        self.ip_combo = ttk.Combobox(net_row, state="readonly"); self.ip_combo.pack(side="left", fill="x", expand=True)
        tk.Button(net_row, text="Refresh", command=self.refresh_ips, bg="#f1f3f4", relief="flat").pack(side="left", padx=5)
        
        tk.Label(conf_lf, text="Port:", bg="#ffffff").pack(anchor="w", padx=10)
        self.port_entry = tk.Entry(conf_lf, width=10, relief="solid", bd=1); self.port_entry.pack(anchor="w", padx=10, pady=(0,10)); self.port_entry.insert(0, "8000")

        # Security & Perms
        sec_lf = tk.LabelFrame(main, text=" Security & Access ", font=("Segoe UI", 9, "bold"), bg="#ffffff", fg="#4f46e5", bd=1, relief="solid")
        sec_lf.pack(fill="x", pady=5)
        self.allow_upload = tk.BooleanVar(value=False)
        tk.Checkbutton(sec_lf, text="Enable Uploads & Deletes", variable=self.allow_upload, bg="#ffffff").pack(anchor="w", padx=10)
        
        auth_row = tk.Frame(sec_lf, bg="#ffffff"); auth_row.pack(fill="x", padx=10, pady=5)
        tk.Label(auth_row, text="User:", bg="#ffffff").pack(side="left")
        self.user_entry = tk.Entry(auth_row, width=12, relief="solid", bd=1); self.user_entry.pack(side="left", padx=5)
        tk.Label(auth_row, text="Pass:", bg="#ffffff").pack(side="left")
        self.pass_entry = tk.Entry(auth_row, width=12, relief="solid", bd=1, show="●"); self.pass_entry.pack(side="left", padx=5)

        # Control
        ctl_frame = tk.Frame(main, bg="#ffffff"); ctl_frame.pack(fill="x", pady=10)
        self.btn_start = tk.Button(ctl_frame, text="START", bg="#4f46e5", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=8, command=self.start_server)
        self.btn_start.pack(side="left", fill="x", expand=True, padx=5)
        self.btn_stop = tk.Button(ctl_frame, text="STOP", bg="#ef4444", fg="white", font=("Segoe UI", 10, "bold"), relief="flat", pady=8, state="disabled", command=self.stop_server)
        self.btn_stop.pack(side="right", fill="x", expand=True, padx=5)

        # Link
        lnk_frame = tk.Frame(main, bg="#f8f9fa", bd=1, relief="solid"); lnk_frame.pack(fill="x")
        self.link_var = tk.StringVar(value="Offline")
        self.entry_link = tk.Entry(lnk_frame, textvariable=self.link_var, font=("Consolas", 10), bd=0, bg="#f8f9fa", state="readonly", justify="center")
        self.entry_link.pack(side="left", fill="x", expand=True, ipady=8)
        tk.Button(lnk_frame, text="Copy", command=self.copy_link, bg="#e8f0fe", relief="flat").pack(side="left", fill="y")
        tk.Button(lnk_frame, text="Open", command=self.open_link, bg="#4f46e5", fg="white", relief="flat").pack(side="left", fill="y")

        # Reduced Log Area Height
        self.log_area = scrolledtext.ScrolledText(main, height=3, font=("Consolas", 8), state='disabled', bg="#f1f3f4", relief="flat"); self.log_area.pack(fill="both", expand=True, pady=10)

        self.refresh_ips(); self.update_ui()

    def update_ui(self): pass
    def browse(self):
        p = filedialog.askdirectory() if self.share_mode.get() == "folder" else filedialog.askopenfilename()
        if p: self.path_entry.delete(0, tk.END); self.path_entry.insert(0, p)
    def log_to_gui(self, msg):
        self.log_area.config(state='normal'); self.log_area.insert(tk.END, msg); self.log_area.see(tk.END); self.log_area.config(state='disabled')
    def refresh_ips(self):
        raw = ["127.0.0.1"]; imap = get_ip_map()
        try: raw = socket.gethostbyname_ex(socket.gethostname())[2]
        except: pass
        final = [f"{ip} ({imap.get(ip, 'Net')})" for ip in raw]
        self.ip_combo['values'] = final; 
        if final: self.ip_combo.current(0)
    def start_server(self):
        path = self.path_entry.get(); ip = self.ip_combo.get().split(' ')[0] or "127.0.0.1"
        try: port = int(self.port_entry.get())
        except: return messagebox.showerror("Err", "Invalid Port")
        if not os.path.exists(path): return messagebox.showerror("Err", "Path not found")
        is_file = self.share_mode.get() == "file"
        srv_dir = os.path.dirname(path) if is_file else path
        srv_file = os.path.basename(path) if is_file else None
        u, p = self.user_entry.get().strip(), self.pass_entry.get().strip()
        SERVER_CONTEXT.update({"auth_enabled": bool(u and p), "upload_enabled": self.allow_upload.get(), "username": u, "password": p, "sessions": set(), "root_dir": srv_dir})
        self.server_thread = threading.Thread(target=self.run_server, args=(srv_dir, ip, port, srv_file))
        self.server_thread.daemon = True; self.server_thread.start()
    def run_server(self, directory, ip, port, served_file):
        try:
            os.chdir(directory)
            Handler = create_auth_handler(served_file)
            self.server = ThreadedHTTPServer(('0.0.0.0', port), Handler)
            link = f"http://{ip}:{port}"
            self.root.after(0, lambda: self.set_state(True, link))
            self.log_to_gui(f"[*] Started: {link}\n")
            self.server.serve_forever()
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            self.root.after(0, lambda: self.set_state(False))
    def set_state(self, running, link=""):
        if running:
            self.link_var.set(link); self.btn_start.config(state="disabled", bg="#bdc3c7"); self.btn_stop.config(state="normal", bg="#d93025")
        else:
            self.link_var.set("Offline"); self.btn_start.config(state="normal", bg="#4f46e5"); self.btn_stop.config(state="disabled", bg="#bdc3c7"); self.server = None
    def stop_server(self):
        if self.server: threading.Thread(target=self._shutdown).start(); self.link_var.set("Stopping...")
    def _shutdown(self):
        try: self.server.shutdown(); self.server.server_close()
        except: pass
        self.root.after(0, lambda: self.set_state(False))
        self.log_to_gui("[*] Stopped.\n")
    def copy_link(self):
        self.root.clipboard_clear(); self.root.clipboard_append(self.link_var.get()); messagebox.showinfo("Info", "Copied!")
    def open_link(self): webbrowser.open(self.link_var.get())

if __name__ == "__main__":
    root = tk.Tk(); app = FileShareApp(root); root.mainloop()