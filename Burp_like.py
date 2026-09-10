#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BURP-LIKE PYTHON - JATHNIEL EDITION
Proxy d'interception HTTP/HTTPS avec éditeur de requête complet

Fonctionnalités :
✅ Proxy HTTP/HTTPS (mitmproxy)
✅ Interception et modification de requêtes
✅ Décodage automatique (URL, Base64, HTML, Hex, JSON, JWT)
✅ History SQLite
✅ Repeater
✅ Decoder
✅ GUI PySide6
"""

import sys
import os
import threading
import json
import sqlite3
import urllib.parse
import base64
import html
import re
import unicodedata
from datetime import datetime
from pathlib import Path

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
except ImportError:
    print("❌ PySide6 non installé. Installez avec : pip install PySide6")
    sys.exit(1)

try:
    from mitmproxy import http, options
    from mitmproxy.tools.dump import DumpMaster
    MITM_OK = True
except ImportError:
    MITM_OK = False
    print("⚠️ mitmproxy non installé. Installez avec : pip install mitmproxy")

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("⚠️ requests non installé. Installez avec : pip install requests")


# ==================== OUTILS DE NETTOYAGE ====================

def clean_url(url: str) -> str:
    """Nettoie une URL des caractères invisibles/parasites."""
    if not url:
        return url
    url = unicodedata.normalize('NFKC', url)
    url = ''.join(c for c in url if unicodedata.category(c)[0] != 'C')
    url = url.replace('\xa0', '').replace('\u202f', '').replace('\u200b', '')
    url = re.sub(r'(https?:)[^/]*//', r'\1//', url)
    url = re.sub(r'(https?:)/(?![/])', r'\1//', url)
    return url.strip()


# ==================== BASE DE DONNÉES ====================

class Database:
    """Gestion de la base de données SQLite."""
    
    def __init__(self):
        self.db_path = Path.home() / '.burp_like' / 'history.db'
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT,
                url TEXT,
                host TEXT,
                path TEXT,
                headers TEXT,
                body TEXT,
                status INTEGER,
                response_headers TEXT,
                response_body TEXT,
                timestamp TEXT,
                modified INTEGER DEFAULT 0
            )
        ''')
        conn.commit()
        conn.close()
    
    def insert(self, req: dict):
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests (method, url, host, path, headers, body, status, response_headers, response_body, timestamp, modified)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            req.get('method', ''),
            req.get('url', ''),
            req.get('host', ''),
            req.get('path', ''),
            json.dumps(req.get('headers', {})),
            req.get('body', ''),
            req.get('status', 0),
            json.dumps(req.get('response_headers', {})),
            req.get('response_body', ''),
            datetime.now().isoformat(),
            1 if req.get('modified') else 0
        ))
        conn.commit()
        conn.close()


# ==================== DÉCODAGE ====================

class Decoder:
    """Décode automatiquement les valeurs (URL, Base64, HTML, Hex, JSON, JWT)."""
    
    @staticmethod
    def decode_value(value: str) -> dict:
        result = {'original': value, 'decoded': value, 'variants': []}
        if not value:
            return result
        
        # URL decode
        try:
            url_decoded = urllib.parse.unquote(value)
            if url_decoded != value:
                result['variants'].append({'type': 'url', 'value': url_decoded})
                result['decoded'] = url_decoded
        except:
            pass
        
        # Base64
        try:
            if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) % 4 == 0:
                b64_decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                if b64_decoded.isprintable():
                    result['variants'].append({'type': 'base64', 'value': b64_decoded})
        except:
            pass
        
        # HTML
        try:
            html_decoded = html.unescape(value)
            if html_decoded != value:
                result['variants'].append({'type': 'html', 'value': html_decoded})
        except:
            pass
        
        # Hex
        try:
            if re.match(r'^[0-9a-fA-F]+$', value) and len(value) % 2 == 0:
                hex_decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
                if hex_decoded.isprintable():
                    result['variants'].append({'type': 'hex', 'value': hex_decoded})
        except:
            pass
        
        # JSON
        try:
            json_data = json.loads(value)
            result['variants'].append({
                'type': 'json',
                'value': json.dumps(json_data, indent=2, ensure_ascii=False)
            })
        except:
            pass
        
        # JWT
        if value.count('.') == 2:
            try:
                parts = value.split('.')
                if len(parts) == 3:
                    padding = lambda s: s + '=' * (-len(s) % 4)
                    header = base64.urlsafe_b64decode(padding(parts[0])).decode('utf-8', errors='ignore')
                    payload = base64.urlsafe_b64decode(padding(parts[1])).decode('utf-8', errors='ignore')
                    result['variants'].append({
                        'type': 'jwt',
                        'value': f"Header: {header}\n\nPayload: {payload}"
                    })
            except:
                pass
        
        return result
    
    @staticmethod
    def decode_body(body: str) -> dict:
        result = {'original': body, 'decoded': body, 'params': {}, 'type': 'raw'}
        if not body:
            return result
        
        # JSON
        try:
            json_data = json.loads(body)
            result['type'] = 'json'
            result['decoded'] = json.dumps(json_data, indent=2, ensure_ascii=False)
            if isinstance(json_data, dict):
                for key, value in json_data.items():
                    if isinstance(value, str):
                        result['params'][key] = Decoder.decode_value(value)
            return result
        except:
            pass
        
        # Form-urlencoded
        try:
            params = urllib.parse.parse_qs(body)
            if params:
                result['type'] = 'form'
                decoded_lines = []
                for key, values in params.items():
                    value = values[0] if values else ''
                    decoded = Decoder.decode_value(value)
                    result['params'][key] = decoded
                    decoded_lines.append(f"{key} = {decoded['decoded']}")
                result['decoded'] = '\n'.join(decoded_lines)
                return result
        except:
            pass
        
        return result


# ==================== ADDON MITMPROXY ====================

class InterceptAddon:
    """Addon mitmproxy : intercepte et modifie les requêtes."""
    
    def __init__(self, gui_callback, db):
        self.gui_callback = gui_callback
        self.db = db
        self.intercept_enabled = True
        self.modified_data = {}
        self.events = {}
        self.lock = threading.Lock()
    
    def request(self, flow: http.HTTPFlow):
        body = flow.request.get_text() if flow.request.content else ''
        decoded_body = Decoder.decode_body(body)
        
        req_data = {
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'host': flow.request.host,
            'path': flow.request.path,
            'headers': dict(flow.request.headers),
            'body': body,
            'decoded_body': decoded_body,
            'flow': flow
        }
        
        if self.intercept_enabled:
            event_key = flow.request.pretty_url + '_' + str(id(flow))
            event = threading.Event()
            
            with self.lock:
                self.events[event_key] = event
            
            self.gui_callback('request_intercept', req_data, flow, event_key)
            event.wait(timeout=300)
            
            with self.lock:
                if event_key in self.modified_data:
                    mods = self.modified_data.pop(event_key)
                    
                    if mods.get('drop'):
                        flow.kill()
                        return
                    
                    if 'method' in mods:
                        flow.request.method = mods['method']
                    if 'url' in mods:
                        parsed = urllib.parse.urlparse(mods['url'])
                        flow.request.scheme = parsed.scheme
                        flow.request.host = parsed.netloc
                        flow.request.path = parsed.path + ('?' + parsed.query if parsed.query else '')
                    if 'headers' in mods:
                        flow.request.headers.clear()
                        for k, v in mods['headers'].items():
                            flow.request.headers[k] = v
                    if 'body' in mods:
                        flow.request.set_text(mods['body'])
                
                if event_key in self.events:
                    del self.events[event_key]
        else:
            self.gui_callback('request', req_data, flow, None)
    
    def modify_request(self, event_key, modifications):
        with self.lock:
            self.modified_data[event_key] = modifications
            if event_key in self.events:
                self.events[event_key].set()
    
    def response(self, flow: http.HTTPFlow):
        body = flow.request.get_text() if flow.request.content else ''
        decoded_body = Decoder.decode_body(body)
        
        req_data = {
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'host': flow.request.host,
            'path': flow.request.path,
            'headers': dict(flow.request.headers),
            'body': body,
            'decoded_body': decoded_body,
            'status': flow.response.status_code,
            'response_headers': dict(flow.response.headers),
            'response_body': flow.response.get_text() if flow.response.content else ''
        }
        
        self.db.insert(req_data)
        self.gui_callback('response', req_data, flow, None)


# ==================== PROXY SERVER ====================

class ProxyServer(threading.Thread):
    """Serveur proxy mitmproxy dans un thread."""
    
    def __init__(self, gui_callback, db, port=8080):
        super().__init__(daemon=True)
        self.gui_callback = gui_callback
        self.db = db
        self.port = port
        self.master = None
        self.addon = None
    
    def run(self):
        if not MITM_OK:
            return
        
        opts = options.Options(
            listen_host='127.0.0.1',
            listen_port=self.port
        )
        
        self.master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self.addon = InterceptAddon(self.gui_callback, self.db)
        self.master.addons.add(self.addon)
        
        try:
            self.master.run()
        except Exception as e:
            print(f"Erreur proxy: {e}")


# ==================== GUI ====================

class BurpLikeGUI(QMainWindow):
    """Interface graphique principale."""
    
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.proxy = None
        self.current_flow = None
        self.current_request = None
        self.current_event_key = None
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Burp-Like Python - JATHNIEL EDITION")
        self.setGeometry(100, 100, 1500, 950)
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a2e; }
            QWidget { background-color: #1a1a2e; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 12px; }
            QPushButton {
                background-color: #2d2d44;
                border: 1px solid #4a4a6a;
                border-radius: 4px;
                padding: 6px 14px;
                color: #e0e0e0;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #3d3d5a; }
            QPushButton#primary { background-color: #2d5a6a; border-color: #3d8a9a; }
            QPushButton#danger { background-color: #6a2d2d; border-color: #8a3d3d; }
            QPushButton#success { background-color: #2d6a2d; border-color: #3d8a3d; }
            QTabWidget::pane { border: 1px solid #2d2d44; background-color: #0d1117; }
            QTabBar::tab { background-color: #2d2d44; padding: 8px 20px; margin-right: 2px; color: #e0e0e0; }
            QTabBar::tab:selected { background-color: #4a4a6a; color: #00ff88; }
            QTableWidget { background-color: #0d1117; border: 1px solid #2d2d44; gridline-color: #2d2d44; color: #e0e0e0; }
            QHeaderView::section { background-color: #2d2d44; padding: 6px; border: none; color: #00ff88; font-weight: bold; }
            QTextEdit { background-color: #0d1117; border: 1px solid #2d2d44; color: #e0e0e0; font-family: 'Consolas', monospace; font-size: 12px; padding: 5px; }
            QLineEdit { background-color: #0d1117; border: 1px solid #2d2d44; padding: 6px; color: #e0e0e0; border-radius: 4px; }
            QComboBox { background-color: #0d1117; border: 1px solid #2d2d44; padding: 6px; color: #e0e0e0; border-radius: 4px; }
            QLabel { color: #e0e0e0; }
            QGroupBox { border: 1px solid #2d2d44; border-radius: 6px; margin-top: 10px; padding-top: 10px; color: #00ff88; font-weight: bold; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QStatusBar { background-color: #0d1117; color: #8888aa; }
            QSplitter::handle { background-color: #2d2d44; }
            QCheckBox { color: #e0e0e0; }
        """)
        
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(10, 10, 10, 10)
        
        header = QLabel("🔷 BURP-LIKE PYTHON - JATHNIEL EDITION")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #00ff88; padding: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        controls = QHBoxLayout()
        
        self.start_btn = QPushButton("▶️ Démarrer le proxy")
        self.start_btn.setObjectName("success")
        self.start_btn.clicked.connect(self.start_proxy)
        controls.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.stop_btn.setEnabled(False)
        controls.addWidget(self.stop_btn)
        
        controls.addSpacing(20)
        controls.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit("8080")
        self.port_input.setFixedWidth(80)
        controls.addWidget(self.port_input)
        
        controls.addSpacing(20)
        controls.addWidget(QLabel("Interception:"))
        self.intercept_toggle = QCheckBox()
        self.intercept_toggle.setChecked(True)
        controls.addWidget(self.intercept_toggle)
        
        controls.addStretch()
        
        self.status_label = QLabel("🔴 Proxy arrêté")
        self.status_label.setStyleSheet("color: #ff6666; font-weight: bold;")
        controls.addWidget(self.status_label)
        
        layout.addLayout(controls)
        
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_intercept_tab(), "🛑 Intercept")
        self.tabs.addTab(self.create_history_tab(), "📜 History")
        self.tabs.addTab(self.create_repeater_tab(), "🔁 Repeater")
        self.tabs.addTab(self.create_decoder_tab(), "🔤 Decoder")
        layout.addWidget(self.tabs)
        
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Prêt - Démarrez le proxy pour commencer")
    
    def create_intercept_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        toolbar = QHBoxLayout()
        
        self.forward_btn = QPushButton("➡️ Forward")
        self.forward_btn.setObjectName("success")
        self.forward_btn.clicked.connect(self.forward_request)
        self.forward_btn.setEnabled(False)
        toolbar.addWidget(self.forward_btn)
        
        self.drop_btn = QPushButton("❌ Drop")
        self.drop_btn.setObjectName("danger")
        self.drop_btn.clicked.connect(self.drop_request)
        self.drop_btn.setEnabled(False)
        toolbar.addWidget(self.drop_btn)
        
        self.modify_btn = QPushButton("✏️ Modifier & Envoyer")
        self.modify_btn.setObjectName("primary")
        self.modify_btn.clicked.connect(self.modify_and_forward)
        self.modify_btn.setEnabled(False)
        toolbar.addWidget(self.modify_btn)
        
        toolbar.addSpacing(20)
        
        self.decode_toggle = QCheckBox("🔓 Décoder automatiquement")
        self.decode_toggle.setChecked(True)
        self.decode_toggle.stateChanged.connect(self.refresh_current_view)
        toolbar.addWidget(self.decode_toggle)
        
        toolbar.addStretch()
        layout.addLayout(toolbar)
        
        splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Requête
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        
        req_group = QGroupBox("📤 Requête (Request)")
        req_group_layout = QVBoxLayout(req_group)
        
        url_line = QHBoxLayout()
        self.req_method = QComboBox()
        self.req_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        self.req_method.setFixedWidth(100)
        url_line.addWidget(self.req_method)
        
        self.req_url = QLineEdit()
        self.req_url.setPlaceholderText("URL de la requête...")
        url_line.addWidget(self.req_url)
        req_group_layout.addLayout(url_line)
        
        req_group_layout.addWidget(QLabel("📋 Headers:"))
        self.req_headers = QTextEdit()
        self.req_headers.setMaximumHeight(120)
        req_group_layout.addWidget(self.req_headers)
        
        body_tabs = QTabWidget()
        
        self.req_body_raw = QTextEdit()
        self.req_body_raw.setPlaceholderText("Body brut...")
        body_tabs.addTab(self.req_body_raw, "📄 Raw")
        
        self.req_body_decoded = QTextEdit()
        self.req_body_decoded.setReadOnly(True)
        body_tabs.addTab(self.req_body_decoded, "🔓 Decoded")
        
        self.req_params = QTableWidget(0, 3)
        self.req_params.setHorizontalHeaderLabels(["Paramètre", "Valeur décodée", "Type"])
        self.req_params.horizontalHeader().setStretchLastSection(True)
        body_tabs.addTab(self.req_params, "📊 Params")
        
        req_group_layout.addWidget(QLabel("📦 Body:"))
        req_group_layout.addWidget(body_tabs)
        
        req_layout.addWidget(req_group)
        splitter.addWidget(req_widget)
        
        # Réponse
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        
        resp_group = QGroupBox("📥 Réponse (Response)")
        resp_group_layout = QVBoxLayout(resp_group)
        
        self.resp_status = QLineEdit()
        self.resp_status.setReadOnly(True)
        resp_group_layout.addWidget(self.resp_status)
        
        resp_group_layout.addWidget(QLabel("📋 Headers:"))
        self.resp_headers = QTextEdit()
        self.resp_headers.setMaximumHeight(100)
        self.resp_headers.setReadOnly(True)
        resp_group_layout.addWidget(self.resp_headers)
        
        resp_group_layout.addWidget(QLabel("📦 Body:"))
        self.resp_body = QTextEdit()
        self.resp_body.setReadOnly(True)
        resp_group_layout.addWidget(self.resp_body)
        
        resp_layout.addWidget(resp_group)
        splitter.addWidget(resp_widget)
        
        layout.addWidget(splitter)
        return tab
    
    def create_history_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels([
            "ID", "Method", "Host", "Path", "Status", "Modified", "Timestamp"
        ])
        self.history_table.horizontalHeader().setStretchLastSection(True)
        self.history_table.cellClicked.connect(self.on_history_click)
        layout.addWidget(self.history_table)
        
        details_group = QGroupBox("📋 Détails")
        details_layout = QVBoxLayout(details_group)
        
        self.details_edit = QTextEdit()
        self.details_edit.setReadOnly(True)
        details_layout.addWidget(self.details_edit)
        layout.addWidget(details_group)
        
        btns = QHBoxLayout()
        refresh_btn = QPushButton("🔄 Rafraîchir")
        refresh_btn.clicked.connect(self.refresh_history)
        btns.addWidget(refresh_btn)
        
        clear_btn = QPushButton("🗑️ Effacer")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self.clear_history)
        btns.addWidget(clear_btn)
        
        btns.addStretch()
        layout.addLayout(btns)
        return tab
    
    def create_repeater_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        
        self.repeater_url = QLineEdit()
        self.repeater_url.setPlaceholderText("https://example.com/api")
        url_layout.addWidget(self.repeater_url)
        
        self.repeater_method = QComboBox()
        self.repeater_method.addItems(["GET", "POST", "PUT", "DELETE", "PATCH"])
        url_layout.addWidget(self.repeater_method)
        
        self.repeater_send = QPushButton("📤 Envoyer")
        self.repeater_send.setObjectName("primary")
        self.repeater_send.clicked.connect(self.send_repeater)
        url_layout.addWidget(self.repeater_send)
        
        layout.addLayout(url_layout)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.addWidget(QLabel("📤 Requête"))
        self.repeater_request = QTextEdit()
        req_layout.addWidget(self.repeater_request)
        splitter.addWidget(req_widget)
        
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.addWidget(QLabel("📥 Réponse"))
        self.repeater_response = QTextEdit()
        self.repeater_response.setReadOnly(True)
        resp_layout.addWidget(self.repeater_response)
        splitter.addWidget(resp_widget)
        
        layout.addWidget(splitter)
        return tab
    
    def create_decoder_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        input_group = QGroupBox("📝 Input")
        input_layout = QVBoxLayout(input_group)
        self.decoder_input = QTextEdit()
        input_layout.addWidget(self.decoder_input)
        layout.addWidget(input_group)
        
        btns = QHBoxLayout()
        for label, action in [
            ("URL Encode", 'url_encode'), ("URL Decode", 'url_decode'),
            ("Base64 Encode", 'b64_encode'), ("Base64 Decode", 'b64_decode'),
            ("Hex Encode", 'hex_encode'), ("Hex Decode", 'hex_decode')
        ]:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, a=action: self.decode_action(a))
            btns.addWidget(btn)
        btns.addStretch()
        layout.addLayout(btns)
        
        output_group = QGroupBox("📤 Output")
        output_layout = QVBoxLayout(output_group)
        self.decoder_output = QTextEdit()
        self.decoder_output.setReadOnly(True)
        output_layout.addWidget(self.decoder_output)
        layout.addWidget(output_group)
        
        return tab
    
    # ==================== ACTIONS ====================
    
    def start_proxy(self):
        if not MITM_OK:
            QMessageBox.warning(self, "Erreur", "mitmproxy n'est pas installé.\n\npip install mitmproxy")
            return
        
        port = int(self.port_input.text())
        self.proxy = ProxyServer(self.on_proxy_event, self.db, port)
        self.proxy.start()
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("🟢 Proxy actif")
        self.status_label.setStyleSheet("color: #00ff88; font-weight: bold;")
        self.status.showMessage(f"🟢 Proxy actif sur 127.0.0.1:{port}")
    
    def stop_proxy(self):
        if self.proxy and self.proxy.master:
            self.proxy.master.shutdown()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("🔴 Proxy arrêté")
        self.status_label.setStyleSheet("color: #ff6666; font-weight: bold;")
        self.status.showMessage("🔴 Proxy arrêté")
    
    def on_proxy_event(self, event_type, data, flow, event_key):
        if event_type == 'request_intercept':
            self.current_flow = flow
            self.current_request = data
            self.current_event_key = event_key
            
            self.req_method.setCurrentText(data['method'])
            self.req_url.setText(data['url'])
            
            headers_text = "\n".join([f"{k}: {v}" for k, v in data['headers'].items()])
            self.req_headers.setPlainText(headers_text)
            
            self.req_body_raw.setPlainText(data['body'])
            self._update_decoded_body(data['decoded_body'])
            
            self.forward_btn.setEnabled(True)
            self.drop_btn.setEnabled(True)
            self.modify_btn.setEnabled(True)
            
            self.status.showMessage("⏸️ Requête interceptée")
        
        elif event_type == 'response':
            self.resp_status.setText(f"HTTP {data.get('status', '?')}")
            headers_text = "\n".join([f"{k}: {v}" for k, v in data.get('response_headers', {}).items()])
            self.resp_headers.setPlainText(headers_text)
            self.resp_body.setPlainText(data.get('response_body', '')[:10000])
            self.refresh_history()
    
    def _update_decoded_body(self, decoded_body):
        self.req_body_decoded.setPlainText(decoded_body.get('decoded', ''))
        
        params = decoded_body.get('params', {})
        self.req_params.setRowCount(len(params))
        
        for i, (key, value) in enumerate(params.items()):
            self.req_params.setItem(i, 0, QTableWidgetItem(key))
            decoded_val = value.get('decoded', value.get('original', ''))
            self.req_params.setItem(i, 1, QTableWidgetItem(str(decoded_val)))
            type_str = decoded_body.get('type', 'raw')
            if value.get('variants'):
                type_str += f" ({', '.join([v['type'] for v in value['variants']])})"
            self.req_params.setItem(i, 2, QTableWidgetItem(type_str))
        
        self.req_params.resizeColumnsToContents()
    
    def refresh_current_view(self):
        if self.current_request:
            if self.decode_toggle.isChecked():
                self._update_decoded_body(self.current_request['decoded_body'])
            else:
                self.req_body_decoded.setPlainText(self.current_request['body'])
    
    def forward_request(self):
        if self.proxy and self.proxy.addon:
            self.proxy.addon.modify_request(self.current_event_key, {})
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.modify_btn.setEnabled(False)
        self.status.showMessage("➡️ Requête transmise")
    
    def drop_request(self):
        if self.proxy and self.proxy.addon:
            self.proxy.addon.modify_request(self.current_event_key, {'drop': True})
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.modify_btn.setEnabled(False)
        self.status.showMessage("❌ Requête abandonnée")
    
    def modify_and_forward(self):
        headers = {}
        for line in self.req_headers.toPlainText().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        modifications = {
            'method': self.req_method.currentText(),
            'url': self.req_url.text(),
            'headers': headers,
            'body': self.req_body_raw.toPlainText()
        }
        
        if self.proxy and self.proxy.addon:
            self.proxy.addon.modify_request(self.current_event_key, modifications)
        
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)
        self.modify_btn.setEnabled(False)
        self.status.showMessage("✏️ Requête modifiée et transmise")
    
    def refresh_history(self):
        conn = sqlite3.connect(str(self.db.db_path))
        cursor = conn.cursor()
        cursor.execute('SELECT id, method, host, path, status, modified, timestamp FROM requests ORDER BY id DESC LIMIT 100')
        rows = cursor.fetchall()
        conn.close()
        
        self.history_table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            for j, value in enumerate(row):
                self.history_table.setItem(i, j, QTableWidgetItem(str(value)))
    
    def on_history_click(self, row, col):
        item = self.history_table.item(row, 0)
        if not item:
            return
        req_id = item.text()
        
        conn = sqlite3.connect(str(self.db.db_path))
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM requests WHERE id = ?', (req_id,))
        row_data = cursor.fetchone()
        conn.close()
        
        if row_data:
            details = (
                f"ID: {row_data[0]}\n"
                f"Method: {row_data[1]}\n"
                f"URL: {row_data[2]}\n"
                f"Host: {row_data[3]}\n"
                f"Path: {row_data[4]}\n"
                f"Status: {row_data[7]}\n"
                f"Modified: {'Oui' if row_data[11] else 'Non'}\n"
                f"Timestamp: {row_data[10]}\n\n"
                f"Headers:\n{row_data[5]}\n\n"
                f"Body:\n{row_data[6]}"
            )
            self.details_edit.setPlainText(details)
    
    def clear_history(self):
        reply = QMessageBox.question(
            self, "Confirmation", "Effacer tout l'historique ?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            conn = sqlite3.connect(str(self.db.db_path))
            cursor = conn.cursor()
            cursor.execute('DELETE FROM requests')
            conn.commit()
            conn.close()
            self.refresh_history()
    
    def send_repeater(self):
        if not REQUESTS_OK:
            self.repeater_response.setPlainText("❌ requests non installé")
            return
        
        url = clean_url(self.repeater_url.text())
        method = self.repeater_method.currentText()
        if not url:
            return
        
        try:
            req_text = self.repeater_request.toPlainText()
            headers = {}
            body = ""
            in_body = False
            
            for line in req_text.split('\n'):
                if line.strip() == "":
                    in_body = True
                    continue
                if in_body:
                    body += line + "\n"
                elif ':' in line and not line.startswith(method):
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            response = requests.request(method, url, headers=headers, data=body, timeout=30)
            
            resp_text = f"HTTP/1.1 {response.status_code}\n"
            for k, v in response.headers.items():
                resp_text += f"{k}: {v}\n"
            resp_text += f"\n{response.text[:10000]}"
            
            self.repeater_response.setPlainText(resp_text)
            
            self.db.insert({
                'method': method, 'url': url,
                'host': url.split('/')[2] if '//' in url else '',
                'path': '/' + '/'.join(url.split('/')[3:]) if '//' in url else url,
                'headers': headers, 'body': body,
                'status': response.status_code,
                'response_headers': dict(response.headers),
                'response_body': response.text[:10000]
            })
            self.refresh_history()
        except Exception as e:
            self.repeater_response.setPlainText(f"❌ Erreur: {e}")
    
    def decode_action(self, action):
        text = self.decoder_input.toPlainText()
        try:
            if action == 'url_encode':
                result = urllib.parse.quote(text)
            elif action == 'url_decode':
                result = urllib.parse.unquote(text)
            elif action == 'b64_encode':
                result = base64.b64encode(text.encode()).decode()
            elif action == 'b64_decode':
                result = base64.b64decode(text.encode()).decode()
            elif action == 'hex_encode':
                result = text.encode().hex()
            elif action == 'hex_decode':
                result = bytes.fromhex(text).decode()
            else:
                result = "Action inconnue"
            self.decoder_output.setPlainText(result)
        except Exception as e:
            self.decoder_output.setPlainText(f"❌ Erreur: {e}")


# ==================== MAIN ====================

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = BurpLikeGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()