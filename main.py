import sys
import os
import psutil
import time
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLineEdit, QPushButton, QTextEdit, 
                             QProgressBar, QLabel, QSplitter, QSizePolicy)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer, QRectF
from PyQt6.QtGui import QTextCursor, QPainter, QPen, QColor, QBrush, QConicalGradient

from core.scanner import NetworkScanner
from core.exploits import ExploitManager
from scapy.all import sniff, IP, TCP, UDP

os.environ["QT_LOGGING_RULES"] = "*.debug=false;qt.qpa.*=false"

class RadarWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.angle = 0
        self.is_scanning = False
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_angle)
        self.timer.start(30)
        self.setMinimumWidth(160) 
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def set_scan_mode(self, active):
        self.is_scanning = active
        self.update()

    def update_angle(self):
        self.angle = (self.angle + 3) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(2, 2, 2))
        
        rect_size = min(self.width(), self.height()) - 20
        rect = QRectF((self.width()-rect_size)/2, (self.height()-rect_size)/2, rect_size, rect_size)
        center = rect.center()
        radius = rect_size / 2

        main_color = QColor(255, 68, 68) if self.is_scanning else QColor(0, 217, 255)
        
        painter.setPen(QPen(main_color, 1))
        painter.setOpacity(0.2)
        painter.drawEllipse(center, radius, radius)
        painter.drawEllipse(center, radius * 0.6, radius * 0.6)
        painter.drawLine(int(center.x() - radius), int(center.y()), int(center.x() + radius), int(center.y()))
        painter.drawLine(int(center.x()), int(center.y() - radius), int(center.x()), int(center.y() + radius))

        painter.setOpacity(1.0)
        gradient = QConicalGradient(center, -self.angle)
        gradient.setColorAt(0, QColor(main_color.red(), main_color.green(), main_color.blue(), 200))
        gradient.setColorAt(0.15, QColor(main_color.red(), main_color.green(), main_color.blue(), 0))
        
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(gradient))
        painter.drawPie(rect, int(self.angle * 16), 70 * 16) 

        painter.setBrush(QBrush(main_color))
        painter.drawEllipse(center, 3, 3)

class SystemMonitorThread(QThread):
    stats_signal = pyqtSignal(str)
    speed_signal = pyqtSignal(str)

    def run(self):
        old_io = psutil.net_io_counters()
        while True:
            time.sleep(1)
            new_io = psutil.net_io_counters()
            rx = (new_io.bytes_recv - old_io.bytes_recv) / 1024
            tx = (new_io.bytes_sent - old_io.bytes_sent) / 1024
            self.speed_signal.emit(f"<b style='color:#00ff00;'>RX: {rx:.1f} KB/s | TX: {tx:.1f} KB/s</b>")
            old_io = new_io
            
            cpu = psutil.cpu_percent()
            ram = psutil.virtual_memory().percent
            procs = sorted(psutil.process_iter(['pid', 'name', 'memory_percent']), 
                           key=lambda x: x.info['memory_percent'], reverse=True)[:5]
            proc_info = "<br>".join([f"{p.info['pid']} | {p.info['name'][:12]} | {p.info['memory_percent']:.1f}%" for p in procs])
            conns = psutil.net_connections(kind='inet')
            conn_info = "<br>".join([f"{c.laddr.port} -> {c.raddr.ip if c.raddr else '*'}" for c in conns[:8]])
            stats = f"<b style='color:#ffcc00;'>[RESOURCES]</b><br>CPU: {cpu}% | RAM: {ram}%<br><br><b style='color:#ffcc00;'>[TOP]</b><br>{proc_info}<br><br><b style='color:#ffcc00;'>[NET]</b><br>{conn_info}"
            self.stats_signal.emit(stats)

class SnifferThread(QThread):
    packet_signal = pyqtSignal(str)
    def run(self):
        def process_packet(pkt):
            if pkt.haslayer(IP):
                self.packet_signal.emit(f"[{pkt.getlayer(1).name}] {pkt[IP].src} -> {pkt[IP].dst}")
        sniff(prn=process_packet, store=0)

class ScanThread(QThread):
    result_signal = pyqtSignal(list)
    status_signal = pyqtSignal(str)
    def __init__(self, target):
        super().__init__(); self.target = target
        self.scanner = NetworkScanner(); self.exploits = ExploitManager()
    def run(self):
        try:
            self.status_signal.emit(f"[*] Analyzing {self.target}...")
            results = self.scanner.scan_hosts(self.target)
            for h in results:
                for p in h.get('ports', []):
                    q = f"{p['service']} {p['version']}".strip()
                    found = self.exploits.search(q) or self.exploits.search(p['service'])
                    p['exploits'] = found[:3]
            self.result_signal.emit(results)
        except Exception as e: self.status_signal.emit(f"[!] Error: {e}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Netmon by NEXTWUZY")
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(int(screen.width() * 0.85), int(screen.height() * 0.85))
        self.init_ui()
        
        self.sniff_thread = SnifferThread(); self.sniff_thread.packet_signal.connect(self.update_sniffer); self.sniff_thread.start()
        self.sys_thread = SystemMonitorThread()
        self.sys_thread.stats_signal.connect(self.update_sys_info); self.sys_thread.speed_signal.connect(self.update_speed_info); self.sys_thread.start()

    def init_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        top = QHBoxLayout()
        self.speed_label = QLabel("RX: 0.0 | TX: 0.0")
        self.speed_label.setFixedHeight(40)
        self.speed_label.setStyleSheet("border: 2px solid #333; background: #000; padding: 5px; font-family: monospace;")
        
        self.target_input = QLineEdit("127.0.0.1")
        self.target_input.setFixedHeight(40)
        self.target_input.setStyleSheet("background: #111; color: #fff; font-family: monospace; font-size: 14px; padding-left: 10px;")
        
        self.scan_btn = QPushButton("EXECUTE AUDIT")
        self.scan_btn.setFixedHeight(40)
        self.scan_btn.setStyleSheet("background-color: #b32d2d; color: white; font-weight: bold;")
        self.scan_btn.clicked.connect(self.start_audit)
        
        top.addWidget(self.speed_label, 2)
        top.addWidget(self.target_input, 5)
        top.addWidget(self.scan_btn, 2)
        layout.addLayout(top)

        self.main_v_split = QSplitter(Qt.Orientation.Vertical)
        self.mid_h_split = QSplitter(Qt.Orientation.Horizontal)
        
        self.audit_log = QTextEdit(); self.audit_log.setReadOnly(True)
        self.audit_log.setStyleSheet("background:#050505; color:#00ff00; font-family:monospace; border:1px solid #222;")
        
        self.sys_info = QTextEdit(); self.sys_info.setReadOnly(True)
        self.sys_info.setStyleSheet("background:#050505; color:#ffcc00; font-family:monospace; border:1px solid #222;")
        
        self.mid_h_split.addWidget(self.audit_log); self.mid_h_split.addWidget(self.sys_info)
        
        self.sniffer_container = QWidget()
        self.sniffer_container.setStyleSheet("border-top: 2px solid #00d9ff;")
        sniff_layout = QHBoxLayout(self.sniffer_container)
        sniff_layout.setContentsMargins(0,0,0,0)
        sniff_layout.setSpacing(0)

        self.sniffer_log = QTextEdit(); self.sniffer_log.setReadOnly(True)
        self.sniffer_log.setStyleSheet("background:#020202; color:#00d9ff; font-family:monospace; border:none;")
        
        self.radar = RadarWidget()
        self.radar.setStyleSheet("border-left:1px solid #333; background:#020202;")

        sniff_layout.addWidget(self.sniffer_log, 4)
        sniff_layout.addWidget(self.radar, 1)

        self.main_v_split.addWidget(self.mid_h_split)
        self.main_v_split.addWidget(self.sniffer_container)
        self.main_v_split.setStretchFactor(0, 3)
        layout.addWidget(self.main_v_split)

    def update_speed_info(self, text): self.speed_label.setText(text)
    def update_sys_info(self, html): self.sys_info.setHtml(html)
    def update_sniffer(self, msg):
        self.sniffer_log.append(msg)
        self.sniffer_log.moveCursor(QTextCursor.MoveOperation.End)

    def start_audit(self):
        self.audit_log.clear(); self.scan_btn.setEnabled(False); self.radar.set_scan_mode(True)
        self.thread = ScanThread(self.target_input.text())
        self.thread.status_signal.connect(lambda m: self.audit_log.append(m))
        self.thread.result_signal.connect(self.on_results); self.thread.start()

    def on_results(self, data):
        self.scan_btn.setEnabled(True); self.radar.set_scan_mode(False)
        for h in data:
            self.audit_log.append(f"\n<b>[+] {h['host']} ({h['os']})</b>")
            for p in h['ports']:
                self.audit_log.append(f"  - {p['port']}/{p['service']} {p['version']}")
                if p.get('exploits'):
                    self.audit_log.append("    <b style='color:#ff4444;'>[!] VULNS:</b>")
                    for ex in p['exploits']: self.audit_log.append(f"      > {ex['Title']}")

if __name__ == "__main__":
    os.environ["QT_QPA_PLATFORM"] = "xcb"
    app = QApplication(sys.argv); app.setStyle("Fusion"); win = MainWindow(); win.show(); sys.exit(app.exec())