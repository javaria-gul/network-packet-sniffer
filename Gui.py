import sys
import threading
import csv
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QComboBox, QLineEdit
)
from PyQt5.QtGui import QPalette, QColor, QFont
from PyQt5.QtCore import QTimer, Qt
import sniffer  # make sure this is the updated version

class PacketSnifferGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer Pro")
        self.setGeometry(100, 100, 1450, 700)

        # Dark Neon Theme
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor("#0a0a0a"))
        palette.setColor(QPalette.WindowText, QColor("#ffffff"))
        self.setPalette(palette)

        self.setStyleSheet("""
            QWidget {
                background-color: #0a0a0a;
                color: #ffffff;
                font-family: Consolas;
                font-size: 13px;
            }
            QPushButton {
                background-color: #0f0f0f;
                color: #39ff14;
                border: 1px solid #39ff14;
                padding: 6px 14px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #1aff00;
                color: black;
                font-weight: bold;
                border: 1px solid #39ff14;
                box-shadow: 0 0 10px #39ff14;
            }
            QComboBox, QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555;
                border-radius: 3px;
            }
            QHeaderView::section {
                background-color: #282c34;
                color: #ffffff;
                font-weight: bold;
                padding: 6px;
            }
            QTableWidget {
                gridline-color: #444;
            }
        """)

        # Layouts
        self.main_layout = QVBoxLayout()
        self.button_layout = QHBoxLayout()
        self.export_layout = QHBoxLayout()

        # Status label
        self.status_label = QLabel("Status: Idle")
        self.status_label.setFont(QFont("Consolas", 11))
        self.main_layout.addWidget(self.status_label)

        # Table setup
        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "TTL", "Length", "Packet Type", "TCP Flags"
        ])
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setDefaultSectionSize(150)
        self.main_layout.addWidget(self.table)

        # Buttons
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.clear_button = QPushButton("Clear Table")
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_table)

        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)
        self.button_layout.addWidget(self.clear_button)
        self.main_layout.addLayout(self.button_layout)

        # Export section
        self.export_type = QComboBox()
        self.export_type.addItems(["Export as CSV", "Export as TXT"])
        self.filename_input = QLineEdit()
        self.filename_input.setPlaceholderText("Enter filename (without extension)")
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.handle_export)

        self.export_layout.addWidget(self.export_type)
        self.export_layout.addWidget(self.filename_input)
        self.export_layout.addWidget(self.export_button)
        self.main_layout.addLayout(self.export_layout)

        self.setLayout(self.main_layout)

        # Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_table)
        self.timer.start(1000)

        self.capture_thread = None

    def start_capture(self):
        self.status_label.setText("Status: Capturing Packets...")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        sniffer.stop_sniffing.clear()
        self.capture_thread = threading.Thread(target=sniffer.capture_packets)
        self.capture_thread.start()

    def stop_capture(self):
        self.status_label.setText("Status: Stopping...")
        sniffer.stop_sniffing.set()
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2)
        self.status_label.setText("Status: Stopped")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def clear_table(self):
        self.table.setRowCount(0)

    def update_table(self):
        while not sniffer.packet_queue.empty():
            packet = sniffer.packet_queue.get()
            row = self.table.rowCount()
            self.table.insertRow(row)

            values = [
                packet.get("src_ip", ""),
                str(packet.get("src_port") or ""),
                packet.get("dest_ip", ""),
                str(packet.get("dst_port") or ""),
                packet.get("protocol", ""),
                str(packet.get("ttl", "")),
                str(packet.get("length", "")),
                packet.get("packet_type", ""),
                packet.get("tcp_flags", "")
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(row, col, item)

            # Coloring based on packet type
            color = "#1a1a1a"
            ptype = packet.get("packet_type", "").lower()

            if "dns" in ptype:
                color = "#005577"
            elif "icmp echo request" in ptype:
                color = "#660066"
            elif "icmp echo reply" in ptype:
                color = "#330099"
            elif "icmp" in ptype:
                color = "#660000"
            elif "http" in ptype:
                color = "#2e8b57"
            elif "https" in ptype:
                color = "#4682b4"
            elif "tcp" in ptype:
                color = "#444444"
            elif "udp" in ptype:
                color = "#003300"

            for col in range(self.table.columnCount()):
                self.table.item(row, col).setBackground(QColor(color))

        self.status_label.setText(f"Packets Captured: {self.table.rowCount()}")

    def handle_export(self):
        export_format = self.export_type.currentText()
        name = self.filename_input.text().strip()
        if not name:
            name = "captured_packets"

        if export_format == "Export as CSV":
            self.export_to_csv(name + ".csv")
        else:
            self.export_to_txt(name + ".txt")

    def export_to_csv(self, filename):
        with open(filename, "w", newline='', encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Source IP", "Source Port", "Destination IP",
                "Destination Port", "Protocol", "TTL", "Length", "Packet Type", "TCP Flags"
            ])
            for row in range(self.table.rowCount()):
                writer.writerow([
                    self.table.item(row, col).text() if self.table.item(row, col) else ""
                    for col in range(self.table.columnCount())
                ])
        self.status_label.setText(f"Exported to {filename} (CSV)")

    def export_to_txt(self, filename):
        headers = [
            "Source IP", "Source Port", "Destination IP", "Destination Port",
            "Protocol", "TTL", "Length", "Packet Type", "TCP Flags"
        ]
        rows = []

        for row in range(self.table.rowCount()):
            rows.append([
                self.table.item(row, col).text() if self.table.item(row, col) else ""
                for col in range(self.table.columnCount())
            ])

        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, val in enumerate(row):
                col_widths[i] = max(col_widths[i], len(val))

        def format_row(values):
            return "| " + " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(values)) + " |"

        with open(filename, "w", encoding='utf-8') as f:
            f.write(format_row(headers) + "\n")
            f.write("|" + "|".join("-" * (w + 2) for w in col_widths) + "|\n")
            for row in rows:
                f.write(format_row(row) + "\n")

        self.status_label.setText(f"Exported to {filename} (TXT Table)")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferGUI()
    window.show()
    sys.exit(app.exec_())

