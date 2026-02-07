"""
GAXSS GUI - Compact Optimized Edition (FIXED)
Modern UI/UX with space-efficient layout
All scanning functionality preserved
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import ttkbootstrap as ttk_boot
import threading
import queue
import sys
import types
import logging
import os
import csv
import re
from datetime import datetime
from PIL import Image, ImageDraw, ImageTk
import io
import webbrowser


# Import GAXSS CLI
try:
    from main_gaxss import GAXSS_CLI
except ImportError as e:
    print(f"Error: {e}")
    sys.exit(1)


class LogCapture(logging.Handler):
    """Custom logging handler for internal logging (not displayed)"""
    def __init__(self, queue_obj):
        super().__init__()
        self.queue_obj = queue_obj

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.queue_obj.put((msg, level))
        except Exception:
            pass


class ModernResultsFrame(ttk_boot.Frame):
    """Enhanced results display with improved visual hierarchy"""
    color_map = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
    }

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.result_data = None
        self.setup_ui()

    def setup_ui(self):
        """Setup enhanced scrollable UI"""
        canvas_frame = ttk_boot.Frame(self)
        canvas_frame.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(canvas_frame, bg="#1a1d23", highlightthickness=0)
        scrollbar = ttk_boot.Scrollbar(
            canvas_frame, orient="vertical", command=self.canvas.yview, bootstyle="info-round"
        )
        scrollable_frame = ttk_boot.Frame(self.canvas, bootstyle="dark")

        scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )

        self.window_id = self.canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.window_id, width=e.width))
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.content_frame = scrollable_frame

    def show_initial_message(self):
        """Show welcome message before first scan"""
        welcome_container = ttk_boot.Frame(self.content_frame)
        welcome_container.pack(fill="both", expand=True, padx=40, pady=80)

        ttk_boot.Label(
            welcome_container,
            text="🔍",
            font=("Segoe UI Emoji", 72),
            bootstyle="info",
        ).pack(pady=(20, 20))

        ttk_boot.Label(
            welcome_container,
            text="Ready to Scan",
            font=("Segoe UI", 24, "bold"),
            bootstyle="light",
        ).pack()

        ttk_boot.Label(
            welcome_container,
            text="Configure your scan parameters and click 'Start Security Scan' to begin",
            font=("Segoe UI", 12),
            bootstyle="secondary",
        ).pack(pady=(12, 0))

    def display_results(self, result_data, mode):
        """Display enhanced vulnerability summary with improved visuals"""
        rows = result_data["rows"]
        if not rows:
            empty_container = ttk_boot.Frame(self.content_frame)
            empty_container.pack(fill="both", expand=True, padx=40, pady=60)

            ttk_boot.Label(
                empty_container,
                text="⚠",
                font=("Segoe UI Emoji", 64),
                bootstyle="warning",
            ).pack(pady=(20, 15))

            ttk_boot.Label(
                empty_container,
                text=f"No Results Available",
                font=("Segoe UI", 20, "bold"),
                bootstyle="secondary",
            ).pack()

            ttk_boot.Label(
                empty_container,
                text=f"The {mode.upper()} scan completed but found no data to display.",
                font=("Segoe UI", 11),
                bootstyle="secondary",
            ).pack(pady=(8, 0))
            return

        # Calculate metrics
        risk_counts = {
            "CRITICAL": sum(1 for r in rows if r.get("Risk_Level", "").strip().upper() == "CRITICAL"),
            "HIGH": sum(1 for r in rows if r.get("Risk_Level", "").strip().upper() == "HIGH"),
            "MEDIUM": sum(1 for r in rows if r.get("Risk_Level", "").strip().upper() == "MEDIUM"),
            "LOW": sum(1 for r in rows if r.get("Risk_Level", "").strip().upper() == "LOW"),
        }

        is_vulnerable = risk_counts["CRITICAL"] > 0 or risk_counts["HIGH"] > 0

        status_text = "VULNERABLE" if is_vulnerable else "SECURE"
        status_icon = "☠️" if is_vulnerable else "🟢"
        status_color = "#dc3545" if is_vulnerable else "#28a745"

        best_row = max(rows, key=lambda x: float(x.get("Fitness", 0)))

        # Clear previous content
        for child in self.content_frame.winfo_children():
            child.destroy()

        # Header Section with Mode Badge (full width, less side padding)
        header_container = ttk_boot.Frame(self.content_frame)
        header_container.pack(fill="x", expand=True, padx=10, pady=(25, 15))

        mode_badge = tk.Frame(header_container, bg="#007bff", height=32)
        mode_badge.pack(side="left", padx=(0, 15))

        ttk_boot.Label(
            mode_badge,
            text=f" {mode.upper()} SCAN ",
            font=("Segoe UI", 10, "bold"),
            bootstyle="inverse-primary",
            background="#007bff",
        ).pack(padx=12, pady=6)

        ttk_boot.Label(
            header_container,
            text="Scan Results",
            font=("Segoe UI", 22, "bold"),
            bootstyle="light",
        ).pack(side="left")

        # Enhanced Status Card
        status_container = ttk_boot.Frame(self.content_frame)
        status_container.pack(fill="x", expand=True, padx=10, pady=(5, 25))

        status_card = tk.Frame(status_container, bg=status_color, bd=0)
        status_card.pack(fill="x", pady=0)

        status_inner = ttk_boot.Frame(status_card, bootstyle="dark")
        status_inner.pack(fill="both", expand=True, padx=3, pady=3)

        status_content = tk.Frame(status_inner, bg=status_color, height=110)
        status_content.pack(fill="both", expand=True, padx=25, pady=20)
        status_content.pack_propagate(False)

        icon_size = 84  # diameter of the circle

        icon_canvas = tk.Canvas(
            status_content,
            width=icon_size,
            height=icon_size,
            bg=status_color,  # same as parent to blend
            highlightthickness=0
        )
        icon_canvas.pack(side="left", padx=(10, 20))

        # Draw circle
        icon_canvas.create_oval(
            2, 2,
            icon_size - 2, icon_size - 2,
            fill=status_color,
            outline=status_color
        )

        # Draw emoji centered
        icon_canvas.create_text(
            icon_size // 2,
            icon_size // 2,
            text=status_icon,
            font=("Segoe UI Emoji", 36),
            fill="#ffffff"
        )

        status_text_frame = tk.Frame(status_content, bg=status_color)
        status_text_frame.pack(side="left", fill="both", expand=True)

        ttk_boot.Label(
            status_text_frame,
            text="Security Status",
            font=("Segoe UI", 11),
            background=status_color,
            foreground="#ffffff",
        ).pack(anchor="w")

        ttk_boot.Label(
            status_text_frame,
            text=status_text,
            font=("Segoe UI", 28, "bold"),
            background=status_color,
            foreground="#ffffff",
        ).pack(anchor="w", pady=(2, 0))

        # Analytics Section
        analytics_header = ttk_boot.Label(
            self.content_frame,
            text="📊 Threat Analytics",
            font=("Segoe UI", 16, "bold"),
            bootstyle="light",
        )
        analytics_header.pack(anchor="w", padx=10, pady=(10, 15))

        analytics_container = ttk_boot.Frame(self.content_frame)
        analytics_container.pack(fill="both", expand=True, padx=10, pady=(0, 25))

        # Left: Pie Chart
        chart_frame = ttk_boot.Labelframe(
            analytics_container,
            text=" Severity Distribution ",
            bootstyle="primary",
            padding=20
        )
        chart_frame.pack(side="left", padx=(0, 15), fill="both")

        self._create_pie_chart_canvas(chart_frame, risk_counts)

        # Right: Risk Counters Grid
        counters_container = ttk_boot.Frame(analytics_container)
        counters_container.pack(side="left", fill="both", expand=True)

        counter_grid = ttk_boot.Frame(counters_container)
        counter_grid.pack(expand=True)

        for idx, (risk_level, count) in enumerate([
            ("CRITICAL", risk_counts["CRITICAL"]),
            ("HIGH", risk_counts["HIGH"]),
            ("MEDIUM", risk_counts["MEDIUM"]),
            ("LOW", risk_counts["LOW"])
        ]):
            self._create_enhanced_risk_card(
                counter_grid, risk_level, count, self.color_map[risk_level]
            ).grid(row=idx // 2, column=idx % 2, padx=8, pady=8, sticky="nsew")

        counter_grid.grid_columnconfigure(0, weight=1)
        counter_grid.grid_columnconfigure(1, weight=1)
        
        # --- Recommendation Section ---
        self._create_recommendation_section(
            self.content_frame,
            mode=mode,
            is_vulnerable=is_vulnerable,
        )
        
        # Best Payload Section
        payload_header = ttk_boot.Label(
            self.content_frame,
            text="⚡ Highest Fitness Payload",
            font=("Segoe UI", 16, "bold"),
            bootstyle="light",
        )
        payload_header.pack(anchor="w", padx=10, pady=(20, 15))

        payload_container = ttk_boot.Labelframe(
            self.content_frame,
            text=f" Fitness Score: {float(best_row.get('Fitness', 0)):.4f} ",
            bootstyle="success",
            padding=20,
        )
        payload_container.pack(fill="both", expand=True, padx=10, pady=(0, 30))

        # Payload Display
        ttk_boot.Label(
            payload_container,
            text="Payload Content:",
            font=("Segoe UI", 11, "bold"),
            bootstyle="light",
        ).pack(anchor="w", pady=(0, 8))

        payload_frame = ttk_boot.Frame(payload_container, bootstyle="dark")

        payload_text = scrolledtext.ScrolledText(
            payload_frame,
            height=7,
            font=("Consolas", 10),
            wrap="word",
            bg="#2d2d30",
            fg="#d4d4d4",
            insertbackground="#ffffff",
            relief="flat",
            padx=10,
            pady=10,
        )
        payload_text.pack(fill="both", expand=True, padx=2, pady=2)
        payload_text.insert("1.0", best_row.get("Payload", "N/A"))
        payload_text.config(state="disabled")

        payload_frame.pack(fill="both", expand=True, pady=(0, 15))

        # Additional info for SQLi
        if mode.upper() == "SQLI":
            info_container = ttk_boot.Frame(payload_container)
            info_container.pack(fill="x", pady=(10, 0))

            param_name = best_row.get("Param_Name", "N/A")
            method = best_row.get("Method", "N/A")

            ttk_boot.Label(
                info_container,
                text=f"📌 Parameter: ",
                font=("Segoe UI", 10, "bold"),
                bootstyle="secondary",
            ).pack(side="left")
            ttk_boot.Label(
                info_container,
                text=param_name,
                font=("Segoe UI", 10),
                bootstyle="light",
            ).pack(side="left", padx=(0, 20))

            ttk_boot.Label(
                info_container,
                text=f"🔧 Method: ",
                font=("Segoe UI", 10, "bold"),
                bootstyle="secondary",
            ).pack(side="left")
            ttk_boot.Label(
                info_container,
                text=method,
                font=("Segoe UI", 10),
                bootstyle="light",
            ).pack(side="left")

    def _create_pie_chart_canvas(self, parent, risk_counts):
        """Draw enhanced pie chart with better styling"""
        canvas = tk.Canvas(parent, width=280, height=280, bg="#1a1d23", highlightthickness=0)
        canvas.pack(pady=10)

        total = sum(risk_counts.values())
        if total == 0:
            ttk_boot.Label(
                parent, 
                text="No vulnerability data", 
                font=("Segoe UI", 10), 
                bootstyle="secondary"
            ).pack()
            return

        colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
        }

        center_x, center_y = 140, 140
        radius = 90
        start_angle = 0

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = risk_counts[severity]
            if count == 0:
                continue

            angle = (count / total) * 359.9
            end_angle = start_angle + angle

            canvas.create_arc(
                center_x - radius, center_y - radius,
                center_x + radius, center_y + radius,
                start=start_angle, extent=angle,
                fill=colors[severity], outline=colors[severity], width=1
            )

            start_angle = end_angle

        # Center circle for donut effect
        inner_radius = 50
        canvas.create_oval(
            center_x - inner_radius, center_y - inner_radius,
            center_x + inner_radius, center_y + inner_radius,
            fill="#1a1d23", outline="#1a1d23"
        )

        # Total count in center
        canvas.create_text(
            center_x, center_y - 8,
            text=str(total),
            font=("Segoe UI", 28, "bold"),
            fill="#ffffff"
        )
        canvas.create_text(
            center_x, center_y + 18,
            text="Total",
            font=("Segoe UI", 10),
            fill="#888888"
        )
        legend = ttk_boot.Frame(parent)
        legend.pack(pady=10)
        for sev, color in colors.items():
            ttk_boot.Label(
                legend,
                text=f"■ {sev}",
                foreground=color,
                font=("Segoe UI", 9)
            ).pack(anchor="w")

    def _create_enhanced_risk_card(self, parent, title, count, color):
        """Risk card with pill-style colored label and neutral number"""
        card = ttk_boot.Frame(parent, bootstyle="dark")

        inner = tk.Frame(card, bg="#1a1d23", width=180, height=120)
        inner.pack(fill="both", expand=True)
        inner.pack_propagate(False)

        content = tk.Frame(inner, bg="#1a1d23")
        content.pack(expand=True, fill="both", padx=15, pady=12)

        # -------- PILL LABEL (Canvas-based, rounded) --------
        pill_width = 90
        pill_height = 22
        radius = pill_height // 2

        pill = tk.Canvas(
            content,
            width=pill_width,
            height=pill_height,
            bg="#1a1d23",
            highlightthickness=0
        )
        pill.pack(anchor="w", pady=(0, 6))

        # Rounded rectangle
        pill.create_arc(
            (0, 0, pill_height, pill_height),
            start=90, extent=180, fill=color, outline=color
        )
        pill.create_arc(
            (pill_width - pill_height, 0, pill_width, pill_height),
            start=270, extent=180, fill=color, outline=color
        )
        pill.create_rectangle(
            (radius, 0, pill_width - radius, pill_height),
            fill=color, outline=color
        )

        # Pill text
        pill.create_text(
            pill_width // 2,
            pill_height // 2,
            text=title,
            fill="#ffffff",
            font=("Segoe UI", 9, "bold")
        )

        # -------- NEUTRAL NUMBER --------
        ttk_boot.Label(
            content,
            text=str(count),
            font=("Segoe UI", 28, "bold"),
            bootstyle="light",
        ).pack(anchor="w", pady=(2, 0))

        return card
    
    def _create_recommendation_section(self, parent, mode, is_vulnerable):
        """
        Display simple remediation recommendations based on scan type and status.
        mode: "xss", "sqli", "both"
        is_vulnerable: bool
        """
        # Header
        rec_header = ttk_boot.Label(
            parent,
            text="🛡 Remediation Recommendations",
            font=("Segoe UI", 16, "bold"),
            bootstyle="light",
        )
        rec_header.pack(anchor="w", padx=10, pady=(10, 8))

        # Card container with subtle border
        rec_container = ttk_boot.Labelframe(
            parent,
            text=" Suggested Actions ",
            bootstyle="info",
            padding=12,
        )
        rec_container.pack(fill="both", expand=True, padx=10, pady=(0, 20))

        # Inner frame with darker background for contrast
        inner = ttk_boot.Frame(rec_container, bootstyle="dark")
        inner.pack(fill="both", expand=True)

        text_widget = tk.Text(
            inner,
            wrap="word",
            height=7,
            font=("Segoe UI", 10),
            bg="#1f232a",
            fg="#f8f9fa",
            relief="flat",
            padx=10,
            pady=10,
        )
        text_widget.pack(fill="both", expand=True)

        if not is_vulnerable:
            msg = (
                "Tidak ditemukan indikasi kerentanan pada parameter yang diuji "
                "berdasarkan skenario pengujian yang digunakan.\n\n"
                "Rekomendasi umum:\n"
                "• Tetap lakukan validasi dan sanitasi input secara konsisten.\n"
                "• Pastikan framework atau library yang digunakan selalu diperbarui.\n"
                "• Lakukan pengujian berkala dengan konfigurasi dan permukaan serangan yang lebih luas."
            )
            text_widget.insert("1.0", msg)
            text_widget.config(state="disabled")
            return

        mode_l = mode.lower()
        lines = []

        if mode_l in ("xss", "both"):
            lines.append(
                "• Kerentanan Reflected XSS terdeteksi pada permukaan input yang diuji.\n"
                "  - Terapkan validasi dan sanitasi input pada sisi server (whitelist karakter dan pola yang diperbolehkan).\n"
                "  - Gunakan output encoding yang sesuai konteks (HTML, JavaScript, atribut, URL encoding).\n"
                "  - Untuk aplikasi PHP, gunakan fungsi seperti htmlspecialchars() atau htmlentities() pada setiap output yang berasal dari input pengguna.\n"
                "  - Pertimbangkan penerapan Content Security Policy (CSP) untuk membatasi eksekusi skrip tidak tepercaya.\n"
                "  - Referensi mitigasi XSS: OWASP XSS Prevention Cheat Sheet (https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) dan CWE-79 (https://cwe.mitre.org/data/definitions/79.html).\n"
            )

        if mode_l in ("sqli", "both"):
            lines.append(
                "• Kerentanan SQL Injection terdeteksi pada permukaan input yang diuji.\n"
                "  - Selalu gunakan prepared statement atau parameterized query pada akses basis data.\n"
                "  - Hindari penyusunan query dengan cara menggabungkan string langsung dari input pengguna.\n"
                "  - Terapkan validasi input berbasis tipe dan pola (misalnya hanya menerima angka untuk ID).\n"
                "  - Batasi hak akses akun database (principle of least privilege) dan nonaktifkan pesan error SQL yang terlalu detail di lingkungan produksi.\n"
                "  - Referensi mitigasi SQL Injection: OWASP SQL Injection Prevention Cheat Sheet (https://owasp.org/www-project-cheat-sheets/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) dan CWE-89 (https://cwe.mitre.org/data/definitions/89.html).\n"
            )

        text_widget.insert("1.0", "\n".join(lines))
        text_widget.config(state="disabled")


class GAXSS_GUI(ttk_boot.Window):
    """Compact GAXSS GUI with space-efficient layout"""

    def __init__(self):
        super().__init__(themename="darkly")
        self.title("🔒 XSSQLi - Genetic Algorithm Security Scanner")
        self.geometry("1920x1080")
        self.state("zoomed")

        # Styling improvements
        self.configure(bg="#1a1d23")

        # Setup logging (internal only)
        self.log_queue = queue.Queue()
        self.setup_logging()
        self.is_scanning = False
        self.logger = logging.getLogger("GAXSS_GUI")
        self.last_scan_result = None

        # Advanced settings state
        self.show_advanced = False

        # Setup UI
        self.setup_ui()

        # Process log queue (internal)
        self.after(100, self.process_log_queue)

    def setup_logging(self):
        """Setup logging handler (internal only)"""
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

        handler = LogCapture(self.log_queue)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    def setup_ui(self):
        """Setup compact GUI interface"""

        # ============ COMPACT HEADER ============
        header = tk.Frame(self, bg="#1a1d23", height=70)
        header.pack(fill="x", padx=0, pady=0)
        header.pack_propagate(False)

        # Header gradient effect
        header_gradient = tk.Frame(header, bg="#212529", height=68)
        header_gradient.pack(fill="both", expand=True, padx=2, pady=2)

        header_content = ttk_boot.Frame(header_gradient, bootstyle="dark")
        header_content.pack(fill="both", expand=True, padx=20, pady=12)

        header_content.grid_columnconfigure(0, weight=1)
        header_content.grid_columnconfigure(1, weight=1)
        header_content.grid_columnconfigure(2, weight=1)
        tk.Frame(
            header_gradient,
            bg="#000000",
            height=1
        ).pack(fill="x", side="bottom")

        # Title section (compact)
        title_section = ttk_boot.Frame(header_content, bootstyle="dark")
        title_section.grid(row=0, column=1)

        ttk_boot.Label(
            title_section,
            text="XSSQLi Security Scanner",
            font=("Segoe UI", 18, "bold"),
            bootstyle="light",
        ).pack(anchor="center")

        # ============ MAIN WORKSPACE ============
        workspace = ttk_boot.Frame(self, bootstyle="dark")
        workspace.pack(fill="both", expand=True, padx=15, pady=10)

        # Left Panel: Configuration (compact)
        left_panel = ttk_boot.Frame(workspace, bootstyle="dark", width=350)
        left_panel.pack(side="left", fill="y", padx=(0, 12))
        left_panel.pack_propagate(False)

        config_card = ttk_boot.Labelframe(
            left_panel,
            text="  ⚙️  Configuration  ",
            bootstyle="primary",
            padding=12,
        )
        config_card.pack(fill="both", expand=True)

        # Scrollable config area
        self.config_scrollable = ttk_boot.Frame(config_card, bootstyle="dark")
        self.config_scrollable.pack(fill="both", expand=True)

        # === COMPACT CONFIG SECTIONS ===

        # 1. Scan Mode
        self._create_compact_header(self.config_scrollable, "🎯 Mode")
        mode_container = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")
        mode_container.pack(fill="x", padx=8, pady=(0, 10))

        self.mode_var = tk.StringVar(value="xss")

        modes = [
            ("XSS", "xss", "primary"),
            ("SQLi", "sqli", "primary"),
            ("BOTH", "both", "primary"),
        ]

        for text, value, style in modes:
            rb = ttk_boot.Radiobutton(
                mode_container,
                text=text,
                variable=self.mode_var,
                value=value,
                bootstyle=f"{style}-toolbutton",
            )
            rb.pack(fill="x", pady=2)

        # 2. Target Application
        self._create_compact_header(self.config_scrollable, "🎯 Target")
        app_container = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")
        app_container.pack(fill="x", padx=8, pady=(0, 10))

        self.app_var = tk.StringVar(value="dvwa")
        ttk_boot.Combobox(
            app_container,
            textvariable=self.app_var,
            values=["dvwa", "bwapp", "mutillidae", "generic"],
            state="readonly",
            font=("Segoe UI", 9),
            bootstyle="primary",
        ).pack(fill="x")

        # 3. URL + Parameters combined
        self._create_compact_header(self.config_scrollable, "🌐 Target & Params")
        url_param_container = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")
        url_param_container.pack(fill="x", padx=8, pady=(0, 10))

        ttk_boot.Label(
            url_param_container, 
            text="URL (optional):", 
            font=("Segoe UI", 8),
            bootstyle="secondary",
        ).pack(anchor="w")

        self.url_var = tk.StringVar(value="")
        ttk_boot.Entry(
            url_param_container, 
            textvariable=self.url_var, 
            font=("Segoe UI", 9)
        ).pack(fill="x", pady=(2, 8))

        self.auto_var = tk.BooleanVar(value=True)
        ttk_boot.Checkbutton(
            url_param_container,
            text="Auto-discover Parameters",
            variable=self.auto_var,
            bootstyle="success-round-toggle",
        ).pack(anchor="w", pady=(0, 6))

        ttk_boot.Label(
            url_param_container, 
            text="Manual params:", 
            font=("Segoe UI", 8),
            bootstyle="secondary",
        ).pack(anchor="w")

        self.param_var = tk.StringVar()
        ttk_boot.Entry(
            url_param_container, 
            textvariable=self.param_var, 
            font=("Segoe UI", 9)
        ).pack(fill="x")

        # 4. Security Level
        self._create_compact_header(self.config_scrollable, "🔐 Security")
        security_container = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")
        security_container.pack(fill="x", padx=8, pady=(0, 10))

        self.security_var = tk.StringVar(value="low")
        ttk_boot.Combobox(
            security_container,
            textvariable=self.security_var,
            values=["low", "medium", "high"],
            state="readonly",
            font=("Segoe UI", 9),
            bootstyle="secondary",
        ).pack(fill="x")

        # 5. Advanced Settings Toggle
        advanced_toggle_frame = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")
        advanced_toggle_frame.pack(fill="x", padx=8, pady=(5, 8))

        self.btn_advanced = ttk_boot.Button(
            advanced_toggle_frame,
            text="⚡ Advanced  ▼",
            command=self.toggle_advanced_settings,
            bootstyle="info-outline",
        )
        self.btn_advanced.pack(fill="x", ipady=6)

        # 6. GA Settings (FIXED - No walrus operator)
        self.ga_frame = ttk_boot.Frame(self.config_scrollable, bootstyle="dark")

        ga_inner = ttk_boot.Frame(self.ga_frame, bootstyle="dark")
        ga_inner.pack(fill="x", padx=8, pady=(5, 10))

        ga_grid = ttk_boot.Frame(ga_inner, bootstyle="dark")
        ga_grid.pack(fill="x")

        # FIXED: Create instance variables FIRST
        self.pop_var = tk.StringVar(value="60")
        self.gen_var = tk.StringVar(value="30")
        self.patience_var = tk.StringVar(value="10")

        # Then use them in list
        ga_params = [
            ("Pop:", self.pop_var, 10, 100),
            ("Gen:", self.gen_var, 10, 100),
            ("Pat:", self.patience_var, 3, 20),
        ]

        for idx, (label_text, var, from_val, to_val) in enumerate(ga_params):
            ttk_boot.Label(
                ga_grid, 
                text=label_text, 
                font=("Segoe UI", 9),
                bootstyle="light",
            ).grid(row=idx, column=0, sticky="w", pady=4)

            ttk_boot.Spinbox(
                ga_grid, 
                from_=from_val, 
                to=to_val, 
                textvariable=var, 
                width=12,
                font=("Segoe UI", 9),
                bootstyle="info",
            ).grid(row=idx, column=1, padx=8, pady=4, sticky="ew")

        ga_grid.grid_columnconfigure(1, weight=1)

        # Scan Button
        button_container = ttk_boot.Frame(left_panel, bootstyle="dark")
        button_container.pack(side="bottom", fill="x", pady=(8, 0))

        self.btn_scan = ttk_boot.Button(
            button_container,
            text="🚀 START SCAN",
            command=self.on_scan_click,
            bootstyle="success",
        )
        self.btn_scan.pack(fill="x", ipady=10)

        # Right Panel: Results
        right_panel = ttk_boot.Frame(workspace, bootstyle="dark")
        right_panel.pack(side="right", fill="both", expand=True)

        # Status Bar
        status_container = ttk_boot.Frame(right_panel, bootstyle="dark")
        status_container.pack(fill="x", pady=(0, 10))

        status_card = ttk_boot.Labelframe(
            status_container,
            text="  Status  ",
            bootstyle="info",
            padding=10,
        )
        status_card.pack(fill="x")

        status_inner = ttk_boot.Frame(status_card, bootstyle="dark")
        status_inner.pack(fill="x")

        self.status_label = ttk_boot.Label(
            status_inner,
            text="●  Ready",
            font=("Segoe UI", 11, "bold"),
            bootstyle="light",
        )
        self.status_label.pack(side="left", padx=8)

        self.progress = ttk_boot.Progressbar(
            status_inner, 
            mode="indeterminate", 
            bootstyle="success-striped",
            length=250,
        )
        self.progress.pack(side="right", fill="x", expand=True, padx=8)

        # Results Display
        results_container = ttk_boot.Labelframe(
            right_panel,
            text="  📊  Results  ",
            bootstyle="primary",
            padding=0,
        )
        results_container.pack(fill="both", expand=True)

        self.results_display = ModernResultsFrame(results_container, bootstyle="dark")
        self.results_display.pack(fill="both", expand=True)

        # Show initial welcome message
        self.results_display.show_initial_message()

    def toggle_advanced_settings(self):
        """Toggle visibility of advanced GA settings"""
        if self.show_advanced:
            self.ga_frame.pack_forget()
            self.btn_advanced.config(text="⚡ Advanced  ▼")
            self.show_advanced = False
        else:
            self.ga_frame.pack(fill="x", padx=8, pady=(5, 10))
            self.btn_advanced.config(text="⚡ Advanced  ▲")
            self.show_advanced = True

    def _create_compact_header(self, parent, text):
        """Create compact section headers"""
        header_frame = ttk_boot.Frame(parent, bootstyle="dark")
        header_frame.pack(fill="x", padx=8, pady=(8, 4))

        ttk_boot.Label(
            header_frame,
            text=text,
            font=("Segoe UI", 10, "bold"),
            bootstyle="light",
        ).pack(anchor="w")

        sep = tk.Frame(header_frame, bg="#404040", height=1)
        sep.pack(fill="x", pady=(4, 0))

    def process_log_queue(self):
        """Process log messages (internal only, not displayed)"""
        try:
            while True:
                try:
                    msg, level = self.log_queue.get_nowait()
                except queue.Empty:
                    break
        except Exception:
            pass
        finally:
            self.after(100, self.process_log_queue)

    def on_scan_click(self):
        """Handle scan button click"""
        if self.is_scanning:
            messagebox.showwarning(
                "Scan In Progress", 
                "A scan is currently running. Please wait for it to complete."
            )
            return

        if not self.auto_var.get() and not self.param_var.get().strip():
            messagebox.showerror(
                "Configuration Error",
                "Please enable auto-discover or manually specify parameters."
            )
            return

        try:
            pop = int(self.pop_var.get())
            gen = int(self.gen_var.get())
            patience = int(self.patience_var.get())
        except ValueError:
            messagebox.showerror(
                "Invalid Input",
                "Population, Generations, and Patience must be valid numbers."
            )
            return

        self.last_scan_result = None
        for w in self.results_display.content_frame.winfo_children():
            w.destroy()

        scanning_container = ttk_boot.Frame(self.results_display.content_frame)
        scanning_container.pack(fill="both", expand=True, padx=40, pady=80)

        ttk_boot.Label(
            scanning_container,
            text="⚙️",
            font=("Segoe UI Emoji", 72),
            bootstyle="info",
        ).pack(pady=(20, 20))

        ttk_boot.Label(
            scanning_container,
            text="Scan In Progress",
            font=("Segoe UI", 24, "bold"),
            bootstyle="light",
        ).pack()

        ttk_boot.Label(
            scanning_container,
            text="Analyzing target for vulnerabilities using genetic algorithms...",
            font=("Segoe UI", 12),
            bootstyle="secondary",
        ).pack(pady=(12, 0))

        self.is_scanning = True
        self.btn_scan.config(text="⏸️ SCANNING...", state="disabled", bootstyle="warning")
        self.status_label.config(
            text="●  Initializing Genetic Algorithm...",
            bootstyle="warning"
        )
        self.progress.start()

        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()

    def run_scan(self):
        """Run scan using GAXSS_CLI"""
        try:
            mode = self.mode_var.get()
            app = self.app_var.get()
            url = self.url_var.get().strip()
            auto = self.auto_var.get()
            param = self.param_var.get().strip() or None
            pop = int(self.pop_var.get())
            gen = int(self.gen_var.get())
            patience = int(self.patience_var.get())
            security = self.security_var.get()

            if not url:
                if app == "dvwa":
                    url = "http://127.0.0.1:8081/vulnerabilities/xss_r/" if mode == "xss" else "http://127.0.0.1:8081/vulnerabilities/sqli/"
                elif app == "bwapp":
                    url = "http://127.0.0.1:8082/xss_get.php" if mode == "xss" else "http://127.0.0.1:8082/sqli_1.php"
                elif app == "mutillidae":
                    url = "http://127.0.0.1:9000/index.php?page=user-info.php"
                else:
                    self.after(0, lambda: messagebox.showerror(
                        "Configuration Error",
                        "Generic application requires manual URL specification!"
                    ))
                    self.after(0, self.reset_ui)
                    return

            args = types.SimpleNamespace(
                mode=mode,
                url=url,
                param=param,
                auto_discover=auto,
                pop=pop,
                gen=gen,
                patience=patience,
                context="outside",
                output="results",
                username="admin",
                password="password",
                security=security,
                dvwa=(app == "dvwa"),
                bwapp=(app == "bwapp"),
                mutillidae=(app == "mutillidae"),
                generic=(app == "generic"),
                custom_url=None,
            )

            from dvwa_config import DVWAConfig
            from bwapp_config import BWAPPConfig
            from mutillidae_config import MutillidaeConfig
            from webapp_config import GenericWebApp

            if app == "dvwa":
                base_url = self._extract_base_url(url, "http://127.0.0.1:8081")
                webapp_config = DVWAConfig(
                    base_url=base_url,
                    username="admin",
                    password="password",
                    security_level=security,
                )
            elif app == "bwapp":
                base_url = self._extract_base_url(url, "http://127.0.0.1:8082")
                webapp_config = BWAPPConfig(
                    base_url=base_url,
                    username="bee",
                    password="bug",
                    security_level=security,
                )
            elif app == "mutillidae":
                base_url = self._extract_base_url(url, "http://127.0.0.1:9000")
                sec_map = {"low": "0", "medium": "1", "high": "2"}
                webapp_config = MutillidaeConfig(
                    base_url=base_url,
                    security_level=sec_map.get(security, "0"),
                )
            else:
                webapp_config = GenericWebApp(base_url=url if url else "http://localhost")

            cli = GAXSS_CLI()
            self.after(0, lambda: self.status_label.config(
                text="●  Running Genetic Algorithm..."
            ))
            if mode == "xss":
                success = cli.run_xss_test(args, webapp_config)
            elif mode == "sqli":
                success = cli.run_sqli_test(args, webapp_config)
            else:
                success_xss = cli.run_xss_test(args, webapp_config)
                success_sqli = cli.run_sqli_test(args, webapp_config)
                success = success_xss and success_sqli
            self.after(0, lambda: self.status_label.config(
                text="●  Exporting Results..."
            ))
            if success:
                self.extract_results_info()
            else:
                self.after(0, lambda: messagebox.showerror(
                    "Scan Failed",
                    "The scan failed to complete. Please check your configuration and try again."
                ))

        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            self.after(0, lambda: messagebox.showerror(
                "Critical Error",
                f"An unexpected error occurred:\n\n{str(e)}"
            ))

        finally:
            self.after(0, self.reset_ui)

    def extract_results_info(self):
        """Extract scan results from CSV files"""
        try:
            results_dir = "results"
            if not os.path.exists(results_dir):
                return

            csv_files = [f for f in os.listdir(results_dir) if f.endswith(".csv")]
            if not csv_files:
                return

            mode = self.mode_var.get()

            def load_latest(prefix):
                files = [f for f in csv_files if f.startswith(prefix)]
                if not files:
                    return None
                latest = max(
                    files,
                    key=lambda f: os.path.getmtime(os.path.join(results_dir, f))
                )
                path = os.path.join(results_dir, latest)
                with open(path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                if not rows:
                    return None
                return {"file": latest, "total": len(rows), "rows": rows}

            if mode == "both":
                xss_data = load_latest("xss_results_")
                sqli_data = load_latest("sqli_results_")
                self.last_scan_result = {
                    "xss": xss_data,
                    "sqli": sqli_data,
                    "mode": "both",
                }
            else:
                prefix = "xss_results_" if mode == "xss" else "sqli_results_"
                data = load_latest(prefix)
                if data:
                    data["mode"] = mode
                    self.last_scan_result = data

        except Exception as e:
            self.logger.error(f"Error extracting results: {e}")

    def reset_ui(self):
        """Reset UI after scan completion"""
        self.is_scanning = False
        self.btn_scan.config(
            text="🚀 START SCAN", 
            state="normal", 
            bootstyle="success"
        )
        self.status_label.config(text="●  Ready", bootstyle="secondary")
        self.progress.stop()

        if self.last_scan_result:
            for w in self.results_display.content_frame.winfo_children():
                w.destroy()

            if self.last_scan_result.get("mode") == "both":
                if self.last_scan_result.get("xss"):
                    self.results_display.display_results(
                        {
                            "file": self.last_scan_result["xss"]["file"],
                            "rows": self.last_scan_result["xss"]["rows"],
                        },
                        "xss",
                    )

                if self.last_scan_result.get("sqli"):
                    ttk_boot.Separator(
                        self.results_display.content_frame, 
                        orient="horizontal",
                        bootstyle="secondary"
                    ).pack(fill="x", padx=30, pady=30)

                    self.results_display.display_results(
                        {
                            "file": self.last_scan_result["sqli"]["file"],
                            "rows": self.last_scan_result["sqli"]["rows"],
                        },
                        "sqli",
                    )
            else:
                self.results_display.display_results(
                    self.last_scan_result, 
                    self.last_scan_result["mode"]
                )
        else:
            error_container = ttk_boot.Frame(self.results_display.content_frame)
            error_container.pack(fill="both", expand=True, padx=40, pady=80)

            ttk_boot.Label(
                error_container,
                text="❌",
                font=("Segoe UI Emoji", 64),
                bootstyle="danger",
            ).pack(pady=(20, 15))

            ttk_boot.Label(
                error_container,
                text="No Results Found",
                font=("Segoe UI", 20, "bold"),
                bootstyle="secondary",
            ).pack()

            ttk_boot.Label(
                error_container,
                text="The scan completed but no results were generated.",
                font=("Segoe UI", 11),
                bootstyle="secondary",
            ).pack(pady=(8, 0))

    @staticmethod
    def _extract_base_url(url: str, default: str = "http://localhost") -> str:
        """Extract base URL from full URL"""
        if not url or "://" not in url:
            return default

        match = re.match(r"(https?://[^/]+)", url)
        return match.group(1) if match else default


def main():
    """Main entry point"""
    app = GAXSS_GUI()
    app.mainloop()


if __name__ == "__main__":
    main()