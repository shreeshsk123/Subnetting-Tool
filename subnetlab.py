#!/usr/bin/env python3
"""
SubnetLab — IP Subnet Calculator & Network Analyzer
Pure Python 3 + tkinter. No external dependencies.
Run:  python subnetlab.py
"""

import tkinter as tk
from tkinter import ttk, font as tkfont, filedialog, messagebox
import re

# ═══════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════
BG_DARK    = "#0a0f1a"
PANEL_BG   = "#111827"
CYAN       = "#00e5ff"
ORANGE     = "#ff6b35"
GREEN      = "#39ff14"
RED        = "#ff2d55"
PURPLE     = "#bf5fff"
YELLOW     = "#ffd700"
TEXT_LIGHT = "#c8e6f5"
TEXT_DIM   = "#4a7a9b"
BORDER     = "#1e3a5f"

CLASS_COLORS = {"A": GREEN, "B": CYAN, "C": ORANGE, "D": PURPLE, "E": RED}
CLASS_BG     = {"A": "#0f2a0f", "B": "#0a1f2a", "C": "#2a1500", "D": "#1a0a2a", "E": "#2a0a0f"}

# ═══════════════════════════════════════════
# NETWORK LOGIC
# ═══════════════════════════════════════════

def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True


def parse_input(raw: str):
    """Return (ip_str, prefix_len) or raise ValueError."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty input")

    # Format: IP/CIDR
    if "/" in raw:
        parts = raw.split("/")
        ip_str = parts[0].strip()
        try:
            prefix = int(parts[1].strip())
        except ValueError:
            raise ValueError("Invalid CIDR prefix")
        if prefix < 0 or prefix > 32:
            raise ValueError("Prefix must be 0-32")
        if not validate_ip(ip_str):
            raise ValueError("Invalid IP address")
        return ip_str, prefix

    # Format: IP MASK (space separated)
    tokens = raw.split()
    if len(tokens) == 2 and validate_ip(tokens[0]) and validate_ip(tokens[1]):
        ip_str = tokens[0]
        mask_int = ip_to_int(tokens[1])
        # Validate mask: must be contiguous 1s followed by 0s
        inv = (~mask_int) & 0xFFFFFFFF
        if (inv & (inv + 1)) != 0:
            raise ValueError("Invalid subnet mask (non-contiguous)")
        prefix = bin(mask_int).count("1")
        return ip_str, prefix

    # Format: IP only → derive prefix from class
    if validate_ip(raw):
        cls = classify_ip(raw)
        return raw, cls["default_prefix"]

    raise ValueError("Unrecognised format. Use IP/CIDR, IP MASK, or just IP.")


def classify_ip(ip: str) -> dict:
    first = int(ip.split(".")[0])
    if first == 0:
        return {"class": "A", "range": "0.0.0.0 – 0.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "This Network", "special": "this_network"}
    if first == 127:
        return {"class": "A", "range": "127.0.0.0 – 127.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "Loopback", "special": "loopback"}
    if 1 <= first <= 126:
        return {"class": "A", "range": "1.0.0.0 – 126.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "Large networks (16M hosts)",
                "private_range": "10.0.0.0 – 10.255.255.255"}
    if 128 <= first <= 191:
        return {"class": "B", "range": "128.0.0.0 – 191.255.255.255",
                "default_prefix": 16, "default_mask": "255.255.0.0",
                "description": "Medium networks (65K hosts)",
                "private_range": "172.16.0.0 – 172.31.255.255"}
    if 192 <= first <= 223:
        return {"class": "C", "range": "192.0.0.0 – 223.255.255.255",
                "default_prefix": 24, "default_mask": "255.255.255.0",
                "description": "Small networks (254 hosts)",
                "private_range": "192.168.0.0 – 192.168.255.255"}
    if 224 <= first <= 239:
        return {"class": "D", "range": "224.0.0.0 – 239.255.255.255",
                "default_prefix": 4, "default_mask": "240.0.0.0",
                "description": "Multicast", "special": "multicast"}
    # 240-255
    return {"class": "E", "range": "240.0.0.0 – 255.255.255.255",
            "default_prefix": 4, "default_mask": "240.0.0.0",
            "description": "Reserved / Experimental", "special": "reserved"}


def ip_to_int(ip: str) -> int:
    octets = ip.split(".")
    return (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])


def int_to_ip(n: int) -> str:
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def cidr_to_mask(prefix: int) -> str:
    if prefix == 0:
        return "0.0.0.0"
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return int_to_ip(mask)


def wildcard_mask(prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    inv = (~mask_int) & 0xFFFFFFFF
    return int_to_ip(inv)


def calculate_network_id(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = ip_to_int(ip) & mask_int
    return int_to_ip(net)


def calculate_broadcast(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = ip_to_int(ip) & mask_int
    inv = (~mask_int) & 0xFFFFFFFF
    return int_to_ip(net | inv)


def to_binary_str(ip: str) -> str:
    return ".".join(f"{int(o):08b}" for o in ip.split("."))


def to_binary_octets(ip: str) -> list:
    return [f"{int(o):08b}" for o in ip.split(".")]


def host_id(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    host = ip_to_int(ip) & (~mask_int & 0xFFFFFFFF)
    return int_to_ip(host)


def is_private(ip: str) -> bool:
    n = ip_to_int(ip)
    # 10.0.0.0/8
    if (n >> 24) == 10:
        return True
    # 172.16.0.0/12
    if (n >> 20) == 0xAC1:
        return True
    # 192.168.0.0/16
    if (n >> 16) == 0xC0A8:
        return True
    return False


def is_loopback(ip: str) -> bool:
    return int(ip.split(".")[0]) == 127


def is_apipa(ip: str) -> bool:
    parts = ip.split(".")
    return int(parts[0]) == 169 and int(parts[1]) == 254


def is_multicast(ip: str) -> bool:
    f = int(ip.split(".")[0])
    return 224 <= f <= 239


# ═══════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════

class SubnetLab(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SubnetLab — IP Subnet Calculator")
        self.configure(bg=BG_DARK)
        self.minsize(1100, 850)

        # Center on screen
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x, y = (sw - 1100) // 2, (sh - 850) // 2
        self.geometry(f"1100x850+{x}+{y}")

        # Fonts
        self.FONT_MONO     = ("Courier New", 11)
        self.FONT_MONO_LG  = ("Courier New", 14, "bold")
        self.FONT_TITLE    = ("Arial Black", 28, "bold")
        self.FONT_LABEL    = ("Arial", 9, "bold")
        self.FONT_VALUE    = ("Courier New", 13, "bold")
        self.FONT_SMALL    = ("Courier New", 9)

        # Track current results
        self.result = None

        self._configure_styles()
        self._build_header()
        self._build_input()
        self._build_notebook()
        self._build_status_bar()

        # Bind Enter key
        self.bind("<Return>", lambda e: self._on_analyze())

    # ───────── ttk styles ─────────
    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Notebook
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BORDER, foreground=CYAN,
                         font=("Arial", 10, "bold"), padding=[14, 6])
        style.map("TNotebook.Tab",
                   background=[("selected", PANEL_BG)],
                   foreground=[("selected", CYAN)])

        # Treeview (Tab 4)
        style.configure("Subnet.Treeview",
                         background=PANEL_BG, foreground=TEXT_LIGHT,
                         fieldbackground=PANEL_BG, rowheight=28,
                         font=("Courier New", 11))
        style.configure("Subnet.Treeview.Heading",
                         background=BORDER, foreground=CYAN,
                         font=("Arial", 10, "bold"))
        style.map("Subnet.Treeview",
                   background=[("selected", BORDER)],
                   foreground=[("selected", CYAN)])

    # ───────── header ─────────
    def _build_header(self):
        hf = tk.Frame(self, bg=BG_DARK)
        hf.pack(fill="x", padx=20, pady=(18, 0))
        tk.Label(hf, text="SubnetLab", font=("Arial Black", 32, "bold"),
                 fg=CYAN, bg=BG_DARK).pack(side="left")
        tk.Label(hf, text="  IP Subnet Calculator & Network Analyzer",
                 font=("Arial", 11), fg=TEXT_DIM, bg=BG_DARK).pack(side="left", padx=(10, 0), pady=(12, 0))

    # ───────── input bar ─────────
    def _build_input(self):
        outer = tk.Frame(self, bg=BG_DARK)
        outer.pack(fill="x", padx=20, pady=(12, 6))

        inp_frame = tk.Frame(outer, bg=PANEL_BG, padx=20, pady=15)
        inp_frame.pack(fill="x")

        tk.Label(inp_frame, text="IP ADDRESS / CIDR:", fg=CYAN,
                 bg=PANEL_BG, font=("Arial", 10, "bold")).pack(side="left")

        self.entry = tk.Entry(inp_frame, width=30, bg=BG_DARK, fg=CYAN,
                              insertbackground=CYAN, font=("Courier New", 14),
                              relief="flat", highlightthickness=2,
                              highlightcolor=CYAN, highlightbackground=BORDER)
        self.entry.pack(side="left", padx=(10, 0))
        self._set_placeholder()
        self.entry.bind("<FocusIn>", self._clear_placeholder)
        self.entry.bind("<FocusOut>", self._restore_placeholder)
        self.entry.bind("<KeyRelease>", self._on_key_release)

        # Live class badge
        self.class_badge = tk.Label(inp_frame, text="", font=("Arial", 10, "bold"),
                                     bg=PANEL_BG, fg=TEXT_DIM, padx=6)
        self.class_badge.pack(side="left", padx=(6, 0))

        btn_analyze = tk.Button(inp_frame, text="ANALYZE", bg=CYAN, fg=BG_DARK,
                                 font=("Arial", 11, "bold"), padx=20, pady=6,
                                 relief="flat", cursor="hand2",
                                 activebackground="#00b8cc",
                                 command=self._on_analyze)
        btn_analyze.pack(side="left", padx=(14, 6))

        btn_clear = tk.Button(inp_frame, text="CLEAR", bg=BORDER, fg=TEXT_LIGHT,
                               font=("Arial", 11, "bold"), padx=20, pady=6,
                               relief="flat", command=self._on_clear)
        btn_clear.pack(side="left")

    def _set_placeholder(self):
        self.entry.delete(0, "end")
        self.entry.insert(0, "e.g. 192.168.1.1/24")
        self.entry.config(fg=TEXT_DIM)
        self._placeholder_active = True

    def _clear_placeholder(self, _=None):
        if getattr(self, "_placeholder_active", False):
            self.entry.delete(0, "end")
            self.entry.config(fg=CYAN)
            self._placeholder_active = False

    def _restore_placeholder(self, _=None):
        if not self.entry.get().strip():
            self._set_placeholder()

    def _on_key_release(self, _=None):
        raw = self.entry.get().strip()
        if getattr(self, "_placeholder_active", False) or not raw:
            self.class_badge.config(text="", bg=PANEL_BG)
            return
        # Try to extract IP portion for live class badge
        ip_part = raw.split("/")[0].split()[0]
        if validate_ip(ip_part):
            cls = classify_ip(ip_part)
            c = cls["class"]
            color = CLASS_COLORS.get(c, TEXT_DIM)
            self.class_badge.config(text=f" Class {c} ", fg=BG_DARK, bg=color)
        else:
            self.class_badge.config(text="", bg=PANEL_BG)

    # ───────── notebook ─────────
    def _build_notebook(self):
        self.notebook = ttk.Notebook(self, style="TNotebook")
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(4, 0))

        # Tab frames
        self.tab_dash   = tk.Frame(self.notebook, bg=BG_DARK)
        self.tab_binary = tk.Frame(self.notebook, bg=BG_DARK)
        self.tab_nh     = tk.Frame(self.notebook, bg=BG_DARK)
        self.tab_table  = tk.Frame(self.notebook, bg=BG_DARK)

        self.notebook.add(self.tab_dash,   text="  ⌂ DASHBOARD  ")
        self.notebook.add(self.tab_binary, text="  ⊕ BINARY ANALYSIS  ")
        self.notebook.add(self.tab_nh,     text="  ≡ NH PATTERN  ")
        self.notebook.add(self.tab_table,  text="  ▦ SUBNET TABLE  ")

        # Pre-build empty canvases / scrollable frames
        self._init_dashboard()
        self._init_binary()
        self._init_nh()
        self._init_table()

    # ───────── status bar ─────────
    def _build_status_bar(self):
        self.status = tk.Label(self, text="Ready", fg=TEXT_DIM, bg=BG_DARK,
                                font=("Courier New", 9), anchor="w")
        self.status.pack(fill="x", side="bottom", padx=20, pady=(0, 6))

    def _set_status(self, msg, color=TEXT_DIM):
        self.status.config(text=msg, fg=color)

    # ═══════════════════════════════════════
    # ACTIONS
    # ═══════════════════════════════════════

    def _on_analyze(self):
        raw = self.entry.get().strip()
        if getattr(self, "_placeholder_active", False) or not raw:
            self._set_status("⚠ Please enter an IP address", ORANGE)
            return
        try:
            ip, prefix = parse_input(raw)
        except ValueError as e:
            self._set_status(f"✗ {e}", RED)
            return

        mask       = cidr_to_mask(prefix)
        wc_mask    = wildcard_mask(prefix)
        net_addr   = calculate_network_id(ip, prefix)
        bcast      = calculate_broadcast(ip, prefix)
        cls_info   = classify_ip(ip)
        host_bits  = 32 - prefix
        total_hosts = 2 ** host_bits
        usable     = max(total_hosts - 2, 0) if prefix < 31 else (1 if prefix == 31 else 0)
        if prefix == 32:
            first_usable = ip
            last_usable  = ip
            usable = 1
        elif prefix == 31:
            first_usable = net_addr
            last_usable  = bcast
            usable = 2
        else:
            first_usable = int_to_ip(ip_to_int(net_addr) + 1)
            last_usable  = int_to_ip(ip_to_int(bcast) - 1)
        h_id = host_id(ip, prefix)

        self.result = {
            "ip": ip, "prefix": prefix, "mask": mask, "wildcard": wc_mask,
            "network": net_addr, "broadcast": bcast, "cls": cls_info,
            "host_bits": host_bits, "total_hosts": total_hosts,
            "usable_hosts": usable, "first_usable": first_usable,
            "last_usable": last_usable, "host_id": h_id,
        }

        self._populate_dashboard()
        self._populate_binary()
        self._populate_nh()
        self._populate_table()
        self._set_status(f"✓ Analysis complete: {ip}/{prefix}", GREEN)

    def _on_clear(self):
        self.result = None
        self._set_placeholder()
        self.class_badge.config(text="", bg=PANEL_BG)
        self._clear_dashboard()
        self._clear_binary()
        self._clear_nh()
        self._clear_table()
        self._set_status("Ready")

    # ═══════════════════════════════════════
    # TAB 1 — DASHBOARD
    # ═══════════════════════════════════════

    def _init_dashboard(self):
        # Scrollable
        canvas = tk.Canvas(self.tab_dash, bg=BG_DARK, highlightthickness=0)
        scrollbar = tk.Scrollbar(self.tab_dash, orient="vertical", command=canvas.yview)
        self.dash_inner = tk.Frame(canvas, bg=BG_DARK)
        self.dash_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.dash_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        # Mouse wheel
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        self.dash_canvas = canvas

    def _clear_dashboard(self):
        for w in self.dash_inner.winfo_children():
            w.destroy()

    def _make_card(self, parent, row, col, colspan=1, border_color=CYAN, bg=PANEL_BG, sticky="nsew", padx=5, pady=5):
        frame = tk.Frame(parent, bg=bg, padx=15, pady=12)
        frame.grid(row=row, column=col, columnspan=colspan, sticky=sticky, padx=padx, pady=pady)
        # Top border accent
        accent = tk.Frame(frame, bg=border_color, height=2)
        accent.pack(fill="x", side="top")
        return frame

    def _copy_to_clipboard(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Copied: {text}", GREEN)

    def _populate_dashboard(self):
        self._clear_dashboard()
        r = self.result
        parent = self.dash_inner

        # Make parent columns equal
        for i in range(4):
            parent.columnconfigure(i, weight=1, uniform="card")

        # ── ROW 1: 4 info cards ──
        # Card 1: IP Address
        c1 = self._make_card(parent, 0, 0, border_color=CYAN)
        tk.Label(c1, text="IP ADDRESS", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c1, text=r["ip"], fg=CYAN, bg=PANEL_BG, font=("Courier New", 16, "bold")).pack(anchor="w")

        # Card 2: IP Class
        cls_letter = r["cls"]["class"]
        cls_color = CLASS_COLORS.get(cls_letter, TEXT_DIM)
        c2 = self._make_card(parent, 0, 1, border_color=cls_color)
        tk.Label(c2, text="IP CLASS", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c2, text=cls_letter, fg=cls_color, bg=PANEL_BG, font=("Arial Black", 28, "bold")).pack(anchor="w")
        tk.Label(c2, text=r["cls"]["range"], fg=TEXT_DIM, bg=PANEL_BG, font=("Courier New", 9)).pack(anchor="w")

        # Card 3: Subnet Mask
        c3 = self._make_card(parent, 0, 2, border_color=ORANGE)
        tk.Label(c3, text="SUBNET MASK", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c3, text=r["mask"], fg=ORANGE, bg=PANEL_BG, font=("Courier New", 16, "bold")).pack(anchor="w")

        # Card 4: CIDR
        c4 = self._make_card(parent, 0, 3, border_color=GREEN)
        tk.Label(c4, text="CIDR NOTATION", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c4, text=f"/{r['prefix']}", fg=GREEN, bg=PANEL_BG, font=("Arial Black", 24, "bold")).pack(anchor="w")

        # ── ROW 2: 3 address cards ──
        parent.columnconfigure(0, weight=1)
        parent.columnconfigure(1, weight=1)
        parent.columnconfigure(2, weight=1)

        # Network Address
        c5 = self._make_card(parent, 1, 0, border_color=CYAN)
        tk.Label(c5, text="NETWORK ADDRESS (First IP)", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c5, text=r["network"], fg=CYAN, bg=PANEL_BG, font=("Courier New", 15, "bold")).pack(anchor="w")
        tk.Label(c5, text="← Network ID", fg=TEXT_DIM, bg=PANEL_BG, font=("Courier New", 9)).pack(anchor="w")

        # Broadcast Address
        c6 = self._make_card(parent, 1, 1, border_color=ORANGE)
        tk.Label(c6, text="BROADCAST ADDRESS (Last IP)", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c6, text=r["broadcast"], fg=ORANGE, bg=PANEL_BG, font=("Courier New", 15, "bold")).pack(anchor="w")
        tk.Label(c6, text="← Last address, not usable", fg=TEXT_DIM, bg=PANEL_BG, font=("Courier New", 9)).pack(anchor="w")

        # Host Count
        c7 = self._make_card(parent, 1, 2, colspan=2, border_color=YELLOW)
        tk.Label(c7, text="HOST CAPACITY", fg=TEXT_DIM, bg=PANEL_BG, font=("Arial", 8, "bold")).pack(anchor="w", pady=(4, 0))
        tk.Label(c7, text=f"{r['total_hosts']:,}", fg=YELLOW, bg=PANEL_BG, font=("Arial Black", 20, "bold")).pack(anchor="w")
        tk.Label(c7, text=f"Total: {r['total_hosts']:,}  |  Usable: {r['usable_hosts']:,}",
                 fg=TEXT_LIGHT, bg=PANEL_BG, font=("Courier New", 10)).pack(anchor="w")
        hb = r["host_bits"]
        tk.Label(c7, text=f"2^{hb} = {r['total_hosts']:,}   2^{hb}-2 = {r['usable_hosts']:,}",
                 fg=TEXT_DIM, bg=PANEL_BG, font=("Courier New", 9)).pack(anchor="w")

        # ── ROW 3: Usable Host Range (full width) ──
        c8 = tk.Frame(parent, bg="#0d1f35", padx=15, pady=15)
        c8.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)
        tk.Label(c8, text="USABLE HOST RANGE", fg=CYAN, bg="#0d1f35", font=("Arial", 11, "bold")).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 8))

        range_data = [
            ("First Usable Host", r["first_usable"], GREEN),
            ("Last Usable Host",  r["last_usable"],  ORANGE),
            ("Network ID",        r["network"],       CYAN),
            ("Host ID",           r["host_id"],       YELLOW),
        ]
        for i, (lbl, val, clr) in enumerate(range_data):
            tk.Label(c8, text=lbl, fg=TEXT_DIM, bg="#0d1f35", font=("Courier New", 10), anchor="w", width=22).grid(row=i+1, column=0, sticky="w")
            tk.Label(c8, text="→", fg=TEXT_DIM, bg="#0d1f35", font=("Courier New", 10)).grid(row=i+1, column=1, padx=4)
            tk.Label(c8, text=val, fg=clr, bg="#0d1f35", font=("Courier New", 13, "bold"), anchor="w").grid(row=i+1, column=2, sticky="w")
            btn = tk.Button(c8, text="⧉", fg=TEXT_DIM, bg="#0d1f35", font=("Arial", 10),
                            relief="flat", cursor="hand2", bd=0,
                            command=lambda v=val: self._copy_to_clipboard(v))
            btn.grid(row=i+1, column=3, padx=(8, 0))

        # ── ROW 4: IP Class Info Card ──
        cls_bg = CLASS_BG.get(cls_letter, PANEL_BG)
        c9 = tk.Frame(parent, bg=cls_bg, padx=15, pady=15)
        c9.grid(row=3, column=0, columnspan=4, sticky="nsew", padx=5, pady=5)

        left = tk.Frame(c9, bg=cls_bg)
        left.pack(side="left", fill="y", padx=(0, 20))
        tk.Label(left, text=f"CLASS {cls_letter}", fg=cls_color, bg=cls_bg,
                 font=("Arial Black", 22, "bold")).pack(anchor="w")
        tk.Label(left, text=r["cls"]["description"], fg=TEXT_LIGHT, bg=cls_bg,
                 font=("Arial", 10)).pack(anchor="w")

        # Badges
        badge_frame = tk.Frame(left, bg=cls_bg)
        badge_frame.pack(anchor="w", pady=(8, 0))
        if is_private(r["ip"]):
            tk.Label(badge_frame, text=" 🔒 PRIVATE IP ", fg=BG_DARK, bg=GREEN,
                     font=("Arial", 9, "bold"), padx=4, pady=2).pack(side="left", padx=(0, 6))
        if is_loopback(r["ip"]):
            tk.Label(badge_frame, text=" ↩ LOOPBACK ", fg=BG_DARK, bg=YELLOW,
                     font=("Arial", 9, "bold"), padx=4, pady=2).pack(side="left", padx=(0, 6))
        if is_apipa(r["ip"]):
            tk.Label(badge_frame, text=" ⚠ APIPA ", fg=BG_DARK, bg=ORANGE,
                     font=("Arial", 9, "bold"), padx=4, pady=2).pack(side="left", padx=(0, 6))
        if is_multicast(r["ip"]):
            tk.Label(badge_frame, text=" 📡 MULTICAST ", fg=BG_DARK, bg=PURPLE,
                     font=("Arial", 9, "bold"), padx=4, pady=2).pack(side="left", padx=(0, 6))

        right = tk.Frame(c9, bg=cls_bg)
        right.pack(side="left", fill="both", expand=True)

        props = [
            ("Default Mask",   r["cls"]["default_mask"]),
            ("Address Range",  r["cls"]["range"]),
            ("Use Case",       r["cls"]["description"]),
        ]
        if "private_range" in r["cls"]:
            props.insert(2, ("Private Range", r["cls"]["private_range"]))
        for i, (k, v) in enumerate(props):
            tk.Label(right, text=k, fg=TEXT_DIM, bg=cls_bg, font=("Arial", 9, "bold"),
                     anchor="w", width=16).grid(row=i, column=0, sticky="w", pady=1)
            tk.Label(right, text=v, fg=TEXT_LIGHT, bg=cls_bg, font=("Courier New", 10),
                     anchor="w").grid(row=i, column=1, sticky="w", padx=(8, 0), pady=1)

    # ═══════════════════════════════════════
    # TAB 2 — BINARY ANALYSIS
    # ═══════════════════════════════════════

    def _init_binary(self):
        canvas = tk.Canvas(self.tab_binary, bg=BG_DARK, highlightthickness=0)
        scrollbar = tk.Scrollbar(self.tab_binary, orient="vertical", command=canvas.yview)
        self.bin_inner = tk.Frame(canvas, bg=BG_DARK)
        self.bin_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.bin_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _clear_binary(self):
        for w in self.bin_inner.winfo_children():
            w.destroy()

    def _populate_binary(self):
        self._clear_binary()
        r = self.result
        parent = self.bin_inner
        prefix = r["prefix"]

        tk.Label(parent, text="BINARY BREAKDOWN & AND OPERATION", fg=CYAN, bg=BG_DARK,
                 font=("Arial", 13, "bold")).pack(anchor="w", padx=10, pady=(10, 6))

        # ── Section 1: AND operation step-by-step ──
        sec1 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=12)
        sec1.pack(fill="x", padx=10, pady=5)
        tk.Label(sec1, text="AND OPERATION — Step by Step", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 8))

        txt = tk.Text(sec1, bg=BG_DARK, fg=TEXT_LIGHT, font=("Courier New", 12),
                      height=5, relief="flat", highlightthickness=0, wrap="none",
                      padx=10, pady=8)
        txt.pack(fill="x")
        txt.tag_configure("cyan", foreground=CYAN)
        txt.tag_configure("orange", foreground=ORANGE)
        txt.tag_configure("green", foreground=GREEN)
        txt.tag_configure("dim", foreground=TEXT_DIM)
        txt.tag_configure("label", foreground=TEXT_DIM)

        ip_octets   = r["ip"].split(".")
        mask_octets = r["mask"].split(".")
        net_octets  = r["network"].split(".")

        # Row 1
        txt.insert("end", "  IP Address    :  ", "label")
        for i, o in enumerate(ip_octets):
            txt.insert("end", f"{o:>3}", "cyan")
            if i < 3: txt.insert("end", "  .  ", "dim")
        txt.insert("end", "\n")

        # Row 2
        txt.insert("end", "  Subnet Mask   :  ", "label")
        for i, o in enumerate(mask_octets):
            txt.insert("end", f"{o:>3}", "orange")
            if i < 3: txt.insert("end", "  .  ", "dim")
        txt.insert("end", "\n")

        # Separator
        txt.insert("end", "                   " + "─" * 47 + "\n", "dim")

        # Row 3
        txt.insert("end", "  AND (Network) :  ", "label")
        for i, o in enumerate(net_octets):
            txt.insert("end", f"{o:>3}", "green")
            if i < 3: txt.insert("end", "  .  ", "dim")
        txt.insert("end", "\n")
        txt.config(state="disabled")

        # ── Section 2: Octet Binary Table ──
        sec2 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=12)
        sec2.pack(fill="x", padx=10, pady=5)
        tk.Label(sec2, text="OCTET BINARY TABLE", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 8))

        grid_f = tk.Frame(sec2, bg=BG_DARK, padx=10, pady=10)
        grid_f.pack(fill="x")

        ip_bin   = to_binary_octets(r["ip"])
        mask_bin = to_binary_octets(r["mask"])
        net_bin  = to_binary_octets(r["network"])

        # Headers
        headers = ["", "Octet 1", "Octet 2", "Octet 3", "Octet 4"]
        for ci, h in enumerate(headers):
            tk.Label(grid_f, text=h, fg=CYAN, bg=BG_DARK, font=("Arial", 9, "bold"),
                     width=18 if ci > 0 else 18).grid(row=0, column=ci, padx=2, pady=(0, 6), sticky="w")

        row_labels = ["IP Address", "Subnet Mask", "AND Result", "Network (Dec)"]
        row_data   = [ip_bin, mask_bin, net_bin, r["network"].split(".")]

        for ri, (lbl, data) in enumerate(zip(row_labels, row_data)):
            tk.Label(grid_f, text=lbl, fg=TEXT_DIM, bg=BG_DARK, font=("Arial", 9, "bold"),
                     anchor="w", width=18).grid(row=ri+1, column=0, sticky="w", pady=2)
            for ci, val in enumerate(data):
                if ri == 0:
                    # IP binary: color N bits cyan, H bits orange
                    bit_frame = tk.Frame(grid_f, bg=BG_DARK)
                    bit_frame.grid(row=ri+1, column=ci+1, sticky="w", padx=2, pady=2)
                    global_start = ci * 8
                    for bi, ch in enumerate(val):
                        clr = CYAN if (global_start + bi) < prefix else ORANGE
                        tk.Label(bit_frame, text=ch, fg=clr, bg=BG_DARK,
                                 font=("Courier New", 11, "bold"), width=1).pack(side="left")
                elif ri == 1:
                    # Mask binary: 1s green, 0s orange
                    bit_frame = tk.Frame(grid_f, bg=BG_DARK)
                    bit_frame.grid(row=ri+1, column=ci+1, sticky="w", padx=2, pady=2)
                    for ch in val:
                        clr = GREEN if ch == "1" else ORANGE
                        tk.Label(bit_frame, text=ch, fg=clr, bg=BG_DARK,
                                 font=("Courier New", 11, "bold"), width=1).pack(side="left")
                elif ri == 2:
                    # AND result: N bits cyan, H bits dim
                    bit_frame = tk.Frame(grid_f, bg=BG_DARK)
                    bit_frame.grid(row=ri+1, column=ci+1, sticky="w", padx=2, pady=2)
                    global_start = ci * 8
                    for bi, ch in enumerate(val):
                        clr = CYAN if (global_start + bi) < prefix else TEXT_DIM
                        tk.Label(bit_frame, text=ch, fg=clr, bg=BG_DARK,
                                 font=("Courier New", 11, "bold"), width=1).pack(side="left")
                else:
                    # Decimal row
                    tk.Label(grid_f, text=val, fg=GREEN, bg=BG_DARK,
                             font=("Courier New", 11, "bold"), anchor="w").grid(
                                 row=ri+1, column=ci+1, sticky="w", padx=2, pady=2)

        # ── Section 3: Broadcast Derivation ──
        sec3 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=12)
        sec3.pack(fill="x", padx=10, pady=5)
        tk.Label(sec3, text="BROADCAST ADDRESS DERIVATION", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 8))

        inv_mask_int = (~ip_to_int(r["mask"])) & 0xFFFFFFFF
        inv_mask_ip  = int_to_ip(inv_mask_int)
        bcast_bin    = to_binary_str(r["broadcast"])
        net_bin_str  = to_binary_str(r["network"])
        inv_bin_str  = to_binary_str(inv_mask_ip)

        txt3 = tk.Text(sec3, bg=BG_DARK, fg=TEXT_LIGHT, font=("Courier New", 12),
                        height=6, relief="flat", highlightthickness=0, wrap="none",
                        padx=10, pady=8)
        txt3.pack(fill="x")
        txt3.tag_configure("cyan", foreground=CYAN)
        txt3.tag_configure("orange", foreground=ORANGE)
        txt3.tag_configure("green", foreground=GREEN)
        txt3.tag_configure("dim", foreground=TEXT_DIM)
        txt3.tag_configure("yellow", foreground=YELLOW)

        txt3.insert("end", "  Network ID      :  ", "dim")
        txt3.insert("end", net_bin_str + "\n", "cyan")
        txt3.insert("end", "  Inverted Mask   :  ", "dim")
        txt3.insert("end", inv_bin_str + "\n", "orange")
        txt3.insert("end", "                     " + "─" * 39 + "\n", "dim")
        txt3.insert("end", "  OR Result       :  ", "dim")
        txt3.insert("end", bcast_bin + "\n", "green")
        txt3.insert("end", "  Broadcast Addr  :  ", "dim")
        txt3.insert("end", r["broadcast"] + "\n", "orange")
        txt3.config(state="disabled")

    # ═══════════════════════════════════════
    # TAB 3 — NH PATTERN
    # ═══════════════════════════════════════

    def _init_nh(self):
        canvas = tk.Canvas(self.tab_nh, bg=BG_DARK, highlightthickness=0)
        scrollbar = tk.Scrollbar(self.tab_nh, orient="vertical", command=canvas.yview)
        self.nh_inner = tk.Frame(canvas, bg=BG_DARK)
        self.nh_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.nh_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _clear_nh(self):
        for w in self.nh_inner.winfo_children():
            w.destroy()

    def _populate_nh(self):
        self._clear_nh()
        r = self.result
        parent = self.nh_inner
        prefix = r["prefix"]
        host_bits = r["host_bits"]

        tk.Label(parent, text="NH PATTERN — NETWORK & HOST BIT DISTRIBUTION", fg=CYAN, bg=BG_DARK,
                 font=("Arial", 13, "bold")).pack(anchor="w", padx=10, pady=(10, 6))

        # ── Section 1: Visual NH pattern ──
        sec1 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=15)
        sec1.pack(fill="x", padx=10, pady=5)
        tk.Label(sec1, text="VISUAL NH BIT PATTERN", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 10))

        bits_frame = tk.Frame(sec1, bg=PANEL_BG)
        bits_frame.pack(anchor="w")

        col = 0
        for bit_idx in range(32):
            if bit_idx > 0 and bit_idx % 8 == 0:
                tk.Label(bits_frame, text=".", fg=TEXT_DIM, bg=PANEL_BG,
                         font=("Courier New", 12, "bold")).grid(row=0, column=col, padx=1)
                col += 1
            is_n = bit_idx < prefix
            ch = "N" if is_n else "H"
            bg_c = CYAN if is_n else ORANGE
            tk.Label(bits_frame, text=ch, fg=BG_DARK, bg=bg_c,
                     font=("Courier New", 10, "bold"), width=2, height=1,
                     relief="flat").grid(row=0, column=col, padx=1, pady=1)
            col += 1

        info_f = tk.Frame(sec1, bg=PANEL_BG)
        info_f.pack(anchor="w", pady=(10, 0))
        tk.Label(info_f, text=f"Network Bits (N): {prefix}", fg=CYAN, bg=PANEL_BG,
                 font=("Courier New", 11, "bold")).pack(anchor="w")
        tk.Label(info_f, text=f"Host Bits   (H): {host_bits}", fg=ORANGE, bg=PANEL_BG,
                 font=("Courier New", 11, "bold")).pack(anchor="w")

        # NH pattern string
        nh_str = ""
        for i in range(32):
            if i > 0 and i % 8 == 0:
                nh_str += "."
            nh_str += "N" if i < prefix else "H"
        tk.Label(info_f, text=f"NH Pattern: {nh_str}", fg=TEXT_LIGHT, bg=PANEL_BG,
                 font=("Courier New", 10)).pack(anchor="w", pady=(6, 0))

        # ── Section 2: Network ID and Host ID using NH ──
        sec2 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=15)
        sec2.pack(fill="x", padx=10, pady=5)
        tk.Label(sec2, text="WHAT NH PATTERN TELLS US", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 8))

        ip_bin = to_binary_str(r["ip"])
        net_bin = to_binary_str(r["network"])
        hid_bin = to_binary_str(r["host_id"])

        txt = tk.Text(sec2, bg=BG_DARK, fg=TEXT_LIGHT, font=("Courier New", 11),
                      height=15, relief="flat", highlightthickness=0, wrap="none",
                      padx=10, pady=8)
        txt.pack(fill="x")
        txt.tag_configure("cyan", foreground=CYAN)
        txt.tag_configure("orange", foreground=ORANGE)
        txt.tag_configure("green", foreground=GREEN)
        txt.tag_configure("dim", foreground=TEXT_DIM)
        txt.tag_configure("yellow", foreground=YELLOW)
        txt.tag_configure("head", foreground=TEXT_LIGHT)

        txt.insert("end", "  Using NH pattern to extract Network ID and Host ID:\n\n", "head")

        txt.insert("end", "  IP in binary   : ", "dim")
        # Color each bit
        flat_ip = ip_bin.replace(".", "")
        dot_positions = {8, 17, 26}
        char_idx = 0
        for i, ch in enumerate(ip_bin):
            if ch == ".":
                txt.insert("end", ".", "dim")
            else:
                clr = "cyan" if char_idx < prefix else "orange"
                txt.insert("end", ch, clr)
                char_idx += 1
        txt.insert("end", "\n")

        txt.insert("end", "  NH Pattern     : ", "dim")
        for i, ch in enumerate(ip_bin):
            if ch == ".":
                txt.insert("end", ".", "dim")
            else:
                bit_pos = i - ip_bin[:i].count(".")
                if bit_pos < prefix:
                    txt.insert("end", "N", "cyan")
                else:
                    txt.insert("end", "H", "orange")
        txt.insert("end", "\n\n")

        txt.insert("end", "  Network ID     : Keep all N-bits, set H-bits to 0\n", "dim")
        txt.insert("end", "               = ", "dim")
        txt.insert("end", net_bin, "cyan")
        txt.insert("end", "\n")
        txt.insert("end", f"               = {r['network']}", "green")
        txt.insert("end", "  ← This is the Network ID\n\n", "dim")

        txt.insert("end", "  Host ID        : Keep only H-bits (host portion of THIS IP)\n", "dim")
        txt.insert("end", "               = ", "dim")
        txt.insert("end", hid_bin, "orange")
        txt.insert("end", "\n")
        txt.insert("end", f"               = {r['host_id']}", "yellow")
        txt.insert("end", f"  ← This host is #{ip_to_int(r['host_id'])} in the subnet\n", "dim")
        txt.config(state="disabled")

        # ── Section 3: Pattern Legend ──
        sec3 = tk.Frame(parent, bg=PANEL_BG, padx=15, pady=15)
        sec3.pack(fill="x", padx=10, pady=5)
        tk.Label(sec3, text="PATTERN LEGEND", fg=CYAN, bg=PANEL_BG,
                 font=("Arial", 10, "bold")).pack(anchor="w", pady=(0, 8))

        legends = [
            ("N", "= Network bit (1 in mask) → Fixed, identifies the network", CYAN),
            ("H", "= Host bit (0 in mask) → Variable, identifies the host", ORANGE),
            ("", f"Total N bits = Prefix length = /{prefix}", TEXT_LIGHT),
            ("", f"Total H bits = 32 - {prefix} = {host_bits} (host space)", TEXT_LIGHT),
            ("", f"2^{host_bits} = {r['total_hosts']:,} total host addresses in this subnet", YELLOW),
        ]
        for sym, desc, clr in legends:
            row_f = tk.Frame(sec3, bg=PANEL_BG)
            row_f.pack(anchor="w", pady=1)
            if sym:
                tk.Label(row_f, text=f" {sym} ", fg=BG_DARK, bg=clr,
                         font=("Courier New", 10, "bold"), width=2).pack(side="left", padx=(0, 6))
            tk.Label(row_f, text=desc, fg=clr, bg=PANEL_BG, font=("Courier New", 10)).pack(side="left")

    # ═══════════════════════════════════════
    # TAB 4 — SUBNET TABLE
    # ═══════════════════════════════════════

    def _init_table(self):
        self.table_frame = tk.Frame(self.tab_table, bg=BG_DARK)
        self.table_frame.pack(fill="both", expand=True, padx=10, pady=10)

    def _clear_table(self):
        for w in self.table_frame.winfo_children():
            w.destroy()

    def _populate_table(self):
        self._clear_table()
        r = self.result
        prefix = r["prefix"]
        host_bits = r["host_bits"]

        # NH pattern string
        nh_str = ""
        for i in range(32):
            if i > 0 and i % 8 == 0:
                nh_str += "."
            nh_str += "N" if i < prefix else "H"

        rows = [
            ("IP Address",            r["ip"]),
            ("IP Class",              r["cls"]["class"]),
            ("Default Class Mask",    r["cls"]["default_mask"]),
            ("Subnet Mask",           r["mask"]),
            ("CIDR Notation",         f"/{prefix}"),
            ("Wildcard Mask",         r["wildcard"]),
            ("Network Address",       r["network"]),
            ("Network ID",            r["network"]),
            ("Broadcast Address",     r["broadcast"]),
            ("First Usable Host",     r["first_usable"]),
            ("Last Usable Host",      r["last_usable"]),
            ("Host ID",              r["host_id"]),
            ("Total Host Addresses",  f"{r['total_hosts']:,}"),
            ("Usable Host Addresses", f"{r['usable_hosts']:,}"),
            ("Network Bits (N)",      f"{prefix} bits"),
            ("Host Bits (H)",         f"{host_bits} bits"),
            ("NH Pattern",            nh_str),
            ("Binary IP",             to_binary_str(r["ip"])),
            ("Binary Mask",           to_binary_str(r["mask"])),
            ("Binary Network ID",     to_binary_str(r["network"])),
            ("Binary Broadcast",      to_binary_str(r["broadcast"])),
        ]

        tree = ttk.Treeview(self.table_frame, columns=("property", "value"),
                             show="headings", style="Subnet.Treeview", height=21)
        tree.heading("property", text="Property")
        tree.heading("value", text="Value")
        tree.column("property", width=260, stretch=False)
        tree.column("value", width=500)

        tree.tag_configure("odd",  background=PANEL_BG)
        tree.tag_configure("even", background="#0d1a2a")

        for i, (prop, val) in enumerate(rows):
            tag = "odd" if i % 2 == 0 else "even"
            tree.insert("", "end", values=(prop, val), tags=(tag,))

        sb = tk.Scrollbar(self.table_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._table_rows = rows  # save for export

        # Export button
        btn_f = tk.Frame(self.tab_table, bg=BG_DARK)
        btn_f.pack(fill="x", padx=10, pady=(4, 10))
        tk.Button(btn_f, text="EXPORT TO .TXT", bg=CYAN, fg=BG_DARK,
                  font=("Arial", 11, "bold"), padx=20, pady=6, relief="flat",
                  cursor="hand2", activebackground="#00b8cc",
                  command=self._export_table).pack(side="right")

    def _export_table(self):
        if not hasattr(self, "_table_rows"):
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt")],
                                             title="Export Subnet Analysis")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("  SubnetLab — Subnet Analysis Export\n")
                f.write("=" * 60 + "\n\n")
                max_key = max(len(k) for k, _ in self._table_rows)
                for k, v in self._table_rows:
                    f.write(f"  {k:<{max_key}}  │  {v}\n")
                f.write("\n" + "=" * 60 + "\n")
            self._set_status(f"✓ Exported to {path}", GREEN)
        except Exception as e:
            self._set_status(f"✗ Export failed: {e}", RED)


# ═══════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════

if __name__ == "__main__":
    app = SubnetLab()
    app.mainloop()
