import streamlit as st
import requests
import json
import re
import time
import asyncio
import aiohttp
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import defaultdict, deque
import hashlib
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from typing import Dict, List, Optional, Set, Tuple
import warnings
from bs4 import BeautifulSoup
import concurrent.futures
from dataclasses import dataclass, field
import ssl
import socket
import dns.resolver
from urllib.robotparser import RobotFileParser
import tldextract
import subprocess
import shutil
from threading import Thread
import queue
import secrets

# ============================================================================
# AUTHENTICATION IMPORTS
# ============================================================================
import os
import sqlite3
import bcrypt
import secrets
from functools import wraps
from contextlib import contextmanager


# Import our new modules (create these files separately)
DB_PATH = "security_scanner.db"
from database import init_database, UserDB, SessionDB, ActivityLog, ScanHistoryDB
# Replace the auth import section with this:
from auth import (
    init_auth, auth_guard, require_auth, require_admin,
    get_current_user, is_admin, is_authenticated, logout,
    render_logout_button, render_user_profile, render_auth_interface,
    render_login_page, render_register_page, render_forgot_password_page,
    login_user, register_user, change_user_password, reset_user_password,
    validate_email, validate_password_strength, check_maintenance_mode,
    ensure_admin_exists
)

from admin import render_admin_dashboard

warnings.filterwarnings('ignore')

# ============================================================================
# PAGE CONFIGURATION
# ============================================================================
st.set_page_config(
    page_title="Enterprise Security Scanner Pro - AI Vulnerability Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class Vulnerability:
    """Vulnerability data structure"""
    vuln_id: str
    type: str
    name: str
    severity: str
    cvss_score: float
    cwe: str
    description: str
    location: str
    evidence: str
    remediation: str
    references: List[str]
    timestamp: datetime
    confirmed: bool = False
    false_positive_risk: float = 0.0

@dataclass
class ScanResult:
    """Complete scan result"""
    scan_id: str
    target_url: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str = "running"
    pages_crawled: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    urls_discovered: Set[str] = field(default_factory=set)
    forms_found: int = 0
    parameters_tested: int = 0
    risk_score: float = 0.0
    scan_coverage: Dict = field(default_factory=dict)
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    nuclei_findings: List[Dict] = field(default_factory=list)

@dataclass
class SubdomainInfo:
    """Subdomain information"""
    subdomain: str
    ip_addresses: List[str]
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = field(default_factory=list)

@dataclass
class PortInfo:
    """Port scan information"""
    port: int
    state: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
# ============================================================================
# CUSTOM CSS STYLING - PROFESSIONAL CYBERSECURITY THEME
# ============================================================================
def apply_professional_styling():
    """Apply modern, professional cybersecurity CSS styling with loading animations"""
    st.markdown("""
        <style>
        /* ============================================ */
        /* MAIN APP STYLING - CYBERPUNK SECURITY THEME */
        /* ============================================ */
        
        /* Animated Matrix Background */
        .main {
            background: radial-gradient(circle at 50% 50%, #0a0f1e, #030614);
            position: relative;
            overflow: hidden;
        }
        
        .main::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(0deg, 
                    rgba(66, 135, 245, 0.02) 1px, 
                    transparent 1px),
                linear-gradient(90deg, 
                    rgba(66, 135, 245, 0.02) 1px, 
                    transparent 1px);
            background-size: 30px 30px;
            pointer-events: none;
            animation: matrixMove 20s linear infinite;
            z-index: 0;
        }
        
        @keyframes matrixMove {
            0% { transform: translateY(0) translateX(0); }
            100% { transform: translateY(30px) translateX(30px); }
        }
        
        /* Glowing Orb Effect */
        .main::after {
            content: '';
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle at 50% 50%, 
                rgba(66, 135, 245, 0.03) 0%, 
                rgba(103, 58, 183, 0.03) 30%, 
                transparent 70%);
            animation: rotate 60s linear infinite;
            pointer-events: none;
            z-index: 0;
        }
        
        @keyframes rotate {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        /* ============================================ */
        /* PROFESSIONAL LOADING ANIMATIONS */
        /* ============================================ */
        
        /* Fullscreen Cybersecurity Loading Overlay */
        .cyber-loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(3, 6, 20, 0.98);
            backdrop-filter: blur(20px);
            z-index: 999999;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            animation: cyberFadeIn 0.5s ease;
            border: 1px solid rgba(66, 135, 245, 0.3);
            box-shadow: 0 0 50px rgba(66, 135, 245, 0.2);
        }
        
        /* Holographic Security Scanner */
        .holographic-scanner {
            position: relative;
            width: 300px;
            height: 300px;
            margin-bottom: 30px;
        }
        
        /* Rotating Shield */
        .shield-ring {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 200px;
            height: 200px;
            border: 3px solid rgba(66, 135, 245, 0.3);
            border-radius: 50%;
            animation: rotateRing 8s linear infinite;
        }
        
        .shield-ring::before {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            right: -3px;
            bottom: -3px;
            border: 3px solid transparent;
            border-top: 3px solid #4287f5;
            border-right: 3px solid #673AB7;
            border-radius: 50%;
            animation: rotateRingReverse 4s linear infinite;
        }
        
        /* Security Lock Icon */
        .security-lock {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #4287f5, #673AB7);
            border-radius: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            animation: pulseGlow 2s ease-in-out infinite;
            box-shadow: 0 0 30px rgba(66, 135, 245, 0.5);
        }
        
        .security-lock::before {
            content: '🔒';
            font-size: 40px;
        }
        
        /* Scanning Lines */
        .scan-lines {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(66, 135, 245, 0.1) 0px,
                rgba(66, 135, 245, 0.1) 2px,
                transparent 2px,
                transparent 8px
            );
            animation: scanMove 2s linear infinite;
            pointer-events: none;
        }
        
        /* Radar Scanner */
        .radar-scanner {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 250px;
            height: 250px;
            border: 2px solid rgba(66, 135, 245, 0.2);
            border-radius: 50%;
        }
        
        .radar-scanner::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 125px;
            height: 2px;
            background: linear-gradient(90deg, #4287f5, transparent);
            transform-origin: left;
            animation: radarSweep 4s linear infinite;
        }
        
        .radar-dot {
            position: absolute;
            width: 6px;
            height: 6px;
            background: #4fc3f7;
            border-radius: 50%;
            box-shadow: 0 0 15px #4fc3f7;
            animation: radarBlip 2s ease-out infinite;
        }
        
        .radar-dot:nth-child(1) { top: 30%; left: 60%; animation-delay: 0.5s; }
        .radar-dot:nth-child(2) { top: 70%; left: 40%; animation-delay: 1.2s; }
        .radar-dot:nth-child(3) { top: 45%; left: 75%; animation-delay: 2.1s; }
        .radar-dot:nth-child(4) { top: 60%; left: 20%; animation-delay: 3.3s; }
        .radar-dot:nth-child(5) { top: 20%; left: 30%; animation-delay: 0.8s; }
        
        /* Binary Rain Effect */
        .binary-rain {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            opacity: 0.1;
            pointer-events: none;
        }
        
        .binary-rain span {
            position: absolute;
            color: #4287f5;
            font-size: 14px;
            font-family: monospace;
            animation: binaryFall 10s linear infinite;
        }
        
        /* Loading Text with Glitch Effect */
        .cyber-loading-text {
            font-size: 28px;
            font-weight: 800;
            margin-top: 20px;
            text-transform: uppercase;
            letter-spacing: 4px;
            position: relative;
            color: white;
            text-shadow: 
                0 0 10px #4287f5,
                0 0 20px #4287f5,
                0 0 40px #4287f5;
            animation: glitch 3s infinite;
        }
        
        .cyber-loading-text::before,
        .cyber-loading-text::after {
            content: attr(data-text);
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
        }
        
        .cyber-loading-text::before {
            animation: glitchTop 0.3s infinite linear alternate-reverse;
            color: #ff6b6b;
            z-index: -1;
        }
        
        .cyber-loading-text::after {
            animation: glitchBottom 0.3s infinite linear alternate-reverse;
            color: #4fc3f7;
            z-index: -2;
        }
        
        /* Status Progress Bar */
        .cyber-progress {
            width: 400px;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 2px;
            margin: 30px 0;
            position: relative;
            overflow: hidden;
            border: 1px solid rgba(66, 135, 245, 0.3);
        }
        
        .cyber-progress-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #4287f5, #673AB7, #4287f5);
            background-size: 200% 100%;
            animation: 
                progressMove 2s ease infinite,
                gradientShift 3s linear infinite;
            border-radius: 2px;
            box-shadow: 0 0 20px rgba(66, 135, 245, 0.5);
        }
        
        /* Status Dots - Matrix Style */
        .matrix-dots {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .matrix-dot {
            width: 12px;
            height: 12px;
            background: #4287f5;
            border-radius: 50%;
            animation: matrixPulse 1.5s ease-in-out infinite;
            box-shadow: 0 0 15px #4287f5;
        }
        
        .matrix-dot:nth-child(2) { animation-delay: 0.3s; background: #5a9aff; }
        .matrix-dot:nth-child(3) { animation-delay: 0.6s; background: #673AB7; }
        .matrix-dot:nth-child(4) { animation-delay: 0.9s; background: #4fc3f7; }
        .matrix-dot:nth-child(5) { animation-delay: 1.2s; background: #4287f5; }
        
        /* ============================================ */
        /* CARD STYLING - GLASS MORPHISM */
        /* ============================================ */
        
        .glass-card {
            background: rgba(15, 25, 45, 0.75);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(66, 135, 245, 0.3);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .glass-card:hover {
            border-color: #4287f5;
            box-shadow: 0 0 30px rgba(66, 135, 245, 0.2);
            transform: translateY(-2px);
        }
        
        .glass-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, 
                transparent, 
                rgba(66, 135, 245, 0.1), 
                transparent);
            transition: left 0.5s;
        }
        
        .glass-card:hover::before {
            left: 100%;
        }
        
        /* ============================================ */
        /* BUTTON STYLING - CYBER SECURITY */
        /* ============================================ */
        
        .stButton>button {
            background: linear-gradient(135deg, #4287f5, #673AB7);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 12px 30px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
            z-index: 1;
        }
        
        .stButton>button::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
            z-index: -1;
        }
        
        .stButton>button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 25px rgba(66, 135, 245, 0.6);
        }
        
        .stButton>button:hover::before {
            width: 300px;
            height: 300px;
        }
        
        .stButton>button:active {
            transform: translateY(0);
        }
        
        /* Danger Button */
        .danger-button>button {
            background: linear-gradient(135deg, #dc3545, #b02a37);
        }
        
        /* Success Button */
        .success-button>button {
            background: linear-gradient(135deg, #28a745, #1e7a34);
        }
        
        /* ============================================ */
        /* METRIC CARDS - SECURITY DASHBOARD */
        /* ============================================ */
        
        .security-metric {
            background: linear-gradient(135deg, 
                rgba(66, 135, 245, 0.15), 
                rgba(103, 58, 183, 0.15));
            border: 1px solid rgba(66, 135, 245, 0.3);
            border-radius: 12px;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        .security-metric::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: linear-gradient(135deg, #4287f5, #673AB7);
        }
        
        .metric-value {
            font-size: 32px;
            font-weight: 800;
            background: linear-gradient(135deg, #4287f5, #673AB7);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        /* ============================================ */
        /* VULNERABILITY CARDS - SEVERITY STYLES */
        /* ============================================ */
        
        .vuln-critical {
            background: linear-gradient(135deg, rgba(220, 53, 69, 0.2), rgba(176, 14, 33, 0.2));
            border-left: 5px solid #dc3545;
            border-image: repeating-linear-gradient(45deg, #dc3545, #ff6b6b) 1;
            animation: borderPulse 2s infinite;
        }
        
        .vuln-high {
            background: linear-gradient(135deg, rgba(253, 126, 20, 0.2), rgba(204, 85, 0, 0.2));
            border-left: 5px solid #fd7e14;
        }
        
        .vuln-medium {
            background: linear-gradient(135deg, rgba(255, 193, 7, 0.2), rgba(204, 153, 0, 0.2));
            border-left: 5px solid #ffc107;
        }
        
        .vuln-low {
            background: linear-gradient(135deg, rgba(23, 162, 184, 0.2), rgba(17, 122, 139, 0.2));
            border-left: 5px solid #17a2b8;
        }
        
        /* ============================================ */
        /* SCANNER ANIMATIONS */
        /* ============================================ */
        
        .scanner-active {
            position: relative;
            animation: scannerPulse 2s infinite;
        }
        
        .scanner-line {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, 
                transparent, 
                #4287f5, 
                #673AB7, 
                #4287f5, 
                transparent);
            animation: scannerMove 3s linear infinite;
        }
        
        /* ============================================ */
        /* TERMINAL STYLE LOGS */
        /* ============================================ */
        
        .terminal-log {
            background: #0a0f1e;
            border: 1px solid #4287f5;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            color: #4fc3f7;
            position: relative;
        }
        
        .terminal-log::before {
            content: '>';
            position: absolute;
            left: 5px;
            color: #28a745;
        }
        
        /* ============================================ */
        /* KEYFRAMES ANIMATIONS */
        /* ============================================ */
        
        @keyframes cyberFadeIn {
            from { opacity: 0; transform: scale(1.1); }
            to { opacity: 1; transform: scale(1); }
        }
        
        @keyframes rotateRing {
            from { transform: translate(-50%, -50%) rotate(0deg); }
            to { transform: translate(-50%, -50%) rotate(360deg); }
        }
        
        @keyframes rotateRingReverse {
            from { transform: translate(-50%, -50%) rotate(0deg); }
            to { transform: translate(-50%, -50%) rotate(-360deg); }
        }
        
        @keyframes pulseGlow {
            0%, 100% { 
                box-shadow: 0 0 30px rgba(66, 135, 245, 0.5);
                transform: translate(-50%, -50%) scale(1);
            }
            50% { 
                box-shadow: 0 0 60px rgba(66, 135, 245, 0.8);
                transform: translate(-50%, -50%) scale(1.1);
            }
        }
        
        @keyframes scanMove {
            0% { transform: translateY(-100%); }
            100% { transform: translateY(100%); }
        }
        
        @keyframes radarSweep {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        @keyframes radarBlip {
            0% { transform: scale(1); opacity: 1; }
            100% { transform: scale(3); opacity: 0; }
        }
        
        @keyframes binaryFall {
            0% { transform: translateY(-100%); opacity: 1; }
            100% { transform: translateY(1000%); opacity: 0; }
        }
        
        @keyframes glitch {
            2%, 64% { transform: translate(2px, 0) skew(0deg); }
            4%, 60% { transform: translate(-2px, 0) skew(0deg); }
            62% { transform: translate(0, 0) skew(5deg); }
        }
        
        @keyframes glitchTop {
            2%, 64% { transform: translate(2px, -2px); }
            4%, 60% { transform: translate(-2px, 2px); }
            62% { transform: translate(13px, -1px) skew(-13deg); }
        }
        
        @keyframes glitchBottom {
            2%, 64% { transform: translate(-2px, 0); }
            4%, 60% { transform: translate(-2px, 0); }
            62% { transform: translate(-22px, 5px) skew(21deg); }
        }
        
        @keyframes progressMove {
            0% { width: 0%; }
            50% { width: 70%; }
            100% { width: 100%; }
        }
        
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            100% { background-position: 200% 50%; }
        }
        
        @keyframes matrixPulse {
            0%, 100% { 
                transform: scale(1);
                box-shadow: 0 0 15px currentColor;
            }
            50% { 
                transform: scale(1.5);
                box-shadow: 0 0 30px currentColor;
            }
        }
        
        @keyframes scannerPulse {
            0%, 100% { border-color: rgba(66, 135, 245, 0.3); }
            50% { border-color: rgba(66, 135, 245, 0.8); }
        }
        
        @keyframes scannerMove {
            0% { top: -2px; }
            100% { top: 100%; }
        }
        
        @keyframes borderPulse {
            0%, 100% { border-left-color: #dc3545; }
            50% { border-left-color: #ff6b6b; }
        }
        
        /* ============================================ */
        /* RESPONSIVE DESIGN */
        /* ============================================ */
        
        @media (max-width: 768px) {
            .cyber-loading-text {
                font-size: 20px;
                letter-spacing: 2px;
            }
            
            .cyber-progress {
                width: 280px;
            }
            
            .holographic-scanner {
                width: 250px;
                height: 250px;
            }
            
            .security-lock {
                width: 60px;
                height: 60px;
            }
        }
        
        /* ============================================ */
        /* CUSTOM SCROLLBAR */
        /* ============================================ */
        
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(15, 25, 45, 0.5);
        }
        
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #4287f5, #673AB7);
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(135deg, #5a9aff, #7a4ac9);
        }
        
        /* ============================================ */
        /* SELECTION STYLING */
        /* ============================================ */
        
        ::selection {
            background: rgba(66, 135, 245, 0.3);
            color: white;
        }
        </style>
    """, unsafe_allow_html=True)
def show_cyber_loading(message="SCANNING SYSTEM", submessage="Establishing secure connection..."):
    """Display professional cybersecurity loading animation"""
    
    loading_placeholder = st.empty()
    
    # Generate random binary rain
    binary_chars = ['0', '1', '0', '1', '0', '1', '0', '1', '1', '0']
    binary_rain_html = '<div class="binary-rain">'
    for i in range(50):
        left = f"{i * 2}%"
        delay = f"{i * 0.2}s"
        duration = f"{5 + (i % 5)}s"
        char = binary_chars[i % len(binary_chars)]
        binary_rain_html += f'<span style="left: {left}; animation-delay: {delay}; animation-duration: {duration};">{char}</span>'
    binary_rain_html += '</div>'
    
    loading_html = f"""
    <div class="cyber-loading-overlay">
        {binary_rain_html}
        
        <div class="holographic-scanner">
            <div class="shield-ring"></div>
            <div class="radar-scanner">
                <div class="radar-dot"></div>
                <div class="radar-dot"></div>
                <div class="radar-dot"></div>
                <div class="radar-dot"></div>
                <div class="radar-dot"></div>
            </div>
            <div class="security-lock"></div>
            <div class="scan-lines"></div>
        </div>
        
        <div class="cyber-loading-text" data-text="{message}">
            {message}
        </div>
        
        <div style="color: #a0a0a0; font-size: 16px; margin-top: 10px; letter-spacing: 2px;">
            {submessage}
        </div>
        
        <div class="cyber-progress">
            <div class="cyber-progress-fill"></div>
        </div>
        
        <div class="matrix-dots">
            <div class="matrix-dot"></div>
            <div class="matrix-dot"></div>
            <div class="matrix-dot"></div>
            <div class="matrix-dot"></div>
            <div class="matrix-dot"></div>
        </div>
        
        <div style="color: #4fc3f7; font-family: monospace; margin-top: 30px; font-size: 14px;">
            ⚡ ENCRYPTED | SECURE | VERIFIED ⚡
        </div>
    </div>
    """
    
    loading_placeholder.markdown(loading_html, unsafe_allow_html=True)
    return loading_placeholder    

# ============================================================================
# SESSION STATE INITIALIZATION
# ============================================================================
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "current_scan" not in st.session_state:
    st.session_state.current_scan = None
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = [
        {
            "role": "assistant",
            "content": "👋 Hello! I'm your AI security assistant. I can help analyze vulnerabilities, suggest remediations, and answer security questions.",
            "timestamp": datetime.now().strftime("%H:%M")
        }
    ]
if "ollama_available" not in st.session_state:
    st.session_state.ollama_available = False
if "available_models" not in st.session_state:
    st.session_state.available_models = []
if "test_logs" not in st.session_state:
    st.session_state.test_logs = []
if "current_test" not in st.session_state:
    st.session_state.current_test = None
if "auth_token" not in st.session_state:
    st.session_state.auth_token = None
if "user_info" not in st.session_state:
    st.session_state.user_info = None
if "session_expiry" not in st.session_state:
    st.session_state.session_expiry = None
if "show_register" not in st.session_state:
    st.session_state.show_register = False

# ============================================================================
# OLLAMA CLIENT
# ============================================================================
class OllamaClient:
    """Ollama API client for AI-powered analysis"""
    
    def __init__(self, model="llama3.2", host="http://localhost:11434"):
        self.model = model
        self.host = host
        self.chat_url = f"{host}/api/chat"
        self.tags_url = f"{host}/api/tags"
        self.available = self.check_connection()
    
    def check_connection(self):
        """Check if Ollama is available"""
        try:
            response = requests.get(self.tags_url, timeout=2)
            if response.status_code == 200:
                models = response.json().get("models", [])
                st.session_state.available_models = [m["name"] for m in models]
                st.session_state.ollama_available = True
                return True
        except:
            st.session_state.ollama_available = False
        return False
    
    def chat(self, messages, temperature=0.7):
        """Send chat request to Ollama"""
        try:
            response = requests.post(
                self.chat_url,
                json={
                    "model": self.model,
                    "messages": messages,
                    "stream": False,
                    "temperature": temperature
                },
                timeout=30
            )
            if response.status_code == 200:
                return response.json()["message"]["content"]
        except Exception as e:
            st.error(f"Chat failed: {str(e)}")
        return None
    
    def analyze_vulnerability(self, vuln: Vulnerability):
        """AI-powered vulnerability analysis"""
        prompt = f"""As a senior cybersecurity analyst, provide a detailed analysis:

VULNERABILITY: {vuln.name}
TYPE: {vuln.type}
SEVERITY: {vuln.severity} (CVSS {vuln.cvss_score})
CWE: {vuln.cwe}
LOCATION: {vuln.location}
EVIDENCE: {vuln.evidence}

Provide:
1. TECHNICAL IMPACT & EXPLOITATION
2. BUSINESS RISK ASSESSMENT
3. DETAILED REMEDIATION STEPS
4. PREVENTION STRATEGIES
5. DETECTION & MONITORING

Keep response practical and actionable."""
        
        messages = [{"role": "user", "content": prompt}]
        return self.chat(messages, temperature=0.3)

# ============================================================================
# LIVE TESTING DISPLAY
# ============================================================================
class LiveTestingDisplay:
    """Real-time testing visualization with animations"""
    
    def __init__(self):
        self.test_container = None
        self.log_container = None
        self.stats_container = None
        self.current_phase = ""
        self.tests_run = 0
        self.vulnerabilities_found = 0
        
    def initialize_display(self):
        """Initialize the live display containers"""
        st.markdown("---")
        st.markdown("## 🔴 Live Testing Monitor")
        
        # Stats row
        self.stats_container = st.empty()
        
        # Current test container with wave animation
        self.test_container = st.empty()
        
        # Log container
        st.markdown("### 📋 Test Logs")
        self.log_container = st.container()
        
    def update_stats(self, phase, tests_run, vulns_found, pages_tested):
        """Update statistics display"""
        self.tests_run = tests_run
        self.vulnerabilities_found = vulns_found
        
        stats_html = f"""
        <div style="display: flex; gap: 15px; margin: 20px 0;">
            <div class="stats-mini">
                <span style="color: #4fc3f7;">Phase:</span> 
                <span style="color: white; font-weight: 600;">{phase}</span>
            </div>
            <div class="stats-mini">
                <span style="color: #4fc3f7;">Tests:</span> 
                <span style="color: white; font-weight: 600;">{tests_run}</span>
            </div>
            <div class="stats-mini">
                <span style="color: #ff6b6b;">Vulnerabilities:</span> 
                <span style="color: white; font-weight: 600;">{vulns_found}</span>
            </div>
            <div class="stats-mini">
                <span style="color: #51cf66;">Pages:</span> 
                <span style="color: white; font-weight: 600;">{pages_tested}</span>
            </div>
        </div>
        """
        self.stats_container.markdown(stats_html, unsafe_allow_html=True)
    
    def show_current_test(self, url, test_type, payload=None, status="Testing"):
        """Display current test with wave animation"""
        payload_html = ""
        if payload:
            payload_html = f'<div class="test-payload">💉 Payload: {payload[:100]}...</div>'
        
        test_html = f"""
        <div class="test-container">
            <div class="phase-indicator">⚡ {status}</div>
            <div class="test-type">🔍 {test_type}</div>
            <div class="test-url">🌐 {url}</div>
            {payload_html}
        </div>
        """
        self.test_container.markdown(test_html, unsafe_allow_html=True)
    
    def add_log(self, message, log_type="info", timestamp=True):
        """Add entry to test log"""
        icons = {
            "info": "ℹ️",
            "success": "✅",
            "warning": "⚠️",
            "error": "❌",
            "vuln": "🔴"
        }
        
        time_str = datetime.now().strftime("%H:%M:%S") if timestamp else ""
        icon = icons.get(log_type, "ℹ️")
        
        log_html = f"""
        <div class="log-entry log-{log_type}">
            {icon} [{time_str}] {message}
        </div>
        """
        
        # Add to session state logs
        st.session_state.test_logs.append(log_html)
        
        # Keep only last 50 logs
        if len(st.session_state.test_logs) > 50:
            st.session_state.test_logs = st.session_state.test_logs[-50:]
        
        # Display logs
        with self.log_container:
            for log in st.session_state.test_logs[-10:]:  # Show last 10
                st.markdown(log, unsafe_allow_html=True)
    
    def clear_logs(self):
        """Clear all logs"""
        st.session_state.test_logs = []

# ============================================================================
# SUBDOMAIN ENUMERATION
# ============================================================================
class SubdomainEnumerator:
    """Advanced subdomain enumeration"""
    
    # Common subdomains to check
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'webmail', 'smtp', 'pop', 'imap',
        'blog', 'dev', 'test', 'staging', 'api', 'mobile', 'cdn', 'static',
        'images', 'img', 'news', 'shop', 'store', 'forum', 'support', 'help',
        'portal', 'app', 'vpn', 'secure', 'ssl', 'ns1', 'ns2', 'mx', 'email',
        'direct', 'cpanel', 'whm', 'dashboard', 'panel', 'old', 'new', 'beta',
        'alpha', 'demo', 'backup', 'db', 'database', 'mysql', 'sql', 'ftp2',
        'files', 'upload', 'downloads', 'cdn1', 'cdn2', 'remote', 'proxy'
    ]
    
    @staticmethod
    def enumerate(domain: str, live_display: Optional[LiveTestingDisplay] = None) -> List[SubdomainInfo]:
        """Enumerate subdomains using multiple methods"""
        subdomains = []
        found_subdomains = set()
        
        if live_display:
            live_display.add_log(f"Starting subdomain enumeration for {domain}", "info")
        
        # Method 1: Common subdomain brute force
        if live_display:
            live_display.add_log(f"Method 1: Brute forcing {len(SubdomainEnumerator.COMMON_SUBDOMAINS)} common subdomains", "info")
        
        for sub in SubdomainEnumerator.COMMON_SUBDOMAINS:
            subdomain = f"{sub}.{domain}"
            
            if live_display:
                live_display.show_current_test(
                    subdomain,
                    "Subdomain Discovery",
                    f"Testing: {subdomain}",
                    "Resolving"
                )
                time.sleep(0.1)
            
            try:
                # DNS resolution
                answers = dns.resolver.resolve(subdomain, 'A')
                ips = [str(rdata) for rdata in answers]
                
                if ips and subdomain not in found_subdomains:
                    found_subdomains.add(subdomain)
                    
                    # Try to get HTTP info
                    status_code = None
                    title = None
                    for protocol in ['https', 'http']:
                        try:
                            url = f"{protocol}://{subdomain}"
                            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
                            status_code = response.status_code
                            
                            # Extract title
                            if 'text/html' in response.headers.get('Content-Type', ''):
                                soup = BeautifulSoup(response.content, 'html.parser')
                                title_tag = soup.find('title')
                                if title_tag:
                                    title = title_tag.text.strip()[:100]
                            break
                        except:
                            continue
                    
                    subdomain_info = SubdomainInfo(
                        subdomain=subdomain,
                        ip_addresses=ips,
                        status_code=status_code,
                        title=title
                    )
                    subdomains.append(subdomain_info)
                    
                    if live_display:
                        live_display.add_log(f"✅ Found: {subdomain} → {', '.join(ips)}", "success")
                        
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass
        
        # Method 2: Certificate Transparency Logs (crt.sh)
        if live_display:
            live_display.add_log("Method 2: Checking Certificate Transparency logs", "info")
        
        try:
            crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(crt_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(domain) and subdomain not in found_subdomains and '*' not in subdomain:
                            found_subdomains.add(subdomain)
                            
                            try:
                                answers = dns.resolver.resolve(subdomain, 'A')
                                ips = [str(rdata) for rdata in answers]
                                
                                subdomain_info = SubdomainInfo(
                                    subdomain=subdomain,
                                    ip_addresses=ips
                                )
                                subdomains.append(subdomain_info)
                                
                                if live_display:
                                    live_display.add_log(f"✅ Found (CT logs): {subdomain}", "success")
                            except:
                                pass
        except Exception as e:
            if live_display:
                live_display.add_log(f"CT logs check failed: {str(e)}", "warning")
        
        if live_display:
            live_display.add_log(f"Subdomain enumeration complete: {len(subdomains)} subdomains found", "success")
        
        return subdomains

# ============================================================================
# PORT SCANNER
# ============================================================================
class PortScanner:
    """Advanced port scanning"""
    
    # Common ports to scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888, 9090, 10000
    ]
    
    SERVICE_NAMES = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
        8000: 'HTTP-Alt', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
        8888: 'HTTP-Alt', 9090: 'HTTP-Alt', 10000: 'Webmin'
    }
    
    @staticmethod
    def scan_port(host: str, port: int, timeout: float = 1.0) -> Optional[PortInfo]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                service = PortScanner.SERVICE_NAMES.get(port, 'Unknown')
                banner = None
                
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()[:200]
                except:
                    pass
                
                sock.close()
                
                return PortInfo(
                    port=port,
                    state='open',
                    service=service,
                    banner=banner
                )
            
            sock.close()
        except:
            pass
        
        return None
    
    @staticmethod
    def scan(host: str, ports: List[int] = None, live_display: Optional[LiveTestingDisplay] = None) -> List[PortInfo]:
        """Scan multiple ports"""
        if ports is None:
            ports = PortScanner.COMMON_PORTS
        
        open_ports = []
        
        if live_display:
            live_display.add_log(f"Starting port scan on {host} ({len(ports)} ports)", "info")
        
        for idx, port in enumerate(ports):
            if live_display:
                live_display.show_current_test(
                    host,
                    f"Port Scanning ({idx+1}/{len(ports)})",
                    f"Port {port} ({PortScanner.SERVICE_NAMES.get(port, 'Unknown')})",
                    "Scanning"
                )
                time.sleep(0.05)
            
            port_info = PortScanner.scan_port(host, port, timeout=0.5)
            
            if port_info:
                open_ports.append(port_info)
                if live_display:
                    live_display.add_log(f"✅ Port {port} OPEN ({port_info.service})", "success")
        
        if live_display:
            live_display.add_log(f"Port scan complete: {len(open_ports)} open ports found", "success")
        
        return open_ports

# ============================================================================
# NMAP SCANNER (if available)
# ============================================================================
class NmapScanner:
    """Nmap integration for advanced scanning"""
    
    @staticmethod
    def is_available() -> bool:
        """Check if nmap is installed (cross-platform Windows/Linux)"""
        import platform
        import os
        
        system = platform.system().lower()
        
        # Common nmap executable names
        exe_names = ['nmap']
        if system == 'windows':
            exe_names.append('nmap.exe')
        
        # Check if in PATH first
        for exe in exe_names:
            path = shutil.which(exe)
            if path:
                return True
        
        # Platform-specific installation paths
        possible_paths = []
        
        if system == 'windows':
            possible_paths = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\nmap\nmap.exe",
                os.path.expanduser(r"~\AppData\Local\Programs\Nmap\nmap.exe"),
            ]
        elif system == 'linux':
            possible_paths = [
                "/usr/bin/nmap",
                "/usr/local/bin/nmap",
                "/opt/nmap/bin/nmap",
                os.path.expanduser("~/nmap/nmap"),
            ]
        elif system == 'darwin':  # macOS
            possible_paths = [
                "/usr/local/bin/nmap",
                "/opt/homebrew/bin/nmap",
                "/usr/bin/nmap",
            ]
        
        # Check each possible path
        for path in possible_paths:
            if os.path.exists(path):
                # Add to PATH for current session
                os.environ["PATH"] += os.pathsep + os.path.dirname(path)
                return True
        
        return False
    
    @staticmethod
    def scan(target: str, scan_type: str = 'basic', live_display: Optional[LiveTestingDisplay] = None) -> Dict:
        """Run nmap scan"""
        if not NmapScanner.is_available():
            if live_display:
                live_display.add_log("Nmap not installed, skipping", "warning")
            return {}
        
        scan_commands = {
            'basic': ['nmap', '-F', target],  # Fast scan
            'service': ['nmap', '-sV', '-F', target],  # Service version detection
            'vuln': ['nmap', '--script', 'vuln', target],  # Vulnerability scan
        }
        
        command = scan_commands.get(scan_type, scan_commands['basic'])
        
        if live_display:
            live_display.add_log(f"Running Nmap {scan_type} scan: {' '.join(command)}", "info")
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )
            
            output = result.stdout
            
            # Parse output
            open_ports = []
            for line in output.split('\n'):
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = {
                            'port': parts[0],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else 'unknown'
                        }
                        open_ports.append(port_info)
            
            if live_display:
                live_display.add_log(f"Nmap scan complete: {len(open_ports)} results", "success")
            
            return {
                'output': output,
                'ports': open_ports,
                'scan_type': scan_type
            }
            
        except subprocess.TimeoutExpired:
            if live_display:
                live_display.add_log("Nmap scan timed out", "error")
            return {}
        except Exception as e:
            if live_display:
                live_display.add_log(f"Nmap scan failed: {str(e)}", "error")
            return {}

# ============================================================================
# NUCLEI SCANNER (if available)
# ============================================================================
class NucleiScanner:
    """Nuclei integration for template-based vulnerability scanning"""
    
    @staticmethod
    def is_available() -> bool:
        """Check if nuclei is installed (cross-platform Windows/Linux)"""
        import platform
        import os
        
        system = platform.system().lower()
        
        # Common nuclei executable names
        exe_names = ['nuclei']
        if system == 'windows':
            exe_names.append('nuclei.exe')
        
        # Check if in PATH first
        for exe in exe_names:
            path = shutil.which(exe)
            if path:
                return True
        
        # Platform-specific installation paths
        possible_paths = []
        
        if system == 'windows':
            possible_paths = [
                os.path.expanduser(r"~\go\bin\nuclei.exe"),
                r"C:\Users\alame\go\bin\nuclei.exe",
                r"C:\Program Files\nuclei\nuclei.exe",
                r"C:\nuclei\nuclei.exe",
            ]
        elif system == 'linux':
            possible_paths = [
                "/usr/local/bin/nuclei",
                "/usr/bin/nuclei",
                os.path.expanduser("~/go/bin/nuclei"),
                os.path.expanduser("~/nuclei"),
            ]
        elif system == 'darwin':  # macOS
            possible_paths = [
                "/usr/local/bin/nuclei",
                "/opt/homebrew/bin/nuclei",
                os.path.expanduser("~/go/bin/nuclei"),
            ]
        
        # Check each possible path
        for path in possible_paths:
            if os.path.exists(path):
                # Add to PATH for current session
                os.environ["PATH"] += os.pathsep + os.path.dirname(path)
                return True
        
        return False
    
    @staticmethod
    def scan(target: str, severity: List[str] = None, live_display: Optional[LiveTestingDisplay] = None) -> List[Dict]:
        """Run nuclei scan"""
        if not NucleiScanner.is_available():
            if live_display:
                live_display.add_log("Nuclei not installed, skipping", "warning")
            return []
        
        if severity is None:
            severity = ['critical', 'high', 'medium']
        
        command = ['nuclei', '-u', target, '-severity', ','.join(severity), '-json']
        
        if live_display:
            live_display.add_log(f"Running Nuclei scan with severity: {', '.join(severity)}", "info")
            live_display.show_current_test(
                target,
                "Nuclei Template Scanning",
                f"Severity: {', '.join(severity)}",
                "Scanning"
            )
        
        findings = []
        
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            for line in process.stdout:
                if line.strip():
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                        
                        if live_display:
                            severity_icon = '🔴' if finding.get('severity') == 'critical' else '🟠' if finding.get('severity') == 'high' else '🟡'
                            live_display.add_log(
                                f"{severity_icon} Nuclei: {finding.get('template-id', 'unknown')} - {finding.get('info', {}).get('name', 'Unknown')}",
                                "vuln"
                            )
                    except json.JSONDecodeError:
                        pass
            
            process.wait(timeout=300)
            
            if live_display:
                live_display.add_log(f"Nuclei scan complete: {len(findings)} findings", "success")
            
        except subprocess.TimeoutExpired:
            if live_display:
                live_display.add_log("Nuclei scan timed out", "error")
            process.kill()
        except Exception as e:
            if live_display:
                live_display.add_log(f"Nuclei scan failed: {str(e)}", "error")
        
        return findings

# ============================================================================
# WEB CRAWLER
# ============================================================================
class SmartCrawler:
    """Intelligent web crawler with scope management"""
    
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 50):
        self.base_url = base_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.parameters: Dict[str, Set[str]] = defaultdict(set)
        self.domain = urlparse(base_url).netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def is_in_scope(self, url: str) -> bool:
        """Check if URL is in scan scope"""
        parsed = urlparse(url)
        return parsed.netloc == self.domain
    
    def normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)
        # Remove fragments
        url = url.split('#')[0]
        # Sort query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            sorted_params = urlencode(sorted(params.items()))
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{sorted_params}"
        return url
    
    def extract_forms(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Extract all forms from page"""
        forms = []
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'source_url': url
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        return forms
    
    def extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        """Extract all links from page"""
        links = set()
        for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe']):
            href = tag.get('href') or tag.get('src')
            if href:
                full_url = urljoin(base_url, href)
                if self.is_in_scope(full_url):
                    links.add(self.normalize_url(full_url))
        return links
    
    def crawl(self, progress_callback=None) -> Tuple[Set[str], List[Dict], Dict]:
        """Main crawling function"""
        queue = deque([(self.base_url, 0)])  # (url, depth)
        self.discovered_urls.add(self.base_url)
        
        while queue and len(self.visited_urls) < self.max_pages:
            url, depth = queue.popleft()
            
            if url in self.visited_urls or depth > self.max_depth:
                continue
            
            try:
                response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
                
                if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    self.visited_urls.add(url)
                    
                    # Parse content
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Extract forms
                    forms = self.extract_forms(soup, url)
                    self.forms.extend(forms)
                    
                    # Extract links
                    links = self.extract_links(soup, url)
                    for link in links:
                        if link not in self.visited_urls:
                            self.discovered_urls.add(link)
                            queue.append((link, depth + 1))
                    
                    # Extract parameters
                    parsed = urlparse(url)
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param, values in params.items():
                            self.parameters[param].update(values)
                    
                    if progress_callback:
                        progress_callback(len(self.visited_urls), len(self.discovered_urls))
                
            except Exception as e:
                continue
        
        return self.visited_urls, self.forms, dict(self.parameters)

# ============================================================================
# VULNERABILITY SCANNERS
# ============================================================================
class SecurityHeaderScanner:
    """Scan for missing/misconfigured security headers"""
    
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'severity': 'high',
            'cvss': 7.5,
            'cwe': 'CWE-1021',
            'description': 'Missing Content Security Policy allows XSS attacks'
        },
        'Strict-Transport-Security': {
            'severity': 'high',
            'cvss': 7.4,
            'cwe': 'CWE-319',
            'description': 'Missing HSTS header allows SSL stripping attacks'
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'cvss': 6.5,
            'cwe': 'CWE-1021',
            'description': 'Missing X-Frame-Options allows clickjacking attacks'
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'cvss': 5.3,
            'cwe': 'CWE-16',
            'description': 'Missing X-Content-Type-Options allows MIME sniffing'
        },
        'Referrer-Policy': {
            'severity': 'low',
            'cvss': 3.1,
            'cwe': 'CWE-200',
            'description': 'Missing Referrer-Policy may leak sensitive information'
        },
        'Permissions-Policy': {
            'severity': 'low',
            'cvss': 2.6,
            'cwe': 'CWE-16',
            'description': 'Missing Permissions-Policy allows unnecessary feature access'
        }
    }
    
    @staticmethod
    def scan(url: str, live_display: Optional['LiveTestingDisplay'] = None) -> List[Vulnerability]:
        """Scan security headers"""
        vulnerabilities = []
        
        if live_display:
            live_display.show_current_test(url, "Security Headers Analysis", status="Analyzing")
            live_display.add_log(f"Checking security headers for {url}", "info")
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header, info in SecurityHeaderScanner.SECURITY_HEADERS.items():
                if live_display:
                    live_display.show_current_test(url, "Security Headers", f"Checking {header}", "Testing")
                    time.sleep(0.2)  # Visual delay
                
                if header.lower() not in headers:
                    if live_display:
                        live_display.add_log(f"Missing header: {header}", "warning")
                    
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{url}{header}".encode()).hexdigest()[:12],
                        type='Missing Security Header',
                        name=f'Missing {header}',
                        severity=info['severity'],
                        cvss_score=info['cvss'],
                        cwe=info['cwe'],
                        description=info['description'],
                        location=url,
                        evidence=f'Header "{header}" not present in response',
                        remediation=f'Add {header} header with appropriate configuration',
                        references=[
                            'https://owasp.org/www-project-secure-headers/',
                            f'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}'
                        ],
                        timestamp=datetime.now(),
                        confirmed=True,
                        false_positive_risk=0.1
                    )
                    vulnerabilities.append(vuln)
                else:
                    if live_display:
                        live_display.add_log(f"Header found: {header}", "success")
            
            # Check for information disclosure
            if 'server' in headers:
                if live_display:
                    live_display.add_log(f"Server information exposed: {headers['server']}", "warning")
                
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{url}server-disclosure".encode()).hexdigest()[:12],
                    type='Information Disclosure',
                    name='Server Version Disclosure',
                    severity='low',
                    cvss_score=3.5,
                    cwe='CWE-200',
                    description='Server header reveals version information',
                    location=url,
                    evidence=f'Server: {headers["server"]}',
                    remediation='Remove or obfuscate Server header',
                    references=['https://owasp.org/www-project-web-security-testing-guide/'],
                    timestamp=datetime.now(),
                    confirmed=True,
                    false_positive_risk=0.0
                )
                vulnerabilities.append(vuln)
            
            if 'x-powered-by' in headers:
                if live_display:
                    live_display.add_log(f"Technology stack exposed: {headers['x-powered-by']}", "warning")
                
                vuln = Vulnerability(
                    vuln_id=hashlib.md5(f"{url}powered-by".encode()).hexdigest()[:12],
                    type='Information Disclosure',
                    name='Technology Stack Disclosure',
                    severity='low',
                    cvss_score=3.5,
                    cwe='CWE-200',
                    description='X-Powered-By header reveals technology stack',
                    location=url,
                    evidence=f'X-Powered-By: {headers["x-powered-by"]}',
                    remediation='Remove X-Powered-By header',
                    references=['https://owasp.org/www-project-web-security-testing-guide/'],
                    timestamp=datetime.now(),
                    confirmed=True,
                    false_positive_risk=0.0
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            if live_display:
                live_display.add_log(f"Error scanning headers: {str(e)}", "error")
        
        return vulnerabilities

class SSLTLSScanner:
    """Scan SSL/TLS configuration"""
    
    @staticmethod
    def scan(url: str) -> List[Vulnerability]:
        """Scan SSL/TLS security"""
        vulnerabilities = []
        parsed = urlparse(url)
        
        if parsed.scheme != 'https':
            vuln = Vulnerability(
                vuln_id=hashlib.md5(f"{url}no-https".encode()).hexdigest()[:12],
                type='Transport Security',
                name='No HTTPS Encryption',
                severity='critical',
                cvss_score=9.1,
                cwe='CWE-319',
                description='Website does not use HTTPS encryption',
                location=url,
                evidence='URL scheme is HTTP',
                remediation='Implement HTTPS with valid SSL/TLS certificate',
                references=['https://owasp.org/www-community/controls/SecureCommunication'],
                timestamp=datetime.now(),
                confirmed=True,
                false_positive_risk=0.0
            )
            vulnerabilities.append(vuln)
            return vulnerabilities
        
        try:
            hostname = parsed.netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (not_after - datetime.now()).days
                    
                    if days_remaining < 0:
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{url}cert-expired".encode()).hexdigest()[:12],
                            type='SSL/TLS',
                            name='Expired SSL Certificate',
                            severity='critical',
                            cvss_score=9.0,
                            cwe='CWE-295',
                            description=f'SSL certificate expired {abs(days_remaining)} days ago',
                            location=url,
                            evidence=f'Certificate expiry: {not_after}',
                            remediation='Renew SSL certificate immediately',
                            references=['https://owasp.org/www-community/vulnerabilities/Certificate_expiry'],
                            timestamp=datetime.now(),
                            confirmed=True,
                            false_positive_risk=0.0
                        )
                        vulnerabilities.append(vuln)
                    elif days_remaining < 30:
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{url}cert-expiring".encode()).hexdigest()[:12],
                            type='SSL/TLS',
                            name='Certificate Expiring Soon',
                            severity='high',
                            cvss_score=7.5,
                            cwe='CWE-295',
                            description=f'SSL certificate expires in {days_remaining} days',
                            location=url,
                            evidence=f'Certificate expiry: {not_after}',
                            remediation='Renew SSL certificate within 30 days',
                            references=['https://owasp.org/www-community/vulnerabilities/Certificate_expiry'],
                            timestamp=datetime.now(),
                            confirmed=True,
                            false_positive_risk=0.1
                        )
                        vulnerabilities.append(vuln)
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
                    cipher_name = cipher[0]
                    if any(weak in cipher_name for weak in weak_ciphers):
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{url}weak-cipher".encode()).hexdigest()[:12],
                            type='SSL/TLS',
                            name='Weak Cipher Suite',
                            severity='high',
                            cvss_score=7.4,
                            cwe='CWE-327',
                            description='Server supports weak cipher suites',
                            location=url,
                            evidence=f'Cipher: {cipher_name}',
                            remediation='Disable weak ciphers and use modern TLS 1.2+ with strong ciphers',
                            references=['https://owasp.org/www-community/vulnerabilities/Weak_SSL_TLS'],
                            timestamp=datetime.now(),
                            confirmed=True,
                            false_positive_risk=0.2
                        )
                        vulnerabilities.append(vuln)
                        
        except Exception as e:
            vuln = Vulnerability(
                vuln_id=hashlib.md5(f"{url}ssl-error".encode()).hexdigest()[:12],
                type='SSL/TLS',
                name='SSL Connection Error',
                severity='high',
                cvss_score=7.5,
                cwe='CWE-295',
                description=f'Failed to establish secure SSL connection: {str(e)}',
                location=url,
                evidence=str(e),
                remediation='Check SSL certificate configuration and validity',
                references=['https://owasp.org/www-community/vulnerabilities/SSL_Certificate_Issues'],
                timestamp=datetime.now(),
                confirmed=True,
                false_positive_risk=0.3
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities

class SQLInjectionScanner:
    """Advanced SQL injection detection"""
    
    SQL_PAYLOADS = [
        ("'", "MySQL single quote"),
        ("'--", "MySQL comment"),
        ("' OR '1'='1", "Classic OR injection"),
        ("' OR '1'='1'--", "OR injection with comment"),
        ("' UNION SELECT NULL--", "UNION injection"),
        ("admin' --", "Username bypass"),
        ("' WAITFOR DELAY '00:00:05'--", "Time-based blind (MSSQL)"),
        ("' AND SLEEP(5)--", "Time-based blind (MySQL)"),
        ("' AND 1=1--", "Boolean-based blind (true)"),
        ("' AND 1=2--", "Boolean-based blind (false)"),
    ]
    
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Microsoft SQL Server",
        r"Syntax error.*SQL",
        r"OleDb\.OleDbException",
        r"SQLite.*exception",
        r"SQLite/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Microsoft Access Driver",
        r"JET Database Engine",
        r"Access Database Engine",
    ]
    
    @staticmethod
    def scan(url: str, parameters: Dict[str, Set[str]], live_display: Optional['LiveTestingDisplay'] = None) -> List[Vulnerability]:
        """Scan for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        if not parameters:
            return vulnerabilities
        
        if live_display:
            live_display.add_log(f"Starting SQL injection tests on {len(parameters)} parameters", "info")
        
        for param, values in parameters.items():
            for payload, description in SQLInjectionScanner.SQL_PAYLOADS[:5]:  # Test subset
                try:
                    # Test GET parameter
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    if live_display:
                        live_display.show_current_test(
                            test_url, 
                            f"SQL Injection Test - {description}",
                            payload,
                            "Testing"
                        )
                        live_display.add_log(f"Testing parameter '{param}' with {description}", "info")
                        time.sleep(0.3)
                    
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False)
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors
                    for pattern in SQLInjectionScanner.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            if live_display:
                                live_display.add_log(f"🔴 SQL Injection vulnerability found in '{param}'!", "vuln")
                            
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{url}{param}{payload}".encode()).hexdigest()[:12],
                                type='SQL Injection',
                                name='Error-Based SQL Injection',
                                severity='critical',
                                cvss_score=9.8,
                                cwe='CWE-89',
                                description=f'SQL error-based injection in parameter "{param}"',
                                location=test_url,
                                evidence=f'Payload: {payload} | Pattern matched: {pattern}',
                                remediation='Use parameterized queries (prepared statements) and input validation',
                                references=[
                                    'https://owasp.org/www-community/attacks/SQL_Injection',
                                    'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
                                ],
                                timestamp=datetime.now(),
                                confirmed=True,
                                false_positive_risk=0.15
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                    # Time-based detection
                    if 'SLEEP' in payload or 'WAITFOR' in payload:
                        if response_time > 4:
                            if live_display:
                                live_display.add_log(f"🔴 Time-based SQL Injection found in '{param}' (delay: {response_time:.2f}s)", "vuln")
                            
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{url}{param}time-based".encode()).hexdigest()[:12],
                                type='SQL Injection',
                                name='Time-Based Blind SQL Injection',
                                severity='critical',
                                cvss_score=9.1,
                                cwe='CWE-89',
                                description=f'Time-based blind SQL injection in parameter "{param}"',
                                location=test_url,
                                evidence=f'Payload: {payload} | Response time: {response_time:.2f}s',
                                remediation='Use parameterized queries and implement timeout protections',
                                references=[
                                    'https://owasp.org/www-community/attacks/Blind_SQL_Injection',
                                ],
                                timestamp=datetime.now(),
                                confirmed=True,
                                false_positive_risk=0.25
                            )
                            vulnerabilities.append(vuln)
                    else:
                        if live_display:
                            live_display.add_log(f"No SQL injection detected in '{param}' with this payload", "success")
                            
                except Exception as e:
                    if live_display:
                        live_display.add_log(f"Error testing '{param}': {str(e)}", "error")
                    continue
        
        return vulnerabilities

class XSSScanner:
    """Cross-Site Scripting detection"""
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        "<input onfocus=alert('XSS') autofocus>",
    ]
    
    @staticmethod
    def scan(url: str, parameters: Dict[str, Set[str]], forms: List[Dict], live_display: Optional['LiveTestingDisplay'] = None) -> List[Vulnerability]:
        """Scan for XSS vulnerabilities"""
        vulnerabilities = []
        tested = set()
        
        if live_display:
            live_display.add_log(f"Starting XSS tests on {len(parameters)} parameters and {len(forms)} forms", "info")
        
        # Test URL parameters
        for param in parameters.keys():
            for payload in XSSScanner.XSS_PAYLOADS[:4]:  # Test subset
                try:
                    test_key = f"{url}_{param}_{payload}"
                    if test_key in tested:
                        continue
                    tested.add(test_key)
                    
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    if live_display:
                        live_display.show_current_test(
                            test_url,
                            f"XSS Test - Parameter '{param}'",
                            payload,
                            "Testing"
                        )
                        live_display.add_log(f"Testing parameter '{param}' for XSS reflection", "info")
                        time.sleep(0.3)
                    
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        if live_display:
                            live_display.add_log(f"🔴 Reflected XSS vulnerability found in '{param}'!", "vuln")
                        
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{url}{param}xss".encode()).hexdigest()[:12],
                            type='Cross-Site Scripting (XSS)',
                            name='Reflected XSS',
                            severity='high',
                            cvss_score=7.5,
                            cwe='CWE-79',
                            description=f'Reflected XSS in parameter "{param}"',
                            location=test_url,
                            evidence=f'Payload reflected: {payload[:50]}...',
                            remediation='Implement output encoding, Content-Security-Policy header, and input validation',
                            references=[
                                'https://owasp.org/www-community/attacks/xss/',
                                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
                            ],
                            timestamp=datetime.now(),
                            confirmed=True,
                            false_positive_risk=0.2
                        )
                        vulnerabilities.append(vuln)
                        break
                    else:
                        if live_display:
                            live_display.add_log(f"Payload not reflected in '{param}'", "success")
                        
                except Exception as e:
                    if live_display:
                        live_display.add_log(f"Error testing '{param}': {str(e)}", "error")
                    continue
        
        # Test forms
        for idx, form in enumerate(forms[:10]):  # Limit form testing
            if live_display:
                live_display.add_log(f"Testing form {idx+1}/{min(len(forms), 10)} at {form['action']}", "info")
            
            for input_field in form['inputs']:
                if not input_field['name']:
                    continue
                    
                for payload in XSSScanner.XSS_PAYLOADS[:3]:
                    try:
                        test_key = f"{form['action']}_{input_field['name']}_{payload}"
                        if test_key in tested:
                            continue
                        tested.add(test_key)
                        
                        if live_display:
                            live_display.show_current_test(
                                form['action'],
                                f"XSS Test - Form Field '{input_field['name']}'",
                                payload,
                                "Testing"
                            )
                            time.sleep(0.3)
                        
                        form_data = {inp['name']: inp['value'] for inp in form['inputs'] if inp['name']}
                        form_data[input_field['name']] = payload
                        
                        if form['method'] == 'POST':
                            response = requests.post(form['action'], data=form_data, timeout=10, verify=False)
                        else:
                            response = requests.get(form['action'], params=form_data, timeout=10, verify=False)
                        
                        if payload in response.text:
                            if live_display:
                                live_display.add_log(f"🔴 XSS vulnerability found in form field '{input_field['name']}'!", "vuln")
                            
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{form['action']}{input_field['name']}xss".encode()).hexdigest()[:12],
                                type='Cross-Site Scripting (XSS)',
                                name='Reflected XSS in Form',
                                severity='high',
                                cvss_score=7.5,
                                cwe='CWE-79',
                                description=f'Reflected XSS in form field "{input_field["name"]}"',
                                location=form['action'],
                                evidence=f'Form: {form["source_url"]} | Payload: {payload[:50]}...',
                                remediation='Implement output encoding and CSP',
                                references=['https://owasp.org/www-community/attacks/xss/'],
                                timestamp=datetime.now(),
                                confirmed=True,
                                false_positive_risk=0.2
                            )
                            vulnerabilities.append(vuln)
                            break
                            
                    except Exception as e:
                        if live_display:
                            live_display.add_log(f"Error testing form: {str(e)}", "error")
                        continue
        
        return vulnerabilities

class CommandInjectionScanner:
    """OS Command injection detection"""
    
    COMMAND_PAYLOADS = [
        ("; ls", "Command chaining"),
        ("| whoami", "Pipe operator"),
        ("& echo test &", "Background execution"),
        ("`id`", "Command substitution"),
        ("$(whoami)", "Command substitution"),
        ("; ping -c 5 127.0.0.1", "Time-based detection"),
    ]
    
    COMMAND_PATTERNS = [
        r"uid=\d+",  # Unix user ID
        r"gid=\d+",  # Unix group ID
        r"root:x:",  # /etc/passwd
        r"bin/bash", # Shell path
        r"Microsoft Windows", # Windows version
        r"Volume Serial Number", # Windows dir
    ]
    
    @staticmethod
    def scan(url: str, parameters: Dict[str, Set[str]]) -> List[Vulnerability]:
        """Scan for command injection"""
        vulnerabilities = []
        
        for param in parameters.keys():
            for payload, description in CommandInjectionScanner.COMMAND_PAYLOADS[:3]:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    start_time = time.time()
                    response = requests.get(test_url, timeout=10, verify=False)
                    response_time = time.time() - start_time
                    
                    # Check for command output
                    for pattern in CommandInjectionScanner.COMMAND_PATTERNS:
                        if re.search(pattern, response.text):
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{url}{param}cmdinj".encode()).hexdigest()[:12],
                                type='Command Injection',
                                name='OS Command Injection',
                                severity='critical',
                                cvss_score=9.8,
                                cwe='CWE-78',
                                description=f'OS command injection in parameter "{param}"',
                                location=test_url,
                                evidence=f'Payload: {payload} | Pattern matched: {pattern}',
                                remediation='Avoid system calls, use safe APIs, implement input validation and whitelisting',
                                references=['https://owasp.org/www-community/attacks/Command_Injection'],
                                timestamp=datetime.now(),
                                confirmed=True,
                                false_positive_risk=0.2
                            )
                            vulnerabilities.append(vuln)
                            break
                    
                    # Time-based detection
                    if 'ping' in payload and response_time > 4:
                        vuln = Vulnerability(
                            vuln_id=hashlib.md5(f"{url}{param}cmdtime".encode()).hexdigest()[:12],
                            type='Command Injection',
                            name='Time-Based Command Injection',
                            severity='critical',
                            cvss_score=9.8,
                            cwe='CWE-78',
                            description=f'Time-based command injection in parameter "{param}"',
                            location=test_url,
                            evidence=f'Payload: {payload} | Response time: {response_time:.2f}s',
                            remediation='Avoid system calls, use safe APIs',
                            references=['https://owasp.org/www-community/attacks/Command_Injection'],
                            timestamp=datetime.now(),
                            confirmed=True,
                            false_positive_risk=0.3
                        )
                        vulnerabilities.append(vuln)
                        
                except Exception:
                    continue
        
        return vulnerabilities

class PathTraversalScanner:
    """Path traversal/LFI detection"""
    
    TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    
    TRAVERSAL_PATTERNS = [
        r"root:x:\d+:\d+",  # /etc/passwd
        r"\[extensions\]",  # win.ini
        r"\[fonts\]",       # win.ini
    ]
    
    @staticmethod
    def scan(url: str, parameters: Dict[str, Set[str]]) -> List[Vulnerability]:
        """Scan for path traversal"""
        vulnerabilities = []
        
        for param in parameters.keys():
            for payload in PathTraversalScanner.TRAVERSAL_PAYLOADS[:2]:
                try:
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                    
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    for pattern in PathTraversalScanner.TRAVERSAL_PATTERNS:
                        if re.search(pattern, response.text):
                            vuln = Vulnerability(
                                vuln_id=hashlib.md5(f"{url}{param}lfi".encode()).hexdigest()[:12],
                                type='Path Traversal',
                                name='Local File Inclusion (LFI)',
                                severity='critical',
                                cvss_score=8.6,
                                cwe='CWE-22',
                                description=f'Path traversal vulnerability in parameter "{param}"',
                                location=test_url,
                                evidence=f'Payload: {payload} | Pattern matched: {pattern}',
                                remediation='Implement path validation, use whitelisting, avoid file operations based on user input',
                                references=['https://owasp.org/www-community/attacks/Path_Traversal'],
                                timestamp=datetime.now(),
                                confirmed=True,
                                false_positive_risk=0.15
                            )
                            vulnerabilities.append(vuln)
                            break
                            
                except Exception:
                    continue
        
        return vulnerabilities

# ============================================================================
# MAIN SCANNER ENGINE
# ============================================================================
class EnterpriseScanner:
    """Main scanning engine orchestrating all tests"""
    
    def __init__(self, target_url: str, max_depth: int = 3, max_pages: int = 50, 
                 enable_subdomain: bool = False, enable_port_scan: bool = False,
                 enable_nmap: bool = False, enable_nuclei: bool = False):
        self.target_url = target_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.enable_subdomain = enable_subdomain
        self.enable_port_scan = enable_port_scan
        self.enable_nmap = enable_nmap
        self.enable_nuclei = enable_nuclei
        self.scan_result = ScanResult(
            scan_id=hashlib.md5(f"{target_url}{datetime.now()}".encode()).hexdigest()[:8],
            target_url=target_url,
            start_time=datetime.now()
        )
    
    def run_scan(self, progress_bar, status_text, live_display: Optional[LiveTestingDisplay] = None):
        """Execute complete security scan"""
        
        tests_run = 0
        vulns_found = 0
        
        # Clear previous logs
        if live_display:
            live_display.clear_logs()
            live_display.add_log("🚀 Starting comprehensive security scan...", "info")
        
        # Extract domain for advanced scans
        parsed = urlparse(self.target_url)
        domain = parsed.netloc
        hostname = domain.split(':')[0]  # Remove port if present
        
        # Phase 0: Advanced Reconnaissance (if enabled)
        phase_offset = 0.0
        total_phases = 6
        
        if self.enable_subdomain or self.enable_port_scan or self.enable_nmap or self.enable_nuclei:
            total_phases += 1
            
            status_text.text("🔍 Phase 0/6: Advanced Reconnaissance...")
            if live_display:
                live_display.add_log("=" * 50, "info")
                live_display.add_log("PHASE 0: ADVANCED RECONNAISSANCE", "info")
                live_display.add_log("=" * 50, "info")
            
            # Subdomain enumeration
            if self.enable_subdomain:
                if live_display:
                    live_display.add_log("Starting subdomain enumeration...", "info")
                
                subdomains = SubdomainEnumerator.enumerate(hostname, live_display)
                self.scan_result.subdomains = [s.subdomain for s in subdomains]
                
                progress_bar.progress(0.05)
            
            # Port scanning
            if self.enable_port_scan:
                if live_display:
                    live_display.add_log("Starting port scan...", "info")
                
                open_ports = PortScanner.scan(hostname, live_display=live_display)
                self.scan_result.open_ports = [
                    {
                        'port': p.port,
                        'state': p.state,
                        'service': p.service,
                        'banner': p.banner
                    } for p in open_ports
                ]
                
                progress_bar.progress(0.08)
            
            # Nmap scan
            if self.enable_nmap:
                if live_display:
                    live_display.add_log("Starting Nmap scan...", "info")
                
                nmap_result = NmapScanner.scan(hostname, 'service', live_display)
                if nmap_result:
                    self.scan_result.scan_coverage['nmap'] = nmap_result
                
                progress_bar.progress(0.10)
            
            # Nuclei scan
            if self.enable_nuclei:
                if live_display:
                    live_display.add_log("Starting Nuclei scan...", "info")
                
                nuclei_findings = NucleiScanner.scan(self.target_url, live_display=live_display)
                self.scan_result.nuclei_findings = nuclei_findings
                
                # Convert nuclei findings to vulnerabilities
                for finding in nuclei_findings:
                    severity_map = {
                        'critical': ('critical', 9.0),
                        'high': ('high', 7.0),
                        'medium': ('medium', 5.0),
                        'low': ('low', 3.0)
                    }
                    
                    sev, cvss = severity_map.get(finding.get('severity', 'medium'), ('medium', 5.0))
                    
                    vuln = Vulnerability(
                        vuln_id=hashlib.md5(f"{finding.get('template-id', '')}{self.target_url}".encode()).hexdigest()[:12],
                        type='Nuclei Template',
                        name=finding.get('info', {}).get('name', 'Unknown'),
                        severity=sev,
                        cvss_score=cvss,
                        cwe='CWE-unknown',
                        description=finding.get('info', {}).get('description', 'Detected by Nuclei'),
                        location=finding.get('matched-at', self.target_url),
                        evidence=f"Template: {finding.get('template-id', 'unknown')}",
                        remediation=finding.get('info', {}).get('remediation', 'Review Nuclei template for details'),
                        references=finding.get('info', {}).get('reference', []),
                        timestamp=datetime.now(),
                        confirmed=True,
                        false_positive_risk=0.1
                    )
                    self.scan_result.vulnerabilities.append(vuln)
                
                progress_bar.progress(0.12)
                vulns_found = len(self.scan_result.vulnerabilities)
            
            phase_offset = 0.12
        
        # Phase 1: Crawling
        status_text.text("🕷️ Phase 1/6: Crawling website...")
        if live_display:
            live_display.update_stats("Crawling", tests_run, vulns_found, 0)
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 1: WEB CRAWLING", "info")
            live_display.add_log("=" * 50, "info")
        
        crawler = SmartCrawler(self.target_url, self.max_depth, self.max_pages)
        
        def crawl_progress(visited, discovered):
            progress = min(visited / self.max_pages, 1.0)
            progress_bar.progress(phase_offset + progress * 0.15)
            status_text.text(f"🕷️ Crawling: {visited} pages visited, {discovered} URLs discovered")
            if live_display:
                live_display.update_stats("Crawling", tests_run, vulns_found, visited)
                if visited % 5 == 0:  # Log every 5 pages
                    live_display.add_log(f"Crawled {visited} pages, discovered {discovered} URLs", "info")
        
        urls, forms, parameters = crawler.crawl(crawl_progress)
        self.scan_result.urls_discovered = urls
        self.scan_result.pages_crawled = len(urls)
        self.scan_result.forms_found = len(forms)
        self.scan_result.parameters_tested = len(parameters)
        
        if live_display:
            live_display.add_log(f"✅ Crawling complete: {len(urls)} pages, {len(forms)} forms, {len(parameters)} parameters", "success")
        
        # Phase 2: Security Headers
        status_text.text("🛡️ Phase 2/6: Analyzing security headers...")
        progress_bar.progress(phase_offset + 0.20)
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 2: SECURITY HEADERS", "info")
            live_display.add_log("=" * 50, "info")
            live_display.update_stats("Security Headers", tests_run, vulns_found, len(urls))
        
        header_vulns = SecurityHeaderScanner.scan(self.target_url, live_display)
        self.scan_result.vulnerabilities.extend(header_vulns)
        tests_run += 7  # Number of headers checked
        vulns_found = len(self.scan_result.vulnerabilities)
        
        # Phase 3: SSL/TLS
        status_text.text("🔐 Phase 3/6: Testing SSL/TLS configuration...")
        progress_bar.progress(phase_offset + 0.35)
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 3: SSL/TLS SECURITY", "info")
            live_display.add_log("=" * 50, "info")
            live_display.update_stats("SSL/TLS", tests_run, vulns_found, len(urls))
        
        ssl_vulns = SSLTLSScanner.scan(self.target_url)
        self.scan_result.vulnerabilities.extend(ssl_vulns)
        tests_run += 3
        vulns_found = len(self.scan_result.vulnerabilities)
        
        # Phase 4: SQL Injection
        status_text.text("💉 Phase 4/6: Testing for SQL injection...")
        progress_bar.progress(phase_offset + 0.50)
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 4: SQL INJECTION TESTING", "info")
            live_display.add_log("=" * 50, "info")
            live_display.update_stats("SQL Injection", tests_run, vulns_found, len(urls))
        
        for idx, url in enumerate(list(urls)[:10]):  # Test subset of URLs
            sql_vulns = SQLInjectionScanner.scan(url, parameters, live_display)
            self.scan_result.vulnerabilities.extend(sql_vulns)
            tests_run += len(parameters) * 5  # payloads per param
            vulns_found = len(self.scan_result.vulnerabilities)
            if live_display and (idx + 1) % 3 == 0:
                live_display.update_stats("SQL Injection", tests_run, vulns_found, len(urls))
        
        # Phase 5: XSS
        status_text.text("⚡ Phase 5/6: Testing for Cross-Site Scripting...")
        progress_bar.progress(phase_offset + 0.65)
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 5: CROSS-SITE SCRIPTING (XSS)", "info")
            live_display.add_log("=" * 50, "info")
            live_display.update_stats("XSS Testing", tests_run, vulns_found, len(urls))
        
        for idx, url in enumerate(list(urls)[:10]):
            xss_vulns = XSSScanner.scan(url, parameters, forms, live_display)
            self.scan_result.vulnerabilities.extend(xss_vulns)
            tests_run += len(parameters) * 4 + len(forms) * 3
            vulns_found = len(self.scan_result.vulnerabilities)
            if live_display and (idx + 1) % 3 == 0:
                live_display.update_stats("XSS Testing", tests_run, vulns_found, len(urls))
        
        # Phase 6: Command Injection & Path Traversal
        status_text.text("🔍 Phase 6/6: Testing for command injection and path traversal...")
        progress_bar.progress(phase_offset + 0.80)
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("PHASE 6: COMMAND INJECTION & PATH TRAVERSAL", "info")
            live_display.add_log("=" * 50, "info")
            live_display.update_stats("Advanced Tests", tests_run, vulns_found, len(urls))
        
        for url in list(urls)[:5]:
            cmd_vulns = CommandInjectionScanner.scan(url, parameters)
            path_vulns = PathTraversalScanner.scan(url, parameters)
            self.scan_result.vulnerabilities.extend(cmd_vulns)
            self.scan_result.vulnerabilities.extend(path_vulns)
            tests_run += len(parameters) * 5
            vulns_found = len(self.scan_result.vulnerabilities)
        
        # Finalize
        progress_bar.progress(1.0)
        status_text.text("✅ Scan completed!")
        
        if live_display:
            live_display.add_log("=" * 50, "info")
            live_display.add_log("SCAN COMPLETED", "success")
            live_display.add_log("=" * 50, "info")
            live_display.add_log(f"Total tests run: {tests_run}", "success")
            live_display.add_log(f"Vulnerabilities found: {vulns_found}", "vuln" if vulns_found > 0 else "success")
            if self.scan_result.subdomains:
                live_display.add_log(f"Subdomains discovered: {len(self.scan_result.subdomains)}", "success")
            if self.scan_result.open_ports:
                live_display.add_log(f"Open ports found: {len(self.scan_result.open_ports)}", "success")
            live_display.update_stats("Complete", tests_run, vulns_found, len(urls))
        
        self.scan_result.end_time = datetime.now()
        self.scan_result.status = "completed"
        self.scan_result.risk_score = self._calculate_risk_score()
        
        return self.scan_result
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score"""
        if not self.scan_result.vulnerabilities:
            return 0.0
        
        weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        total = sum(weights.get(v.severity, 0) for v in self.scan_result.vulnerabilities)
        max_score = len(self.scan_result.vulnerabilities) * 10
        
        return (total / max_score * 100) if max_score > 0 else 0.0

# ============================================================================
# UI FUNCTIONS
# ============================================================================
def display_scan_results(scan_result: ScanResult, ollama_client: OllamaClient):
    """Display comprehensive scan results with database integration"""
    
    # Save scan to database if user is authenticated
    user = get_current_user()
    if user:
        try:
            ScanHistoryDB.save_scan(scan_result, user['id'], user['username'])
            
            # Log activity
            ActivityLog.log(
                user_id=user['id'],
                username=user['username'],
                action='scan',
                resource_type='scan',
                resource_id=scan_result.scan_id,
                details={
                    'target': scan_result.target_url,
                    'vulnerabilities': len(scan_result.vulnerabilities),
                    'risk_score': scan_result.risk_score
                },
                status='success'
            )
        except Exception as e:
            print(f"Failed to save scan: {e}")
    
    # Summary metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Pages Crawled", scan_result.pages_crawled)
    with col2:
        st.metric("Vulnerabilities", len(scan_result.vulnerabilities))
    with col3:
        st.metric("Forms Found", scan_result.forms_found)
    with col4:
        st.metric("Subdomains", len(scan_result.subdomains))
    with col5:
        st.metric("Risk Score", f"{scan_result.risk_score:.1f}%")
    
    # Advanced scan results (if available)
    if scan_result.subdomains or scan_result.open_ports or scan_result.nuclei_findings:
        st.markdown("---")
        st.subheader("🔍 Advanced Reconnaissance Results")
        
        tab_recon1, tab_recon2, tab_recon3 = st.tabs(["🌐 Subdomains", "🔌 Open Ports", "⚡ Nuclei Findings"])
        
        with tab_recon1:
            if scan_result.subdomains:
                st.write(f"**{len(scan_result.subdomains)} subdomains discovered:**")
                subdomain_df = pd.DataFrame([
                    {'Subdomain': sub} for sub in scan_result.subdomains
                ])
                st.dataframe(subdomain_df, use_container_width=True)
            else:
                st.info("No subdomains discovered. Enable subdomain scanning in configuration.")
        
        with tab_recon2:
            if scan_result.open_ports:
                st.write(f"**{len(scan_result.open_ports)} open ports found:**")
                port_df = pd.DataFrame(scan_result.open_ports)
                st.dataframe(port_df, use_container_width=True)
                
                # Port visualization
                fig = go.Figure(data=[go.Bar(
                    x=[str(p['port']) for p in scan_result.open_ports],
                    y=[1] * len(scan_result.open_ports),
                    text=[p['service'] for p in scan_result.open_ports],
                    textposition='auto',
                    marker=dict(color='#4287f5')
                )])
                fig.update_layout(
                    title="Open Ports by Service",
                    xaxis_title="Port",
                    yaxis_visible=False,
                    height=300,
                    paper_bgcolor='rgba(0,0,0,0)',
                    plot_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='white')
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No port scan data. Enable port scanning in configuration.")
        
        with tab_recon3:
            if scan_result.nuclei_findings:
                st.write(f"**{len(scan_result.nuclei_findings)} Nuclei findings:**")
                for finding in scan_result.nuclei_findings:
                    severity = finding.get('severity', 'unknown')
                    icon = '🔴' if severity == 'critical' else '🟠' if severity == 'high' else '🟡' if severity == 'medium' else '🔵'
                    
                    with st.expander(f"{icon} {finding.get('info', {}).get('name', 'Unknown')} ({severity.upper()})"):
                        st.write(f"**Template:** {finding.get('template-id', 'unknown')}")
                        st.write(f"**Matched At:** {finding.get('matched-at', 'N/A')}")
                        if 'description' in finding.get('info', {}):
                            st.write(f"**Description:** {finding['info']['description']}")
            else:
                st.info("No Nuclei findings. Enable Nuclei scanning in configuration.")
    
    st.markdown("---")
    
    # Vulnerability breakdown
    st.subheader("📊 Vulnerability Distribution")
    
    severity_counts = defaultdict(int)
    type_counts = defaultdict(int)
    
    for vuln in scan_result.vulnerabilities:
        severity_counts[vuln.severity] += 1
        type_counts[vuln.type] += 1
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Severity pie chart
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            hole=.3,
            marker=dict(colors=['#dc3545', '#fd7e14', '#ffc107', '#17a2b8'])
        )])
        fig.update_layout(
            title="By Severity",
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        # Type bar chart
        fig = go.Figure(data=[go.Bar(
            x=list(type_counts.keys()),
            y=list(type_counts.values()),
            marker=dict(color='#4287f5')
        )])
        fig.update_layout(
            title="By Type",
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='white'),
            xaxis=dict(tickangle=-45)
        )
        st.plotly_chart(fig, use_container_width=True)
    
    # Detailed vulnerabilities
    st.subheader("🔍 Detailed Findings")
    
    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_vulns = sorted(scan_result.vulnerabilities, 
                         key=lambda x: (severity_order.get(x.severity, 99), x.cvss_score),
                         reverse=True)
    
    for idx, vuln in enumerate(sorted_vulns):
        severity_class = f"vuln-{vuln.severity}"
        
        with st.expander(f"{'🔴' if vuln.severity == 'critical' else '🟠' if vuln.severity == 'high' else '🟡' if vuln.severity == 'medium' else '🔵'} {vuln.name} (CVSS {vuln.cvss_score})"):
            
            col1, col2, col3 = st.columns([2, 1, 1])
            with col1:
                st.write(f"**Type:** {vuln.type}")
            with col2:
                st.write(f"**Severity:** {vuln.severity.upper()}")
            with col3:
                st.write(f"**CWE:** {vuln.cwe}")
            
            st.write(f"**Description:** {vuln.description}")
            st.write(f"**Location:** `{vuln.location}`")
            
            with st.expander("🔬 Evidence"):
                st.code(vuln.evidence, language="text")
            
            with st.expander("🛠️ Remediation"):
                st.write(vuln.remediation)
            
            with st.expander("📚 References"):
                for ref in vuln.references:
                    st.write(f"- [{ref}]({ref})")
            
            # AI Analysis button - FINAL FIX with scan_id, vuln_id, AND index
            if ollama_client and ollama_client.available:
                if st.button(f"🤖 AI Analysis", key=f"ai_{scan_result.scan_id}_{vuln.vuln_id}_{idx}"):
                    with st.spinner("Analyzing with AI..."):
                        analysis = ollama_client.analyze_vulnerability(vuln)
                        if analysis:
                            st.markdown(analysis)
    
    # Export options
    st.subheader("📥 Export Results")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # JSON export
        json_data = {
            'scan_id': scan_result.scan_id,
            'target': scan_result.target_url,
            'timestamp': scan_result.start_time.isoformat(),
            'vulnerabilities': [
                {
                    'id': v.vuln_id,
                    'type': v.type,
                    'name': v.name,
                    'severity': v.severity,
                    'cvss': v.cvss_score,
                    'cwe': v.cwe,
                    'description': v.description,
                    'location': v.location,
                    'remediation': v.remediation
                }
                for v in scan_result.vulnerabilities
            ]
        }
        st.download_button(
            "Download JSON",
            data=json.dumps(json_data, indent=2),
            file_name=f"scan_{scan_result.scan_id}.json",
            mime="application/json"
        )
    
    with col2:
        # CSV export
        df = pd.DataFrame([
            {
                'Vulnerability': v.name,
                'Type': v.type,
                'Severity': v.severity,
                'CVSS': v.cvss_score,
                'CWE': v.cwe,
                'Location': v.location
            }
            for v in scan_result.vulnerabilities
        ])
        st.download_button(
            "Download CSV",
            data=df.to_csv(index=False),
            file_name=f"scan_{scan_result.scan_id}.csv",
            mime="text/csv"
        )
    
    with col3:
        # Scan saved confirmation
        if user:
            st.success("✅ Scan saved to database")
            st.caption(f"Scan ID: {scan_result.scan_id[:8]}")
        else:
            if st.button("🔐 Login to Save Scan"):
                st.rerun()

def render_user_dashboard():
    """Render user dashboard with scan history"""
    st.subheader("📊 Your Scan History")
    
    user = get_current_user()
    if not user:
        st.warning("Please login to view your dashboard")
        return
    
    scans = ScanHistoryDB.get_user_scans(user['id'])
    
    if scans:
        df = pd.DataFrame(scans)
        
        # Format timestamps
        if 'start_time' in df.columns:
            df['start_time'] = pd.to_datetime(df['start_time']).dt.strftime('%Y-%m-%d %H:%M')
        
        # Display metrics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Scans", len(scans))
        with col2:
            st.metric("Total Vulnerabilities", df['vulnerabilities_found'].sum())
        with col3:
            st.metric("Average Risk Score", f"{df['risk_score'].mean():.1f}%")
        
        # Display scans table
        st.dataframe(
            df[['target_url', 'start_time', 'vulnerabilities_found', 'risk_score', 'status']],
            use_container_width=True
        )
    else:
        st.info("You haven't run any scans yet. Start a scan to see history here.")

def render_chat_interface(ollama_client: OllamaClient):
    """Render AI chat interface"""
    st.subheader("💬 AI Security Assistant")
    
    # Chat messages
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if "timestamp" in message:
                st.caption(message["timestamp"])
    
    # Chat input
    if prompt := st.chat_input("Ask about vulnerabilities, security best practices..."):
        # Add user message
        st.session_state.chat_messages.append({
            "role": "user",
            "content": prompt,
            "timestamp": datetime.now().strftime("%H:%M")
        })
        
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get AI response
        if ollama_client and ollama_client.available:
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    messages = [{"role": m["role"], "content": m["content"]} 
                               for m in st.session_state.chat_messages]
                    response = ollama_client.chat(messages)
                    
                    if response:
                        st.markdown(response)
                        st.session_state.chat_messages.append({
                            "role": "assistant",
                            "content": response,
                            "timestamp": datetime.now().strftime("%H:%M")
                        })
                    else:
                        st.error("Failed to get response from AI")
        else:
            st.warning("Ollama is not available. Please start Ollama to use AI features.")

# ============================================================================
# MAIN APPLICATION (Modified with authentication)
# ============================================================================
def main():
    apply_professional_styling()
    
    # Initialize database
    init_database()
    
    # Initialize authentication
    init_auth()
    
    # Check authentication - render login page if not authenticated
    if not is_authenticated():
        # Show the login interface
        st.markdown("""
        <div style="display: flex; justify-content: center; align-items: center; min-height: 80vh;">
            <div style="max-width: 500px; width: 100%;">
        """, unsafe_allow_html=True)
        
        # Render the authentication interface
        render_auth_interface()
        
        st.markdown("""
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Stop here - don't show main app
        st.stop()
    
    # If we get here, user is authenticated
    # Get current user
    user = get_current_user()
    
    # Initialize Ollama
    ollama_client = OllamaClient()
    
    # Rest of your main app code...
    # [Your existing main app code continues here]
    
    # Sidebar
    with st.sidebar:
        st.image("https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExc3p4eDRyMmM0eTRxNDc5NjN3dTU3bTE0aGc0NDEwZG9hN3ZrcGwyNiZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/wwg1suUiTbCY8H8vIA/giphy.gif", width=240)
        st.title("Security Scanner")
        
        st.divider()
        
        # User info and logout
        render_logout_button()
        
        st.divider()
        
        # Navigation
        st.subheader("🧭 Navigation")
        
        if is_admin():
            page = st.radio(
                "Go to",
                ["🔍 Scanner", "👤 Profile", "📊 My Dashboard", "👑 Admin Dashboard", "💬 AI Assistant"],
                key="navigation"
            )
        else:
            page = st.radio(
                "Go to",
                ["🔍 Scanner", "👤 Profile", "📊 My Dashboard", "💬 AI Assistant"],
                key="navigation"
            )
        
        st.divider()
        
        # Ollama status
        if st.session_state.ollama_available:
            st.success("🤖 AI Assistant: Online")
            if st.session_state.available_models:
                selected_model = st.selectbox(
                    "AI Model",
                    st.session_state.available_models,
                    index=0
                )
                ollama_client.model = selected_model
        else:
            st.warning("🤖 AI Assistant: Offline")
            st.caption("Start Ollama to enable AI features")
        
        st.divider()
        
        # Scan configuration (only show on scanner page)
        if page == "🔍 Scanner":
            st.subheader("⚙️ Scan Configuration")
            
            target_url = st.text_input(
                "Target URL",
                placeholder="https://example.com",
                help="Enter the target website URL"
            )
            
            max_depth = st.slider("Crawl Depth", 1, 5, 3)
            max_pages = st.slider("Max Pages", 10, 100, 50)
            
            st.markdown("### 🔧 Advanced Options")
            
            enable_subdomain = st.checkbox("🌐 Subdomain Enumeration", value=False, 
                                           help="Discover subdomains using DNS and CT logs")
            enable_port_scan = st.checkbox("🔌 Port Scanning", value=False,
                                           help="Scan common ports (fast)")
            
            # Check if tools are available
            nmap_available = NmapScanner.is_available()
            nuclei_available = NucleiScanner.is_available()
            
            enable_nmap = st.checkbox(f"🛡️ Nmap Scan {'✅' if nmap_available else '❌ (not installed)'}", 
                                      value=False, disabled=not nmap_available,
                                      help="Advanced port scanning with service detection")
            enable_nuclei = st.checkbox(f"⚡ Nuclei Scan {'✅' if nuclei_available else '❌ (not installed)'}", 
                                        value=False, disabled=not nuclei_available,
                                        help="Template-based vulnerability scanning")
            
            if not nmap_available:
                st.caption("💡 Install: `sudo apt install nmap`")
            if not nuclei_available:
                st.caption("💡 Install: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`")
            
            scan_button = st.button("🚀 Start Scan", use_container_width=True)
            
            st.divider()
        
        # Scan history (always visible)
        if st.session_state.scan_results:
            st.subheader("📜 Recent Scans")
            for scan in st.session_state.scan_results[-3:]:
                with st.expander(f"Scan {scan.scan_id[:8]}"):
                    st.write(f"Target: {scan.target_url}")
                    st.write(f"Time: {scan.start_time.strftime('%H:%M:%S')}")
                    st.write(f"Vulns: {len(scan.vulnerabilities)}")
    
    # Main content based on selected page
    if page == "🔍 Scanner":
        st.title("💀 Enterprise Security Scanner Pro")
        st.markdown("### AI-Powered Vulnerability Detection & Analysis")
        
        # Check if scan button was clicked
        scan_clicked = 'scan_button' in locals() and scan_button
        
        if scan_clicked and target_url:
            if not target_url.startswith(('http://', 'https://')):
                st.error("Please enter a valid URL starting with http:// or https://")
            else:
                # Initialize live display
                live_display = LiveTestingDisplay()
                live_display.initialize_display()
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                scanner = EnterpriseScanner(
                    target_url, 
                    max_depth, 
                    max_pages,
                    enable_subdomain=enable_subdomain,
                    enable_port_scan=enable_port_scan,
                    enable_nmap=enable_nmap,
                    enable_nuclei=enable_nuclei
                )
                st.session_state.current_scan = scanner
                
                scan_result = scanner.run_scan(progress_bar, status_text, live_display)
                st.session_state.scan_results.append(scan_result)
                
                st.success("✅ Scan completed successfully!")
                st.balloons()
                
                # Display results below
                st.markdown("---")
                display_scan_results(scan_result, ollama_client)
        
        elif st.session_state.scan_results:
            st.info("Displaying most recent scan results")
            display_scan_results(st.session_state.scan_results[-1], ollama_client)
        else:
            st.info("👈 Enter a target URL and click 'Start Scan' to begin")
            
            # Show demo features
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.markdown("""
                ### 🕷️ Smart Crawling
                - Intelligent URL discovery
                - Form detection
                - Parameter extraction
                - Scope management
                """)
            
            with col2:
                st.markdown("""
                ### 🔍 Vulnerability Testing
                - SQL Injection
                - XSS (Reflected)
                - Command Injection
                - Path Traversal
                - Security Headers
                - SSL/TLS Analysis
                """)
            
            with col3:
                st.markdown("""
                ### 🛡️ Advanced Scanning
                - 🌐 Subdomain Enumeration
                - 🔌 Port Scanning
                - 🛡️ Nmap Integration
                - ⚡ Nuclei Templates
                - 🤖 AI Analysis
                - 📊 Real-time Monitoring
                """)
            
            # Tool status
            st.markdown("---")
            st.markdown("### 🔧 Tool Availability")
            
            import platform
            system = platform.system().lower()
            
            tool_col1, tool_col2, tool_col3, tool_col4 = st.columns(4)
            
            with tool_col1:
                if NmapScanner.is_available():
                    st.success("✅ Nmap Installed")
                else:
                    st.error("❌ Nmap Not Found")
                    if system == 'windows':
                        st.caption("💡 Install: https://nmap.org/download.html")
                    else:
                        st.caption("💡 Install: `sudo apt install nmap`")
                    
            with tool_col2:
                if NucleiScanner.is_available():
                    st.success("✅ Nuclei Installed")
                else:
                    st.error("❌ Nuclei Not Found")
                    if system == 'windows':
                        st.caption("💡 Install: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`")
                        st.caption("Or download: https://github.com/projectdiscovery/nuclei/releases")
                    else:
                        st.caption("💡 Install: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`")
                    
            with tool_col3:
                if st.session_state.ollama_available:
                    st.success("✅ Ollama Connected")
                else:
                    st.warning("⚠️ Ollama Offline")
                    if system == 'windows':
                        st.caption("💡 Download: https://ollama.ai/download")
                    else:
                        st.caption("💡 Install: `curl -fsSL https://ollama.ai/install.sh | sh`")
                    
            with tool_col4:
                st.success("✅ Python Scanners")
    
    elif page == "👤 Profile":
        st.title("👤 User Profile")
        render_user_profile()
    
    elif page == "📊 My Dashboard":
        st.title("📊 My Security Dashboard")
        render_user_dashboard()
    
    elif page == "👑 Admin Dashboard":
        st.title("👑 Admin Dashboard")
        render_admin_dashboard()
    
    elif page == "💬 AI Assistant":
        st.title("💬 AI Security Assistant")
        render_chat_interface(ollama_client)

if __name__ == "__main__":
    main()
