# 🛡️ Enterprise Security Scanner Pro

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-purple)
![Streamlit](https://img.shields.io/badge/streamlit-1.28+-red)
![License](https://img.shields.io/badge/license-MIT-green)

## 🚀 AI-Powered Vulnerability Detection System

Enterprise Security Scanner Pro is a professional-grade security testing tool that combines multiple scanning techniques with AI-powered analysis to detect vulnerabilities in web applications.

![Security Scanner Demo](https://media.giphy.com/media/wwg1suUiTbCY8H8vIA/giphy.gif)

## ✨ Features

### 🔍 Core Scanning
- **Smart Web Crawling** - Automatic URL discovery and form detection
- **SQL Injection Detection** - Error-based, time-based blind, and UNION attacks
- **XSS Detection** - Reflected, stored, and DOM-based variants  
- **Command Injection** - OS command injection testing
- **Path Traversal** - LFI/RFI vulnerability detection
- **Security Headers** - Comprehensive header analysis
- **SSL/TLS Analysis** - Certificate validation and cipher strength

### 🛡️ Advanced Reconnaissance
- **Subdomain Enumeration** - DNS brute-force and certificate transparency logs
- **Port Scanning** - Fast TCP port scanning with service detection
- **Nmap Integration** - Professional network mapping
- **Nuclei Integration** - Template-based vulnerability scanning

### 🤖 AI Integration
- **Ollama AI Assistant** - Intelligent vulnerability analysis
- **Automated Remediation** - AI-generated fix recommendations
- **Security Chatbot** - Interactive security Q&A

### 📊 Professional Features
- **Real-time Monitoring** - Live test execution display
- **Interactive Dashboards** - Plotly visualizations
- **Multi-format Export** - JSON, CSV reporting
- **Scan History** - Persistent storage with SQLite
- **Authentication System** - User management with bcrypt
- **Role-Based Access** - Admin and user roles

## 🚀 Quick Start

### Prerequisites
```bash
# Install Python 3.8+
python --version

# Install Ollama (optional, for AI features)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2

# Install Nmap (optional, for advanced scanning)
# Ubuntu/Debian
sudo apt install nmap
# macOS
brew install nmap
# Windows
# Download from https://nmap.org/download.html

# Install Nuclei (optional, for template scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
