#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import tldextract
import whois
import datetime
import socket
import re
import subprocess
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(Fore.CYAN + "╔════════════════════════════════════╗")
    print("║     PHISHING LINK SCANNER TOOL    ║")
    print("╚════════════════════════════════════╝" + Style.RESET_ALL)

def extract_domain(url):
    extracted = tldextract.extract(url)
    return ".".join(part for part in [extracted.domain, extracted.suffix] if part)

def raw_whois_lookup(domain):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(("whois.verisign-grs.com", 43))
        s.send((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(1024)
            if not data:
                break
            response += data
        s.close()
        text = response.decode(errors="ignore")
        match = re.search(r'Creation Date:\s?(.+)', text)
        if not match:
            match = re.search(r'Domain Registration Date:\s?(.+)', text)
        if match:
            creation_str = match.group(1).strip()
            # Parse date safely (some formats vary)
            creation_date = datetime.datetime.strptime(creation_str[:10], '%Y-%m-%d')
            return (datetime.datetime.now() - creation_date).days, creation_date.strftime('%Y-%m-%d')
    except Exception:
        return None, None
    return None, None

def whois_cli_fallback(domain):
    try:
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        output = result.stdout
        match = re.search(r'Creation Date:\s?(.+)', output)
        if not match:
            match = re.search(r'Domain Registration Date:\s?(.+)', output)
        if not match:
            match = re.search(r'created:\s?(.+)', output, re.IGNORECASE)
        if match:
            creation_str = match.group(1).strip()
            # Try parsing with common formats
            for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%d-%b-%Y', '%Y-%m-%dT%H:%M:%SZ'):
                try:
                    creation_date = datetime.datetime.strptime(creation_str[:10], fmt)
                    age_days = (datetime.datetime.now() - creation_date).days
                    return age_days, creation_date.strftime('%Y-%m-%d')
                except:
                    continue
    except Exception:
        return None, None
    return None, None

def get_domain_age(domain):
    # Try python-whois
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date is not None:
            today = datetime.datetime.now()
            age_days = (today - creation_date).days
            return age_days, creation_date.strftime('%Y-%m-%d')
    except:
        pass

    # Try raw whois socket fallback
    age, date_str = raw_whois_lookup(domain)
    if age is not None:
        return age, date_str

    # Try system whois command fallback
    age, date_str = whois_cli_fallback(domain)
    if age is not None:
        return age, date_str

    return None, None

def check_url(url):
    flags = []
    soft_warnings = []

    parsed_url = urlparse(url)
    full_domain = extract_domain(url)
    tld = full_domain.split('.')[-1]

    print("\n🔎 Scanning URL:", url)

    # Suspicious TLDs
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq']
    if tld in suspicious_tlds:
        flags.append(f"[!] Suspicious top-level domain: .{tld}")

    # Domain age
    domain_age_days, creation_str = get_domain_age(full_domain)
    if domain_age_days is None:
        soft_warnings.append("[!] Unable to fetch domain age (possibly private WHOIS or WHOIS blocked).")
    else:
        print(Fore.BLUE + f"[i] Domain created on: {creation_str} ({domain_age_days} days old)" + Style.RESET_ALL)
        if domain_age_days < 30:
            flags.append(f"[!] Domain is very new: {domain_age_days} days old")

    # HTTP check
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        print(Fore.GREEN + f"[+] Server responded with status: {response.status_code}")
        if len(response.history) > 0:
            redirect_count = len(response.history)
            if redirect_count > 2:
                flags.append(f"[!] URL redirects {redirect_count} times")
            else:
                soft_warnings.append(f"[!] URL redirects once (common behavior)")
    except requests.exceptions.RequestException as e:
        flags.append(f"[!] Could not connect to the server: {e}")

    return flags, soft_warnings

def main():
    banner()
    url = input("\n🔗 Enter the URL to scan: ").strip()

    flags, soft_warnings = check_url(url)

    print("\n📋 Scan Result:")
    for warning in soft_warnings:
        print(Fore.YELLOW + warning)
    for flag in flags:
        print(Fore.RED + flag)

    if not flags:
        print(Fore.GREEN + "\n✅ This URL looks safe based on current checks.")
    else:
        print(Fore.RED + "\n⚠  Warning: The URL has phishing-like characteristics!")

if __name__ == "__main__":
    main()
