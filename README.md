# Shortbread 🍪

A lightweight CLI security auditor for inspecting web headers, transport security, and defence-in-depth configurations.

## Overview
Shortbread analyses target HTTP endpoints to verify the implementation of modern defensive security headers (CSP, HSTS, X-Frame-Options, etc.) and outputs clear, colourised audit findings with remediation context.

## Features
- Inspects essential defence headers (CSP, HSTS, X-Frame-Options, Referrer-Policy).
- Flags missing configurations and provides remediation guidance.
- Structured, colour-coded terminal output.

## Requirements
- Python 3.8+
- Dependencies listed in `requirements.txt`
