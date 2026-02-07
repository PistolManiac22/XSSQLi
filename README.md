# XSSQLi

XSSQLi is a Python-based security testing tool that uses a genetic algorithm to generate and refine payloads for **XSS** and **SQL injection** discovery. It supports multiple target platforms (DVWA, bWAPP, OWASP Mutillidae II, or generic/custom apps) and provides both CLI and GUI workflows.

> **Disclaimer:** Use this tool only on systems you own or have explicit permission to test.

## Features

- Genetic-algorithm-driven payload evolution for XSS and SQLi.
- Target presets for DVWA, bWAPP, and Mutillidae II.
- Automatic parameter discovery for injectable inputs.
- CLI mode for scripted scans and CSV export.
- Tkinter-based GUI for interactive scanning and results viewing.

## Requirements

- Python 3.9+ (recommended)
- Python packages:
  - `requests`
  - `beautifulsoup4`
  - `ttkbootstrap` (GUI)
  - `pillow` (GUI)

Install dependencies:

```bash
pip install requests beautifulsoup4 ttkbootstrap pillow
```

## Quick Start

### CLI (XSS)

```bash
python main_gaxss.py xss --dvwa \
  --url http://127.0.0.1:8081/vulnerabilities/xss_r/ \
  --param name \
  --pop 60 --gen 30
```

### CLI (SQLi)

```bash
python main_gaxss.py sqli --dvwa \
  --url http://127.0.0.1:8081/vulnerabilities/sqli/ \
  --param id \
  --pop 40 --gen 20
```

### CLI (Both XSS + SQLi)

```bash
python main_gaxss.py both --dvwa \
  --url http://127.0.0.1:8081/vulnerabilities/xss_r/ \
  --param name \
  --pop 60 --gen 30
```

### Auto-Discover Parameters

```bash
python main_gaxss.py xss --dvwa \
  --url http://127.0.0.1:8081/vulnerabilities/xss_r/ \
  --auto-discover
```

## Web App Targets

Choose one of the supported target modes per scan:

- `--dvwa` (Damn Vulnerable Web Application)
- `--bwapp` (bWAPP)
- `--mutillidae` (OWASP Mutillidae II)
- `--generic` (generic target, requires a full URL)
- `--custom-url http://target-base-url` (use a custom base URL)

For DVWA, you can also configure credentials and security level:

```bash
--username admin --password password --security low
```

## GUI

Launch the graphical interface:

```bash
python gui.py
```

The GUI provides a guided flow for XSS, SQLi, or combined scans and can export results to CSV.

## Output

Results are stored in the `results/` folder by default, with logs saved in `logs/`.

## Project Structure

- `main_gaxss.py`: CLI entry point for XSS/SQLi scans.
- `gui.py`: GUI application.
- `gaxss_engine.py`: Genetic algorithm engine.
- `payload_generator.py`: Payload generation and mutation.
- `parameter_discoverer.py`: Input discovery.
- `sqli_detector/`: SQLi detection helpers.

## Notes

- Ensure your target apps are running and reachable at the URLs you provide.
- For bWAPP and Mutillidae, adjust base URLs or ports to match your local setup.

## License

This project is released under the MIT License:

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
