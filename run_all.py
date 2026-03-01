"""
Run All — Execute all scenarios and generate the exploit report.

Usage:
    python run_all.py

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

from scenario_runner import run_all as run_scenarios
from report_generator import generate_report

if __name__ == "__main__":
    run_scenarios()
    generate_report()
    print("\n" + "=" * 60)
    print("  Done. Open outputs/report.html in your browser.")
    print("=" * 60)
