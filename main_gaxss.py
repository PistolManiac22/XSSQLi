"""
GAXSS Main CLI Interface - Generic Version
Works with any web application via configuration classes

CORRECTED VERSION with proper error handling and integration per paper Section 4
"""

import argparse
import logging
import csv
import os
import sys
from datetime import datetime
import re
from typing import Optional, Dict, List, Tuple

from gaxss_engine import GAXSS_Engine
from payload_generator import GAXSS_PayloadGenerator
from parameter_discoverer import ParameterDiscoverer
from webapp_config import GenericWebApp
from webapp_behavior_analyzer import WebAppBehaviorAnalyzer


class GAXSS_CLI:
    """Command-line interface for GAXSS (Generic).

    Implements complete workflow per paper Section 4:
    1. Parameter Discovery
    2. Behavior Analysis
    3. Genetic Algorithm Evolution
    4. Results Export

    Reference:
        Liu et al. (2022), Section 4: Genetic Algorithm for XSS
    """

    def __init__(self, output_dir: str = 'results', log_dir: str = 'logs'):
        """Initialize CLI with output directories."""
        self.output_dir = output_dir
        self.log_dir = log_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        self.setup_logging()
        self.logger = logging.getLogger('GAXSS')

    def setup_logging(self):
        """Setup comprehensive logging configuration."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.log_dir, f'gaxss_{timestamp}.log')

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    def run_xss_test(self, args, webapp_config):
        """Run XSS vulnerability detection workflow."""
        self.logger.info("=" * 70)
        self.logger.info("GAXSS XSS Testing Started")
        self.logger.info("=" * 70)
        self.logger.info(f"Target URL: {args.url}")
        self.logger.info(f"Parameter: {args.param if args.param else 'auto-discovering'}")
        self.logger.info(f"Configuration: {webapp_config.__class__.__name__}")

        # ==================== STEP 1: AUTHENTICATE ====================
        try:
            self.logger.info("Step 1: Authenticating to web application...")
            session = webapp_config.authenticate()

            if session is None:
                self.logger.error("[ERROR] Authentication failed. Exiting.")
                return False

            self.logger.info("[OK] Authentication successful")

        except Exception as e:
            self.logger.error(f"[ERROR] Authentication error: {e}")
            return False

        # ==================== STEP 2: PARAMETER DISCOVERY ====================
        param_name = args.param
        context = 2  # Default to 'outside' context

        if args.auto_discover:
            try:
                self.logger.info("Step 2: Auto-discovering vulnerable parameters...")
                discoverer = ParameterDiscoverer(webapp_config)
                injectable_params = discoverer.find_injectable_parameters(args.url)

                if not injectable_params:
                    self.logger.error("[ERROR] No injectable parameters found!")
                    return False

                param_name = list(injectable_params.keys())[0]
                context_type = injectable_params[param_name]

                self.logger.info(f"[OK] Found {len(injectable_params)} injectable parameter(s)")
                self.logger.info(f"  Using: {param_name} (context: {context_type})")

                context_map = {'js': 0, 'attribute': 1, 'text': 2, 'unknown': 2}
                context = context_map.get(context_type, 2)

            except Exception as e:
                self.logger.error(f"[ERROR] Parameter discovery error: {e}")
                return False

        else:
            if not param_name:
                self.logger.error("[ERROR] Either -p/--param or --auto-discover must be specified")
                return False

            self.logger.info(f"Step 2: Using parameter: {param_name}")
            context_map = {'script': 0, 'attribute': 1, 'outside': 2}
            context = context_map.get(args.context, 2)
            self.logger.info(f"[OK] Context type: {args.context} (code: {context})")

        # ==================== STEP 3: BEHAVIOR ANALYSIS ====================
        try:
            self.logger.info("Step 3: Analyzing web application behavior...")

            def test_func(payload: str) -> str:
                """Test function that sends payload to web app."""
                return webapp_config.send_payload(args.url, param_name, payload)

            analyzer = WebAppBehaviorAnalyzer(test_func, param_name)
            behaviors = analyzer.analyze()

            self.logger.info("[OK] Behavior analysis complete")
            self.logger.info(f"  Detected behaviors: {list(behaviors.keys())}")

        except Exception as e:
            self.logger.error(f"[ERROR] Behavior analysis error: {e}")
            return False

        # ==================== STEP 4: GENETIC ALGORITHM EVOLUTION ====================
        try:
            self.logger.info("Step 4: Starting genetic algorithm evolution...")
            self.logger.info(f"  Population size: {args.pop}")
            self.logger.info(f"  Generations: {args.gen}")
            self.logger.info(f"  Mutation probability: 0.2")
            self.logger.info(f"  Early stopping patience: {args.patience}")

            engine = GAXSS_Engine(
                population_size=args.pop,
                generations=args.gen,
                patience=args.patience,
                mutation_prob=0.2,
                behaviors=behaviors
            )

            self.logger.info("Starting evolution loop...")
            population, fitness_history = engine.evolve(test_func, context, verbose=True)

            self.logger.info("Evaluating final population...")
            final_fitness_data = engine.evaluate_population(population, test_func, context)

            # results: [(dna, (fitness, ex, closed, dis, pu)), ...]
            results = list(zip(population, final_fitness_data))
            results.sort(key=lambda x: x[1][0], reverse=True)

            best_fitness = results[0][1][0] if results else 0.0
            avg_fitness = sum(fit[0] for _, fit in results) / len(results) if results else 0.0

            self.logger.info("[OK] Evolution complete")
            self.logger.info(f"  Best fitness: {best_fitness:.4f}")
            self.logger.info(f"  Average fitness: {avg_fitness:.4f}")

        except Exception as e:
            self.logger.error(f"[ERROR] Evolution error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            return False

        # ==================== STEP 5: EXPORT RESULTS ====================
        try:
            self.logger.info("Step 5: Exporting results...")
            self.export_xss_results(results, args.output, context)
            self.logger.info("[OK] Results exported successfully")

        except Exception as e:
            self.logger.error(f"[ERROR] Export error: {e}")
            return False

        # ==================== VULNERABILITY ANALYSIS ====================
        self.logger.info("=" * 70)
        self.logger.info("GAXSS XSS Testing Completed Successfully")
        self.logger.info("=" * 70)
        self.logger.info(f"Results: {args.output}")
        self.logger.info(f"Logs: {self.log_dir}")
        self.logger.info("=" * 70)
        self.logger.info("VULNERABILITY ANALYSIS")
        self.logger.info("=" * 70)

        # Analisis kerentanan dengan kriteria ketat
        vuln_payloads = []
        high_risk_payloads = []
        medium_risk_payloads = []

        for dna, fitness_data in results:
            if not isinstance(fitness_data, (list, tuple)) or len(fitness_data) < 5:
                continue

            fitness, ex, closed, dis, pu = fitness_data

            # Kerentanan KRITIS: Ex=2 (eksekusi terdeteksi) + konteks baik + filter minimal
            if ex >= 2.0 and closed >= 0.8 and pu <= 0.1:
                vuln_payloads.append((dna, fitness_data))
                # DEBUG: log ringkas semua payload yang diklasifikasikan CRITICAL
                logger = self.logger
                if vuln_payloads:
                    logger.debug("[DEBUG-SUMMARY] === CRITICAL VULN PAYLOADS BEGIN ===")
                    dbg_pg = GAXSS_PayloadGenerator()
                    for idx, (dna, (fit, ex, closed, dis, pu)) in enumerate(vuln_payloads, 1):
                        try:
                            payload_dbg = dbg_pg.generate_payload(dna, context)
                        except Exception:
                            payload_dbg = "<error generating payload for debug>"

                        logger.debug(
                            "[DEBUG-SUMMARY] #%d | fit=%.3f ex=%.2f closed=%.2f dis=%.2f pu=%.2f | payload=%r",
                            idx, fit, ex, closed, dis, pu, payload_dbg[:200]
                        )
                    logger.debug("[DEBUG-SUMMARY] === CRITICAL VULN PAYLOADS END ===")

            # High risk: Ex=2 tapi mungkin closure kurang sempurna
            elif ex >= 2.0 and closed >= 0.6 and pu <= 0.3:
                high_risk_payloads.append((dna, fitness_data))

            # Medium risk: Ada indikasi parsial (Ex > 0 tapi < 2)
            elif ex > 0.0 and ex < 2.0 and closed >= 0.5:
                medium_risk_payloads.append((dna, fitness_data))

        # Laporan berdasarkan tingkat kerentanan
        if vuln_payloads:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] KERENTANAN XSS TERDETEKSI - KRITIS")
            self.logger.warning("=" * 70)
            self.logger.warning(
                f"Ditemukan {len(vuln_payloads)} payload dengan indikasi eksekusi kuat:"
            )
            self.logger.warning("  - Execution Score (Ex) = 2.0 (kode dieksekusi)")
            self.logger.warning("  - Closure Score (CLOSED) >= 0.8 (konteks tertutup baik)")
            self.logger.warning("  - Penalty Score (Pu) <= 0.1 (filter minimal)")
            self.logger.warning("")
            self.logger.warning("Rekomendasi:")
            self.logger.warning("  1. Implementasikan sanitasi input yang ketat")
            self.logger.warning("  2. Gunakan Content Security Policy (CSP)")
            self.logger.warning("  3. Encode output dengan HTML entities")
            self.logger.warning("  4. Review filter keamanan aplikasi")

        elif high_risk_payloads:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] POTENSI KERENTANAN XSS - TINGGI")
            self.logger.warning("=" * 70)
            self.logger.warning(
                f"Ditemukan {len(high_risk_payloads)} payload dengan potensi eksekusi:"
            )
            self.logger.warning("  - Ada indikasi eksekusi (Ex >= 2.0)")
            self.logger.warning("  - Namun konteks atau filter perlu evaluasi lebih lanjut")
            self.logger.warning("")
            self.logger.warning("Rekomendasi:")
            self.logger.warning("  1. Lakukan verifikasi manual pada payload tersebut")
            self.logger.warning("  2. Perbaiki mekanisme sanitasi input")

        elif medium_risk_payloads:
            self.logger.info("=" * 70)
            self.logger.info("[*] POTENSI KERENTANAN XSS - SEDANG")
            self.logger.info("=" * 70)
            self.logger.info(
                f"Ditemukan {len(medium_risk_payloads)} payload dengan indikasi parsial:"
            )
            self.logger.info("  - Execution score rendah (0 < Ex < 2)")
            self.logger.info("  - Perlu investigasi lebih lanjut")
            self.logger.info("")
            self.logger.info("Rekomendasi:")
            self.logger.info("  1. Evaluasi mekanisme encoding yang diterapkan")
            self.logger.info("  2. Pastikan filter berfungsi konsisten")

        else:
            self.logger.info("=" * 70)
            self.logger.info("[✓] TIDAK TERDETEKSI KERENTANAN XSS")
            self.logger.info("=" * 70)
            self.logger.info("Hasil analisis:")
            self.logger.info("  - Tidak ada payload dengan Ex = 2.0 (eksekusi)")
            self.logger.info("  - Filter dan encoding tampak berfungsi dengan baik")
            self.logger.info("  - Target kemungkinan sudah menerapkan proteksi XSS")
            self.logger.info("")
            self.logger.info("Catatan:")
            self.logger.info("  - Hasil ini berlaku untuk konfigurasi dan konteks saat ini")
            self.logger.info("  - Tetap lakukan review berkala terhadap keamanan aplikasi")

        self.logger.info("=" * 70)

        return True

    def export_xss_results(self, results: List[Tuple], output_dir: str, context: int = 2):
        """Export XSS results to CSV file."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_file = os.path.join(output_dir, f'xss_results_{timestamp}.csv')

        try:
            payload_generator = GAXSS_PayloadGenerator()

            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                writer.writerow([
                    'Rank',
                    'Fitness',
                    'Payload',
                    'Ex',
                    'CLOSED',
                    'Dis',
                    'Pu',
                    'Risk_Level',
                    'DNA_Closing',
                    'DNA_Main',
                    'DNA_Mutations'
                ])

                for rank, (dna, fitness_data) in enumerate(results, 1):
                    try:
                        fitness, ex, closed, dis, pu = fitness_data

                        # Tentukan risk level
                        if ex >= 2.0 and closed >= 0.8 and pu <= 0.1:
                            risk_level = "CRITICAL"
                        elif ex >= 2.0 and closed >= 0.6 and pu <= 0.3:
                            risk_level = "HIGH"
                        elif ex > 0.0 and ex < 2.0 and closed >= 0.5:
                            risk_level = "MEDIUM"
                        else:
                            risk_level = "LOW"

                        payload = payload_generator.generate_payload(dna, context=context)
                        payload_escaped = payload.replace('"', '""')

                        writer.writerow([
                            rank,
                            f'{fitness:.4f}',
                            f'"{payload_escaped}"',
                            f'{ex:.4f}',
                            f'{closed:.4f}',
                            f'{dis:.4f}',
                            f'{pu:.4f}',
                            risk_level,
                            str(dna.closing),
                            str(dna.main),
                            str(dna.mutations)
                        ])

                    except Exception as e:
                        self.logger.warning(f"Error exporting rank {rank}: {e}")
                        continue

            self.logger.info(f"Results exported to {csv_file} ({len(results)} payloads)")

        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            raise

    def main(self):
        """Main CLI entry point with argument parsing."""
        parser = argparse.ArgumentParser(
            description='GAXSS - Genetic Algorithm XSS Testing Tool (Generic)',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
EXAMPLES:

Generic Web App (no authentication):
  python main_gaxss.py xss -u "http://example.com/search" -p "q" --generic
  python main_gaxss.py xss -u "http://example.com/search" --generic --auto-discover

DVWA (with different security levels):
  python main_gaxss.py xss --dvwa --security low -p "name"
  python main_gaxss.py xss --dvwa --auto-discover --security medium

bWAPP (Buggy Web Application):
  python main_gaxss.py xss --bwapp --security low -p "firstname"
  python main_gaxss.py xss --bwapp --auto-discover

Mutillidae (OWASP):
  python main_gaxss.py xss -u "http://localhost:9000/index.php?page=user-info.php" \\
    --mutillidae --auto-discover

Custom Web App (with specific base URL):
  python main_gaxss.py xss -u "http://custom.app/vulnerable" \\
    --custom-url "http://custom.app" -p "input"

GA Tuning:
  python main_gaxss.py xss -u "http://example.com/search" -p "q" --generic \\
    --pop 100 --gen 50 --patience 15
            """
        )

        subparsers = parser.add_subparsers(dest='mode', help='Testing mode')

        # ==================== XSS MODE ====================
        xss_parser = subparsers.add_parser('xss', help='XSS vulnerability testing')

        # Target and parameter
        xss_parser.add_argument(
            '-u', '--url',
            help='Target URL (jika kosong: default DVWA/bWAPP akan digunakan)'
        )
        xss_parser.add_argument(
            '-p', '--param',
            help='Parameter name (required if --auto-discover not used)'
        )
        xss_parser.add_argument(
            '--auto-discover',
            action='store_true',
            help='Automatically discover vulnerable parameters'
        )

        # ==================== WEB APPLICATION TYPE ====================
        app_group = xss_parser.add_argument_group('Web Application Type')
        app_type = app_group.add_mutually_exclusive_group(required=True)

        app_type.add_argument(
            '--generic',
            action='store_true',
            help='Generic web app (no authentication required)'
        )
        app_type.add_argument(
            '--dvwa',
            action='store_true',
            help='DVWA - Damn Vulnerable Web Application'
        )
        app_type.add_argument(
            '--bwapp',
            action='store_true',
            help='bWAPP - Buggy Web Application Platform'
        )
        app_type.add_argument(
            '--mutillidae',
            action='store_true',
            help='OWASP Mutillidae II'
        )
        app_type.add_argument(
            '--custom-url',
            type=str,
            help='Custom web app base URL'
        )

        # ==================== DVWA OPTIONS ====================
        dvwa_group = xss_parser.add_argument_group('DVWA Options')
        dvwa_group.add_argument(
            '--username',
            default='admin',
            help='DVWA username (default: admin)'
        )
        dvwa_group.add_argument(
            '--password',
            default='password',
            help='DVWA password (default: password)'
        )
        dvwa_group.add_argument(
            '--security',
            default='low',
            choices=['low', 'medium', 'high', 'impossible'],
            help='Security level (default: low)'
        )

        # ==================== bWAPP OPTIONS ====================
        bwapp_group = xss_parser.add_argument_group('bWAPP Options')
        bwapp_group.add_argument(
            '--bwapp-user',
            default='bee',
            help='bWAPP username (default: bee)'
        )
        bwapp_group.add_argument(
            '--bwapp-pass',
            default='bug',
            help='bWAPP password (default: bug)'
        )
        bwapp_group.add_argument(
            '--vulnerability',
            default='xss_reflected',
            help='bWAPP vulnerability ID (default: xss_reflected)'
        )

        # ==================== MUTILLIDAE OPTIONS ====================
        mutillidae_group = xss_parser.add_argument_group('Mutillidae Options')
        mutillidae_group.add_argument(
            '--mutillidae-security',
            default='0',
            choices=['0', '1', '2', '3', '4', '5'],
            help='Security level 0-5 (default: 0 = least secure)'
        )

        # ==================== GENETIC ALGORITHM OPTIONS ====================
        ga_group = xss_parser.add_argument_group('Genetic Algorithm Configuration')
        ga_group.add_argument(
            '--pop',
            type=int,
            default=60,
            help='Population size per generation (default: 60)'
        )
        ga_group.add_argument(
            '--gen',
            type=int,
            default=30,
            help='Maximum number of generations (default: 30)'
        )
        ga_group.add_argument(
            '--context',
            default='outside',
            choices=['script', 'attribute', 'outside'],
            help='Injection context (default: outside)'
        )
        ga_group.add_argument(
            '--patience',
            type=int,
            default=10,
            help='Early stopping patience in generations (default: 10)'
        )

        # ==================== OUTPUT OPTIONS ====================
        xss_parser.add_argument(
            '-o', '--output',
            default='results',
            help='Output directory for results (default: results)'
        )

        # ==================== PARSE ARGUMENTS ====================
        args = parser.parse_args()

        if not args.mode:
            parser.print_help()
            return

        # Set default URL untuk DVWA dan bWAPP jika -u tidak diisi
        if args.mode == 'xss':
            if not args.url:
                if getattr(args, 'dvwa', False):
                    args.url = "http://127.0.0.1:8081/vulnerabilities/xss_r/"
                elif getattr(args, 'bwapp', False):
                    args.url = "http://127.0.0.1:8082/xss_get.php"

            # Validasi: generic/custom harus punya URL
            if (args.generic or args.custom_url) and not args.url:
                self.logger.error("Error: untuk generic/custom, -u/--url wajib diisi")
                xss_parser.print_help()
                return

        # ==================== XSS MODE EXECUTION ====================
        if args.mode == 'xss':
            if not args.auto_discover and not args.param:
                self.logger.error("Error: Either -p/--param or --auto-discover must be specified")
                xss_parser.print_help()
                return

            try:
                if args.generic:
                    webapp_config = GenericWebApp(base_url="")
                    self.logger.info("Configuration: Generic Web App")

                elif args.dvwa:
                    from dvwa_config import DVWAConfig
                    base_url = self._extract_base_url(args.url)
                    webapp_config = DVWAConfig(
                        base_url=base_url,
                        username=args.username,
                        password=args.password,
                        security_level=args.security
                    )
                    self.logger.info(f"Configuration: DVWA at {base_url} (security: {args.security})")

                elif args.bwapp:
                    from bwapp_config import BWAPPConfig
                    base_url = self._extract_base_url(args.url, default="http://localhost:8082")
                    webapp_config = BWAPPConfig(
                        base_url=base_url,
                        username=args.bwapp_user,
                        password=args.bwapp_pass,
                        vulnerability=args.vulnerability,
                        security_level=args.security
                    )
                    self.logger.info(f"Configuration: bWAPP at {base_url}")

                elif args.mutillidae:
                    from mutillidae_config import MutillidaeConfig
                    base_url = self._extract_base_url(args.url, default="http://localhost:9000")
                    webapp_config = MutillidaeConfig(
                        base_url=base_url,
                        security_level=args.mutillidae_security
                    )
                    self.logger.info(f"Configuration: Mutillidae at {base_url}")

                elif args.custom_url:
                    webapp_config = GenericWebApp(base_url=args.custom_url)
                    self.logger.info(f"Configuration: Custom Web App at {args.custom_url}")

                else:
                    self.logger.error("Must specify one of: --generic, --dvwa, --bwapp, --mutillidae, --custom-url")
                    xss_parser.print_help()
                    return

                success = self.run_xss_test(args, webapp_config)
                sys.exit(0 if success else 1)

            except ImportError as e:
                self.logger.error(f"Configuration module not found: {e}")
                self.logger.error("Make sure dvwa_config.py, bwapp_config.py, or mutillidae_config.py exists")
                return
            except Exception as e:
                self.logger.error(f"Error: {e}")
                import traceback
                self.logger.error(traceback.format_exc())
                sys.exit(1)

    @staticmethod
    def _extract_base_url(url: str, default: str = "http://localhost") -> str:
        """Extract base URL from target URL."""
        match = re.match(r'(https?://[^/]+)', url)
        return match.group(1) if match else default


def main():
    """Entry point for package."""
    cli = GAXSS_CLI()
    cli.main()


if __name__ == '__main__':
    main()
