"""
GAXSS Main CLI Interface - WITH SQLi MODE
Works with any web application via configuration classes
Includes both XSS and SQLi vulnerability testing

UPDATED VERSION with SQLi support integrated (DVWA, bWAPP, Mutillidae, Generic)
MODIFIED: SQLi export now uses CSV format (not TXT)
"""

import argparse
import logging
import csv
import os
import sys
from datetime import datetime
import re
from typing import Dict, List, Tuple

from gaxss_engine import GAXSS_Engine
from payload_generator import GAXSS_PayloadGenerator
from parameter_discoverer import ParameterDiscoverer
from webapp_config import GenericWebApp
from webapp_behavior_analyzer import WebAppBehaviorAnalyzer


class GAXSS_CLI:
    """Command-line interface for GAXSS (Generic) with XSS and SQLi modes."""

    def __init__(self, output_dir: str = "results", log_dir: str = "logs"):
        self.output_dir = output_dir
        self.log_dir = log_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)
        self.setup_logging()
        self.logger = logging.getLogger("GAXSS")

    def setup_logging(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.log_dir, f"gaxss_{timestamp}.log")

        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)

        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter("%(levelname)s: %(message)s")
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

    # ==================== XSS WORKFLOW ====================

    def run_xss_test(self, args, webapp_config):
        """Run XSS vulnerability detection workflow."""
        self.logger.info("=" * 70)
        self.logger.info("GAXSS XSS Testing Started")
        self.logger.info("=" * 70)
        self.logger.info(f"Target URL: {args.url}")
        self.logger.info(
            f"Parameter: {args.param if args.param else 'auto-discovering'}"
        )
        self.logger.info(f"Configuration: {webapp_config.__class__.__name__}")

        # STEP 1: AUTHENTICATE
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

        # STEP 2: PARAMETER DISCOVERY
        param_name = args.param
        context = 2  # default outside

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

                self.logger.info(
                    f"[OK] Found {len(injectable_params)} injectable parameter(s)"
                )
                self.logger.info(f"  Using: {param_name} (context: {context_type})")

                context_map = {"js": 0, "attribute": 1, "text": 2, "unknown": 2}
                context = context_map.get(context_type, 2)
            except Exception as e:
                self.logger.error(f"[ERROR] Parameter discovery error: {e}")
                return False
        else:
            if not param_name:
                self.logger.error(
                    "[ERROR] Either -p/--param or --auto-discover must be specified"
                )
                return False

            self.logger.info(f"Step 2: Using parameter: {param_name}")
            context_map = {"script": 0, "attribute": 1, "outside": 2}
            context = context_map.get(args.context, 2)
            self.logger.info(f"[OK] Context type: {args.context} (code: {context})")

        # STEP 3: BEHAVIOR ANALYSIS
        try:
            self.logger.info("Step 3: Analyzing web application behavior...")

            def test_func(payload: str) -> str:
                return webapp_config.send_payload(args.url, param_name, payload)

            analyzer = WebAppBehaviorAnalyzer(test_func, param_name)
            behaviors = analyzer.analyze()

            self.logger.info("[OK] Behavior analysis complete")
            self.logger.info(f"  Detected behaviors: {list(behaviors.keys())}")
        except Exception as e:
            self.logger.error(f"[ERROR] Behavior analysis error: {e}")
            return False

        # STEP 4: GA EVOLUTION
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
                behaviors=behaviors,
            )

            self.logger.info("Starting evolution loop...")
            population, fitness_history = engine.evolve(
                test_func, context, verbose=True
            )

            self.logger.info("Evaluating final population...")
            final_fitness_data = engine.evaluate_population(
                population, test_func, context
            )

            results = list(zip(population, final_fitness_data))
            results.sort(key=lambda x: x[1][0], reverse=True)

            best_fitness = results[0][1][0] if results else 0.0
            avg_fitness = (
                sum(fit[0] for _, fit in results) / len(results) if results else 0.0
            )

            self.logger.info("[OK] Evolution complete")
            self.logger.info(f"  Best fitness: {best_fitness:.4f}")
            self.logger.info(f"  Average fitness: {avg_fitness:.4f}")
        except Exception as e:
            self.logger.error(f"[ERROR] Evolution error: {e}")
            import traceback

            self.logger.error(traceback.format_exc())
            return False

        # STEP 5: EXPORT RESULTS
        try:
            self.logger.info("Step 5: Exporting results...")
            self.export_xss_results(results, args.output, context)
            self.logger.info("[OK] Results exported successfully")
        except Exception as e:
            self.logger.error(f"[ERROR] Export error: {e}")
            return False

        # VULNERABILITY ANALYSIS
        self.logger.info("=" * 70)
        self.logger.info("GAXSS XSS Testing Completed Successfully")
        self.logger.info("=" * 70)
        self.logger.info(f"Results: {args.output}")
        self.logger.info(f"Logs: {self.log_dir}")
        self.logger.info("=" * 70)
        self.logger.info("VULNERABILITY ANALYSIS")
        self.logger.info("=" * 70)

        vuln_payloads = []
        high_risk_payloads = []
        medium_risk_payloads = []

        for dna, fitness_data in results:
            if not isinstance(fitness_data, (list, tuple)) or len(fitness_data) < 5:
                continue

            fitness, ex, closed, dis, pu = fitness_data

            if ex >= 2.0 and closed >= 0.8 and pu <= 0.1:
                vuln_payloads.append((dna, fitness_data))
            elif ex >= 2.0 and closed >= 0.6 and pu <= 0.3:
                high_risk_payloads.append((dna, fitness_data))
            elif ex > 0.0 and ex < 2.0 and closed >= 0.5:
                medium_risk_payloads.append((dna, fitness_data))

        if vuln_payloads:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] KERENTANAN XSS TERDETEKSI - KRITIS")
            self.logger.warning("=" * 70)
            self.logger.warning(
                f"Ditemukan {len(vuln_payloads)} payload dengan indikasi eksekusi kuat:"
            )
            self.logger.warning("  - Execution Score (Ex) = 2.0")
            self.logger.warning("  - Closure Score (CLOSED) >= 0.8")
            self.logger.warning("  - Penalty Score (Pu) <= 0.1")
        elif high_risk_payloads:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] POTENSI KERENTANAN XSS - TINGGI")
            self.logger.warning("=" * 70)
            self.logger.warning(
                f"Ditemukan {len(high_risk_payloads)} payload dengan potensi eksekusi:"
            )
        elif medium_risk_payloads:
            self.logger.info("=" * 70)
            self.logger.info("[*] POTENSI KERENTANAN XSS - SEDANG")
            self.logger.info("=" * 70)
            self.logger.info(
                f"Ditemukan {len(medium_risk_payloads)} payload dengan indikasi parsial:"
            )
        else:
            self.logger.info("=" * 70)
            self.logger.info("[[OK]] TIDAK TERDETEKSI KERENTANAN XSS")
            self.logger.info("=" * 70)

        self.logger.info("=" * 70)
        return True

    # ==================== SQLi WORKFLOW ====================

    def run_sqli_test(self, args, webapp_config):
        """Run SQLi vulnerability detection workflow."""
        self.logger.info("=" * 70)
        self.logger.info("GAXSS SQLi Testing Started")
        self.logger.info("=" * 70)
        self.logger.info(f"Target URL: {args.url}")
        self.logger.info(
            f"Parameter: {args.param if args.param else 'auto-discovering'}"
        )
        self.logger.info(f"Configuration: {webapp_config.__class__.__name__}")

        # STEP 1: AUTHENTICATE
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

        # STEP 2: PARAMETER DISCOVERY (SQLi: test all params)
        if args.auto_discover:
            try:
                self.logger.info("Step 2: Auto-discovering parameters...")
                discoverer = ParameterDiscoverer(webapp_config)
                parameters = discoverer.discover_parameters(args.url)

                if not parameters:
                    self.logger.error("[ERROR] No parameters discovered!")
                    return False

                self.logger.info(f"[OK] Discovered parameters: {parameters}")

                if not hasattr(webapp_config, "param_methods"):
                    webapp_config.param_methods = {}

                for p in parameters:
                    webapp_config.param_methods[p] = discoverer.get_param_method(p)

                param_list = parameters

            except Exception as e:
                self.logger.error(f"[ERROR] Parameter discovery error: {e}")
                return False
        else:
            if not args.param:
                self.logger.error(
                    "[ERROR] Either -p/--param or --auto-discover must be specified"
                )
                return False

            param_list = [args.param]

            if not hasattr(webapp_config, "param_methods"):
                webapp_config.param_methods = {}
            webapp_config.param_methods.setdefault(args.param, "GET")

            self.logger.info(f"Step 2: Using parameter: {args.param}")

        # STEP 3: GA EVOLUTION (SQLi) untuk setiap parameter
        all_stats: List[Dict] = []
        try:
            self.logger.info("Step 3: Starting genetic algorithm evolution...")

            for param_name in param_list:
                method = webapp_config.param_methods.get(param_name, "GET")
                self.logger.info("=" * 70)
                self.logger.info(
                    f"[PARAM] Testing SQLi on '{param_name}' (method={method})"
                )
                self.logger.info("=" * 70)
                self.logger.info(f"  Population size: {args.pop}")
                self.logger.info(f"  Generations: {args.gen}")

                engine = GAXSS_Engine(
                    population_size=args.pop,
                    generations=args.gen,
                    sqli_mode=True,
                    sqli_column_count=None,
                )

                self.logger.info("Starting evolution loop...")

                population, fitness_history = engine.evolve_sqli(
                    test_func=None,
                    app_config=webapp_config,
                    target_url=args.url,
                    param_name=param_name,
                    verbose=True,
                )

                stats = engine.get_statistics()
                stats["param_name"] = param_name
                stats["method"] = method
                stats["population"] = population
                stats["fitness_data"] = fitness_history
                all_stats.append(stats)

                self.logger.info(
                    f"[OK] Evolution complete for param '{param_name}' "
                    f"(best fitness: {stats['best_fitness']:.4f})"
                )

        except Exception as e:
            self.logger.error(f"[ERROR] Evolution error: {e}")
            import traceback

            self.logger.error(traceback.format_exc())
            return False

        if not all_stats:
            self.logger.error("[ERROR] No stats collected from GA runs")
            return False

        # pilih parameter dengan fitness terbaik
        stats = max(all_stats, key=lambda s: s["best_fitness"])

        # STEP 4: EXPORT RESULTS
        try:
            self.logger.info("Step 4: Exporting results...")
            population = stats.get("population", [])
            fitness_data = stats.get("fitness_data", [])
            self.export_sqli_results(stats, population, fitness_data, args.output)
            self.logger.info("[OK] Results exported")
        except Exception as e:
            self.logger.error(f"[ERROR] Export error: {e}")
            return False

        # VULN ANALYSIS
        self.logger.info("=" * 70)
        self.logger.info("GAXSS SQLi Testing Completed Successfully")
        self.logger.info("=" * 70)
        self.logger.info(f"Results: {args.output}")
        self.logger.info(f"Logs: {self.log_dir}")
        self.logger.info("=" * 70)
        self.logger.info("VULNERABILITY ANALYSIS")
        self.logger.info("=" * 70)

        best_fitness = stats["best_fitness"]
        param_name = stats.get("param_name", "?")
        method = stats.get("method", "?")

        if best_fitness >= 0.7:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] SQL INJECTION VULNERABILITY DETECTED - CRITICAL")
            self.logger.warning("=" * 70)
            self.logger.warning(f"Parameter: {param_name} (method={method})")
            self.logger.warning(f"Best fitness: {best_fitness:.4f}")
            self.logger.warning(f"Successful payload: {stats['best_individual']}")
        elif best_fitness >= 0.3:
            self.logger.warning("=" * 70)
            self.logger.warning("[!] SQL INJECTION VULNERABILITY DETECTED - HIGH")
            self.logger.warning("=" * 70)
            self.logger.warning(f"Parameter: {param_name} (method={method})")
            self.logger.warning(f"Best fitness: {best_fitness:.4f}")
            self.logger.warning(f"Partial payload found: {stats['best_individual']}")
        else:
            self.logger.info("=" * 70)
            self.logger.info("[*] SQL INJECTION - INCONCLUSIVE")
            self.logger.info("=" * 70)
            self.logger.info(f"Best fitness achieved: {best_fitness:.4f}")
            self.logger.info(f"Best parameter tested: {param_name} (method={method})")
            self.logger.info("No clear SQL injection vulnerability detected")

        self.logger.info("=" * 70)
        return True

    # ==================== EXPORTERS ====================

    def export_xss_results(
        self,
        results: List[Tuple],
        output_dir: str,
        context: int = 2,
        ground_truth: str = "VULNERABLE",
    ):
        """Export XSS results to CSV file."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = os.path.join(output_dir, f"xss_results_{timestamp}.csv")

        try:
            payload_generator = GAXSS_PayloadGenerator()

            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                writer.writerow(
                    [
                        "Rank",
                        "Fitness",
                        "Payload",
                        "Ex",
                        "CLOSED",
                        "Dis",
                        "Pu",
                        "Risk_Level",
                        "Predicted",
                        "GroundTruth",
                    ]
                )

                for rank, (dna, fitness_data) in enumerate(results, 1):
                    try:
                        fitness, ex, closed, dis, pu = fitness_data

                        if ex >= 2.0 and closed >= 0.8 and pu <= 0.1:
                            risk_level = "CRITICAL"
                        elif ex >= 2.0 and closed >= 0.6 and pu <= 0.3:
                            risk_level = "HIGH"
                        elif ex > 0.0 and ex < 2.0 and closed >= 0.5:
                            risk_level = "MEDIUM"
                        else:
                            risk_level = "LOW"

                        predicted = (
                            "VULNERABLE" if risk_level in ["CRITICAL", "HIGH"] else "SAFE"
                        )
                        payload = payload_generator.generate_payload(
                            dna, context=context
                        )
                        payload_escaped = payload.replace('"', '""')

                        writer.writerow(
                            [
                                rank,
                                f"{fitness:.4f}",
                                f'"{payload_escaped}"',
                                f"{ex:.4f}",
                                f"{closed:.4f}",
                                f"{dis:.4f}",
                                f"{pu:.4f}",
                                risk_level,
                                predicted,
                                ground_truth,
                            ]
                        )
                    except Exception as e:
                        self.logger.warning(f"Error exporting rank {rank}: {e}")
                        continue

            self.logger.info(
                f"Results exported to {csv_file} ({len(results)} payloads)"
            )
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            raise

    def export_sqli_results(
        self,
        stats: dict,
        population: list,
        fitness_data: list,
        output_dir: str,
        ground_truth: str = "VULNERABLE",
    ):
        """Export SQLi results to CSV file (XSS-like, with real payload strings)."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = os.path.join(output_dir, f"sqli_results_{timestamp}.csv")

        try:
            results = list(zip(population, fitness_data))
            results.sort(key=lambda x: x[1], reverse=True)

            from sqli_detector.sqli_payload_generator import SQLiPayloadGenerator
            # if your module is under sqli_detector, use:
            # from sqli_detector.sqli_payload_generator import SQLiPayloadGenerator

            sqli_gen = SQLiPayloadGenerator(column_count=2)

            with open(csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)

                writer.writerow(
                    [
                        "Rank",
                        "Fitness",
                        "Payload",
                        "Risk_Level",
                        "GroundTruth",
                        "Predicted",
                        "Param_Name",
                        "Method",
                    ]
                )

                param_name = stats.get("param_name", "?")
                method = stats.get("method", "?")

                for rank, (dna, fitness) in enumerate(results, 1):
                    try:
                        if fitness >= 0.7:
                            risk_level = "CRITICAL"
                        elif fitness >= 0.3:
                            risk_level = "HIGH"
                        elif fitness >= 0.1:
                            risk_level = "MEDIUM"
                        else:
                            risk_level = "LOW"

                        predicted = "VULNERABLE" if fitness >= 0.3 else "SAFE"

                        try:
                            sql_payload = sqli_gen.dna_to_payload(dna)
                        except Exception as e:
                            self.logger.debug(f"Error generating SQLi payload: {e}")
                            sql_payload = str(dna)

                        payload_escaped = str(sql_payload).replace('"', '""')

                        writer.writerow(
                            [
                                rank,
                                f"{fitness:.4f}",
                                f'"{payload_escaped}"',
                                risk_level,
                                ground_truth,
                                predicted,
                                param_name,
                                method,
                            ]
                        )
                    except Exception as e:
                        self.logger.warning(f"Error exporting rank {rank}: {e}")
                        continue

            self.logger.info(
                f"Results exported to {csv_file} ({len(results)} payloads)"
            )
        except Exception as e:
            self.logger.error(f"Failed to export results: {e}")
            raise

    # ==================== ARGUMENT PARSING ====================

    def main(self):
        """Main CLI entry point with argument parsing."""
        parser = argparse.ArgumentParser(
            description="GAXSS - Genetic Algorithm XSS/SQLi Testing Tool (Generic)",
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )

        subparsers = parser.add_subparsers(dest="mode", help="Testing mode")

        # XSS MODE
        xss_parser = subparsers.add_parser("xss", help="XSS vulnerability testing")

        xss_parser.add_argument(
            "-u",
            "--url",
            help="Target URL (jika kosong: default DVWA/bWAPP akan digunakan)",
        )
        xss_parser.add_argument(
            "-p",
            "--param",
            help="Parameter name (required if --auto-discover not used)",
        )
        xss_parser.add_argument(
            "--auto-discover",
            action="store_true",
            help="Automatically discover vulnerable parameters",
        )

        app_group = xss_parser.add_argument_group("Web Application Type")
        app_type = app_group.add_mutually_exclusive_group(required=True)

        app_type.add_argument("--generic", action="store_true", help="Generic web app")
        app_type.add_argument("--dvwa", action="store_true", help="DVWA")
        app_type.add_argument("--bwapp", action="store_true", help="bWAPP")
        app_type.add_argument(
            "--mutillidae", action="store_true", help="OWASP Mutillidae II"
        )
        app_type.add_argument("--custom-url", type=str, help="Custom web app base URL")

        dvwa_group = xss_parser.add_argument_group("DVWA Options")
        dvwa_group.add_argument("--username", default="admin", help="DVWA username")
        dvwa_group.add_argument("--password", default="password", help="DVWA password")
        dvwa_group.add_argument(
            "--security",
            default="low",
            choices=["low", "medium", "high", "impossible"],
            help="Security level (default: low)",
        )

        ga_group = xss_parser.add_argument_group("Genetic Algorithm Configuration")
        ga_group.add_argument(
            "--pop", type=int, default=60, help="Population size (default: 60)"
        )
        ga_group.add_argument(
            "--gen", type=int, default=30, help="Generations (default: 30)"
        )
        ga_group.add_argument(
            "--context",
            default="outside",
            choices=["script", "attribute", "outside"],
            help="Injection context (default: outside)",
        )
        ga_group.add_argument(
            "--patience",
            type=int,
            default=10,
            help="Early stopping patience in generations (default: 10)",
        )

        xss_parser.add_argument(
            "-o",
            "--output",
            default="results",
            help="Output directory for results (default: results)",
        )

        # SQLi MODE
        sqli_parser = subparsers.add_parser(
            "sqli", help="SQL Injection vulnerability testing"
        )

        sqli_parser.add_argument(
            "-u", "--url", required=True, help="Target URL with vulnerable parameter"
        )
        sqli_parser.add_argument(
            "-p",
            "--param",
            help="Parameter name (required if --auto-discover not used)",
        )
        sqli_parser.add_argument(
            "--auto-discover",
            action="store_true",
            help="Automatically discover vulnerable parameters",
        )

        app_group_sqli = sqli_parser.add_argument_group("Web Application Type")
        app_type_sqli = app_group_sqli.add_mutually_exclusive_group(required=True)

        app_type_sqli.add_argument(
            "--generic", action="store_true", help="Generic web app"
        )
        app_type_sqli.add_argument("--dvwa", action="store_true", help="DVWA")
        app_type_sqli.add_argument("--bwapp", action="store_true", help="bWAPP")
        app_type_sqli.add_argument(
            "--mutillidae", action="store_true", help="OWASP Mutillidae II"
        )
        app_type_sqli.add_argument(
            "--custom-url", type=str, help="Custom base URL"
        )

        dvwa_group_sqli = sqli_parser.add_argument_group("DVWA Options")
        dvwa_group_sqli.add_argument(
            "--username", default="admin", help="DVWA username"
        )
        dvwa_group_sqli.add_argument(
            "--password", default="password", help="DVWA password"
        )
        dvwa_group_sqli.add_argument(
            "--security",
            default="low",
            choices=["low", "medium", "high", "impossible"],
            help="Security level",
        )

        ga_group_sqli = sqli_parser.add_argument_group(
            "Genetic Algorithm Configuration"
        )
        ga_group_sqli.add_argument(
            "--pop", type=int, default=40, help="Population size"
        )
        ga_group_sqli.add_argument(
            "--gen", type=int, default=20, help="Generations"
        )

        sqli_parser.add_argument(
            "-o", "--output", default="results", help="Output directory"
        )

        # BOTH MODE
        both_parser = subparsers.add_parser(
            "both", help="Run both XSS and SQLi testing"
        )

        both_parser.add_argument(
            "-u", "--url", required=True, help="Target URL with vulnerable parameter"
        )
        both_parser.add_argument(
            "-p",
            "--param",
            help="Parameter name (required if --auto-discover not used)",
        )
        both_parser.add_argument(
            "--auto-discover",
            action="store_true",
            help="Automatically discover vulnerable parameters",
        )

        app_group_both = both_parser.add_argument_group("Web Application Type")
        app_type_both = app_group_both.add_mutually_exclusive_group(required=True)

        app_type_both.add_argument("--generic", action="store_true", help="Generic web app")
        app_type_both.add_argument("--dvwa", action="store_true", help="DVWA")
        app_type_both.add_argument("--bwapp", action="store_true", help="bWAPP")
        app_type_both.add_argument(
            "--mutillidae", action="store_true", help="OWASP Mutillidae II"
        )
        app_type_both.add_argument(
            "--custom-url", type=str, help="Custom base URL"
        )

        both_parser.add_argument(
            "--username", default="admin", help="DVWA username (if applicable)"
        )
        both_parser.add_argument(
            "--password", default="password", help="DVWA password (if applicable)"
        )
        both_parser.add_argument(
            "--security",
            default="low",
            choices=["low", "medium", "high", "impossible"],
            help="Security level",
        )

        ga_group_both = both_parser.add_argument_group(
            "Genetic Algorithm Configuration"
        )
        ga_group_both.add_argument(
            "--pop", type=int, default=60, help="Population size for both scans"
        )
        ga_group_both.add_argument(
            "--gen", type=int, default=30, help="Generations for both scans"
        )

        both_parser.add_argument(
            "-o", "--output", default="results", help="Output directory"
        )

        # PARSE
        args = parser.parse_args()

        if not args.mode:
            parser.print_help()
            return

        # Default URL for XSS if omitted
        if args.mode == "xss":
            if not args.url:
                if getattr(args, "dvwa", False):
                    args.url = "http://127.0.0.1:8081/vulnerabilities/xss_r/"
                elif getattr(args, "bwapp", False):
                    args.url = "http://127.0.0.1:8082/xss_get.php"
                elif getattr(args, "mutillidae", False):
                    args.url = "http://localhost:9000/index.php?page=user-info.php"

            if (args.generic or args.custom_url) and not args.url:
                self.logger.error("Error: untuk generic/custom, -u/--url wajib diisi")
                xss_parser.print_help()
                return

        # EXECUTION
        if args.mode == "xss":
            if not args.auto_discover and not args.param:
                self.logger.error(
                    "Error: Either -p/--param or --auto-discover must be specified"
                )
                xss_parser.print_help()
                return

            try:
                if args.generic:
                    webapp_config = GenericWebApp(base_url="")
                elif args.dvwa:
                    from dvwa_config import DVWAConfig

                    base_url = self._extract_base_url(args.url)
                    webapp_config = DVWAConfig(
                        base_url=base_url,
                        username=args.username,
                        password=args.password,
                        security_level=args.security,
                    )
                elif args.custom_url:
                    webapp_config = GenericWebApp(base_url=args.custom_url)
                elif args.bwapp:
                    from bwapp_config import BWAPPConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://localhost:8082"
                    )
                    webapp_config = BWAPPConfig(
                        base_url=base_url,
                        username="bee",
                        password="bug",
                        security_level=args.security,
                    )
                elif args.mutillidae:
                    from mutillidae_config import MutillidaeConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://127.0.0.1:9000"
                    )
                    if args.security == "low":
                        security_level = "0"
                    elif args.security == "medium":
                        security_level = "1"
                    else:
                        security_level = "2"
                    webapp_config = MutillidaeConfig(
                        base_url=base_url, security_level=security_level
                    )
                else:
                    self.logger.error(
                        "Must specify one of: --generic, --dvwa, --bwapp, --mutillidae, --custom-url"
                    )
                    xss_parser.print_help()
                    return

                success = self.run_xss_test(args, webapp_config)
                sys.exit(0 if success else 1)
            except ImportError as e:
                self.logger.error(f"Configuration module not found: {e}")
                return
            except Exception as e:
                self.logger.error(f"Error: {e}")
                import traceback

                self.logger.error(traceback.format_exc())
                sys.exit(1)

        elif args.mode == "sqli":
            if not args.auto_discover and not args.param:
                self.logger.error(
                    "Error: Either -p/--param or --auto-discover required"
                )
                sqli_parser.print_help()
                return

            try:
                if args.generic:
                    webapp_config = GenericWebApp(base_url="")
                elif args.dvwa:
                    from dvwa_config import DVWAConfig

                    base_url = self._extract_base_url(args.url)
                    webapp_config = DVWAConfig(
                        base_url=base_url,
                        username=args.username,
                        password=args.password,
                        security_level=args.security,
                    )
                elif args.bwapp:
                    from bwapp_config import BWAPPConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://localhost:8082"
                    )
                    webapp_config = BWAPPConfig(
                        base_url=base_url,
                        security_level=args.security,
                        vulnerability="sqli",
                    )
                elif args.mutillidae:
                    from mutillidae_config import MutillidaeConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://127.0.0.1:9000"
                    )
                    if args.security == "low":
                        security_level = "0"
                    elif args.security == "medium":
                        security_level = "1"
                    else:
                        security_level = "2"
                    webapp_config = MutillidaeConfig(
                        base_url=base_url, security_level=security_level
                    )
                elif args.custom_url:
                    webapp_config = GenericWebApp(base_url=args.custom_url)
                else:
                    self.logger.error(
                        "Must specify: --generic, --dvwa, --bwapp, --mutillidae, or --custom-url"
                    )
                    return

                success = self.run_sqli_test(args, webapp_config)
                sys.exit(0 if success else 1)
            except ImportError as e:
                self.logger.error(f"Configuration module not found: {e}")
                return
            except Exception as e:
                self.logger.error(f"Error: {e}")
                import traceback

                self.logger.error(traceback.format_exc())
                sys.exit(1)

        elif args.mode == "both":
            if not args.auto_discover and not args.param:
                self.logger.error(
                    "Error: Either -p/--param or --auto-discover required"
                )
                both_parser.print_help()
                return

            try:
                if args.generic:
                    webapp_config = GenericWebApp(base_url="")
                elif args.dvwa:
                    from dvwa_config import DVWAConfig

                    base_url = self._extract_base_url(args.url)
                    webapp_config = DVWAConfig(
                        base_url=base_url,
                        username=args.username,
                        password=args.password,
                        security_level=args.security,
                    )
                elif args.bwapp:
                    from bwapp_config import BWAPPConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://localhost:8082"
                    )
                    webapp_config = BWAPPConfig(
                        base_url=base_url,
                        security_level=args.security,
                        vulnerability="sqli",
                    )
                elif args.mutillidae:
                    from mutillidae_config import MutillidaeConfig

                    base_url = self._extract_base_url(
                        args.url, default="http://127.0.0.1:9000"
                    )
                    if args.security == "low":
                        security_level = "0"
                    elif args.security == "medium":
                        security_level = "1"
                    else:
                        security_level = "2"
                    webapp_config = MutillidaeConfig(
                        base_url=base_url, security_level=security_level
                    )
                elif args.custom_url:
                    webapp_config = GenericWebApp(base_url=args.custom_url)
                else:
                    self.logger.error(
                        "Must specify: --generic, --dvwa, --bwapp, --mutillidae, or --custom-url"
                    )
                    return

                self.logger.info("=== Running XSS scan (BOTH mode) ===")
                success_xss = self.run_xss_test(args, webapp_config)

                self.logger.info("=== Running SQLi scan (BOTH mode) ===")
                success_sqli = self.run_sqli_test(args, webapp_config)

                sys.exit(0 if (success_xss and success_sqli) else 1)

            except ImportError as e:
                self.logger.error(f"Configuration module not found: {e}")
                return
            except Exception as e:
                self.logger.error(f"Error: {e}")
                import traceback

                self.logger.error(traceback.format_exc())
                sys.exit(1)

    @staticmethod
    def _extract_base_url(url: str, default: str = "http://localhost") -> str:
        """Extract base URL from target URL."""
        match = re.match(r"(https?://[^/]+)", url)
        return match.group(1) if match else default


def main():
    cli = GAXSS_CLI()
    cli.main()


if __name__ == "__main__":
    main()
