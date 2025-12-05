"""
GAXSS Main CLI Interface - Generic Version
Works with any web application via configuration classes
"""

import argparse
import logging
import csv
import os
from datetime import datetime
import re

from gaxss_engine import GAXSS_Engine
from payload_generator import GAXSS_PayloadGenerator
from parameter_discoverer import ParameterDiscoverer
from webapp_config import GenericWebApp
from webapp_behavior_analyzer import WebAppBehaviorAnalyzer


class GAXSS_CLI:
    """Command-line interface for GAXSS (Generic)."""

    def __init__(self, output_dir: str = 'results', log_dir: str = 'logs'):
        self.output_dir = output_dir
        self.log_dir = log_dir

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

        self.setup_logging()

    def setup_logging(self):
        """Setup logging configuration."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(self.log_dir, f'gaxss_{timestamp}.log')

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('GAXSS')
        self.logger.info("GAXSS Tool Started")

    def run_xss_test(self, args, webapp_config):
        """Run XSS vulnerability detection."""
        self.logger.info("Starting XSS Test")
        self.logger.info(f"Target: {args.url}")
        
        # Authenticate to web application
        self.logger.info(f"Authenticating to web application...")
        session = webapp_config.authenticate()
        
        if session is None:
            self.logger.error("Failed to authenticate. Exiting.")
            return

        # Auto-discover parameters if requested
        if args.auto_discover:
            self.logger.info("Auto-discovering vulnerable parameters...")
            discoverer = ParameterDiscoverer(webapp_config)
            injectable_params = discoverer.find_injectable_parameters(args.url)
            
            if not injectable_params:
                self.logger.error("No injectable parameters found!")
                return
            
            # Use first found parameter
            param_name = list(injectable_params.keys())[0]
            context_type = injectable_params[param_name]
            
            self.logger.info(f"Using parameter: {param_name} (context: {context_type})")
            args.param = param_name
            
            # Map context to numeric value
            context_map = {'js': 0, 'attribute': 1, 'text': 2, 'unknown': 2}
            context = context_map.get(context_type, 2)
        else:
            # Manual parameter specified
            if not args.param:
                self.logger.error("Either -p/--param or --auto-discover must be specified")
                return
            
            self.logger.info(f"Parameter: {args.param}")
            context_map = {'script': 0, 'attribute': 1, 'outside': 2}
            context = context_map.get(args.context, 2)

        # Define test function
        def test_func(payload):
            return webapp_config.send_payload(args.url, args.param, payload)

        # ANALYZE WEB APP BEHAVIOR
        self.logger.info("Analyzing web application behavior...")
        analyzer = WebAppBehaviorAnalyzer(test_func, args.param)
        behaviors = analyzer.analyze()

        # Configure GA engine with behaviors
        engine = GAXSS_Engine(
            population_size=args.pop,
            generations=args.gen,
            patience=args.patience,
            mutation_prob=0.2,
            behaviors=behaviors
        )

        # Run evolution
        self.logger.info("Starting genetic algorithm evolution...")
        population, fitness_history = engine.evolve(test_func, context, verbose=True)

        # Evaluate final population
        final_fitness_data = engine.evaluate_population(population, test_func, context)

        # Sort by fitness
        results = list(zip(population, final_fitness_data))
        results.sort(key=lambda x: x[1][0], reverse=True)

        # Export results
        self.export_xss_results(results, args.output)

        # Summary
        best_fitness = results[0][1][0] if results else 0.0
        self.logger.info(f"Best Fitness: {best_fitness:.4f}")
        self.logger.info(f"Results exported to {args.output}")

    def export_xss_results(self, results, output_dir: str):
        """Export XSS results to CSV."""
        os.makedirs(output_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        csv_file = os.path.join(output_dir, f'xss_results_{timestamp}.csv')

        payload_generator = GAXSS_PayloadGenerator()

        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Rank', 'Fitness', 'Payload', 'Ex', 'CLOSED', 'Dis', 'Pu'])

            for rank, (dna, fitness_data) in enumerate(results, 1):
                fitness, ex, closed, dis, pu = fitness_data
                payload = payload_generator.generate_payload(dna, 2)

                writer.writerow([
                    rank,
                    f'{fitness:.4f}',
                    payload,
                    f'{ex:.4f}',
                    f'{closed:.4f}',
                    f'{dis:.4f}',
                    f'{pu:.4f}'
                ])

        self.logger.info(f"Results exported to {csv_file}")

    def main(self):
        """Main CLI entry point."""
        parser = argparse.ArgumentParser(
            description='GAXSS - Genetic Algorithm XSS Testing Tool (Generic)',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples (Generic Web App):
  python main_gaxss.py xss -u "http://example.com/search" -p "q" --generic

Examples (DVWA):
  python main_gaxss.py xss -u "http://localhost/dvwa/vulnerabilities/xss_r/" -p "name" --dvwa
  python main_gaxss.py xss -u "http://localhost/dvwa/vulnerabilities/xss_r/" --dvwa --auto-discover --security medium

Examples (Custom Web App):
  python main_gaxss.py xss -u "http://myapp.local/search" -p "query" --custom-url "http://myapp.local"
            """
        )

        subparsers = parser.add_subparsers(dest='mode', help='Testing mode')

        # XSS mode
        xss_parser = subparsers.add_parser('xss', help='XSS vulnerability testing')
        xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
        xss_parser.add_argument('-p', '--param', help='Parameter name')
        xss_parser.add_argument('--auto-discover', action='store_true', 
                               help='Automatically discover vulnerable parameters')
        
        # Web app type selection
        app_group = xss_parser.add_argument_group('Web Application Type')
        app_type = app_group.add_mutually_exclusive_group(required=True)
        app_type.add_argument('--generic', action='store_true', help='Generic web app (no auth)')
        app_type.add_argument('--dvwa', action='store_true', help='DVWA (Damn Vulnerable Web App)')
        app_type.add_argument('--bwapp', action='store_true', help='bWAPP (Buggy Web Application)')
        app_type.add_argument('--custom-url', type=str, help='Custom web app (provide base URL)')
        
        # DVWA-specific options
        dvwa_group = xss_parser.add_argument_group('DVWA Options')
        dvwa_group.add_argument('--username', default='admin', help='DVWA username (default: admin)')
        dvwa_group.add_argument('--password', default='password', help='DVWA password (default: password)')
        dvwa_group.add_argument('--security', default='low', choices=['low', 'medium', 'high', 'impossible'],
                               help='DVWA security level (default: low)')
        
        # bWAPP-specific options
        bwapp_group = xss_parser.add_argument_group('bWAPP Options')
        bwapp_group.add_argument('--bwapp-user', default='bee', help='bWAPP username (default: bee)')
        bwapp_group.add_argument('--bwapp-pass', default='bug', help='bWAPP password (default: bug)')
        bwapp_group.add_argument('--vulnerability', default='xss_reflected', 
                                help='bWAPP vulnerability (default: xss_reflected)')
        
        # GA options
        ga_group = xss_parser.add_argument_group('Genetic Algorithm Options')
        ga_group.add_argument('--pop', type=int, default=60, help='Population size (default: 60)')
        ga_group.add_argument('--gen', type=int, default=30, help='Generations (default: 30)')
        ga_group.add_argument('--context', default='outside', choices=['script', 'attribute', 'outside'],
                             help='Injection context (default: outside)')
        ga_group.add_argument('--patience', type=int, default=10, help='Early stopping patience (default: 10)')
        
        # Output options
        xss_parser.add_argument('-o', '--output', default='results', help='Output directory (default: results)')

        args = parser.parse_args()

        if not args.mode:
            parser.print_help()
            return

        if args.mode == 'xss':
            # Determine which webapp configuration to use
            if args.generic:
                webapp_config = GenericWebApp(base_url="")
                self.logger.info("Using Generic Web App configuration")
            
            elif args.dvwa:
                from dvwa_config import DVWAConfig
                base_url_match = re.match(r'(https?://[^/]+)', args.url)
                base_url = base_url_match.group(1) if base_url_match else "http://localhost:8082"
                
                webapp_config = DVWAConfig(
                    base_url=base_url,
                    username=args.username,
                    password=args.password,
                    security_level=args.security
                )
                self.logger.info(f"Using DVWA configuration at {base_url}")
                
            elif args.bwapp:
                from bwapp_config import BWAPPConfig
                base_url_match = re.match(r'(https?://[^/]+)', args.url)
                base_url = base_url_match.group(1) if base_url_match else "http://localhost:8082"
                
                webapp_config = BWAPPConfig(
                    base_url=base_url,
                    username=args.bwapp_user,
                    password=args.bwapp_pass,
                    vulnerability=args.vulnerability,
                    security_level=args.security
                )
                self.logger.info(f"Using bWAPP configuration at {base_url}")
            
            elif args.custom_url:
                webapp_config = GenericWebApp(base_url=args.custom_url)
                self.logger.info(f"Using Generic Web App configuration at {args.custom_url}")
            
            else:
                self.logger.error("Must specify --generic, --dvwa, --bwapp, or --custom-url")
                parser.print_help()
                return
            
            self.run_xss_test(args, webapp_config)


if __name__ == '__main__':
    cli = GAXSS_CLI()
    cli.main()
