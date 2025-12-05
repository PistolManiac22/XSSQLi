"""
GAXSS Main CLI Interface with DVWA Authentication & Auto-Discovery
"""

import argparse
import logging
import csv
import os
from datetime import datetime
import requests
from bs4 import BeautifulSoup

from gaxss_engine import GAXSS_Engine
from payload_generator import GAXSS_PayloadGenerator
from parameter_discoverer import ParameterDiscoverer


# Global session for DVWA authentication
_SESSION = None


def get_session():
    """Get or create authenticated session."""
    global _SESSION
    if _SESSION is None:
        _SESSION = requests.Session()
    return _SESSION


def login_dvwa(base_url="http://localhost/dvwa", security_level="low", username="admin", password="password"):
    """
    Login to DVWA and set security level.
    
    Args:
        base_url: Base URL DVWA
        security_level: low, medium, high, impossible
        username: DVWA username
        password: DVWA password
        
    Returns:
        Authenticated session or None if failed
    """
    global _SESSION
    
    logger = logging.getLogger('GAXSS')
    
    try:
        if _SESSION is None:
            _SESSION = requests.Session()
        
        login_url = f"{base_url}/login.php"
        
        logger.info(f"Getting login page from {login_url}")
        r = _SESSION.get(login_url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        token = token_input['value'] if token_input else ""
        
        if not token:
            logger.warning("Could not find CSRF token, proceeding anyway")
        else:
            logger.info(f"Found CSRF token: {token[:20]}...")
        
        # Login data
        login_data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": token
        }
        
        logger.info(f"Attempting login with username: {username}")
        r = _SESSION.post(login_url, data=login_data, timeout=10, allow_redirects=True)
        
        if r.status_code != 200:
            logger.error(f"Login returned status {r.status_code}")
            return None
        
        # Set security level
        security_url = f"{base_url}/security.php"
        logger.info(f"Setting security level to {security_level}")
        r = _SESSION.get(security_url, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        token_input = soup.find('input', {'name': 'user_token'})
        token = token_input['value'] if token_input else ""
        
        security_data = {
            "security": security_level,
            "seclev_submit": "Submit",
            "user_token": token
        }
        r = _SESSION.post(security_url, data=security_data, timeout=10)
        
        logger.info(f"[OK] DVWA logged in (security={security_level})")
        return _SESSION
        
    except Exception as e:
        logger.error(f"[ERROR] Login failed: {e}")
        return None


def send_payload(url, param, payload, session=None):
    """Send payload via GET request."""
    if session is None:
        session = get_session()
    
    try:
        params = {param: payload}
        r = session.get(url, params=params, timeout=10)
        return r.text
    except Exception as e:
        logger = logging.getLogger('GAXSS')
        logger.warning(f"Error sending payload: {e}")
        return ""


class GAXSS_CLI:
    """Command-line interface for GAXSS."""

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

    def run_xss_test(self, args):
        """Run XSS vulnerability detection."""
        self.logger.info("Starting XSS Test")
        self.logger.info(f"Target: {args.url}")
        
        # Extract base URL for login
        import re
        base_url_match = re.match(r'(https?://[^/]+/[^/]+)', args.url)
        if base_url_match:
            base_url = base_url_match.group(1)
        else:
            base_url = "http://localhost/dvwa"
        
        # Login to DVWA
        self.logger.info(f"Logging into DVWA at {base_url}")
        session = login_dvwa(
            base_url=base_url,
            security_level=args.security or "low",
            username=args.username,
            password=args.password
        )
        
        if session is None:
            self.logger.error("Failed to login to DVWA. Exiting.")
            return

        # Auto-discover parameters if requested
        if args.auto_discover:
            self.logger.info("Auto-discovering vulnerable parameters...")
            discoverer = ParameterDiscoverer(session)
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
            self.logger.info(f"Parameter: {args.param}")
            context_map = {'script': 0, 'attribute': 1, 'outside': 2}
            context = context_map.get(args.context, 2)

        # Configure GA engine
        engine = GAXSS_Engine(
            population_size=args.pop,
            generations=args.gen,
            patience=args.patience,
            mutation_prob=0.2
        )

        # Test function
        def test_func(payload):
            return send_payload(args.url, args.param, payload, session)

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

        with open(csv_file, 'w', newline='') as f:
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
            description='GAXSS - Genetic Algorithm XSS Testing Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  Manual parameter:
    python main_gaxss.py xss -u "http://localhost/dvwa/vulnerabilities/xss_r/" -p "name"
  
  Auto-discover parameters:
    python main_gaxss.py xss -u "http://localhost/dvwa/vulnerabilities/xss_r/" --auto-discover
  
  Custom credentials:
    python main_gaxss.py xss -u "..." -p "name" --username admin --password password
  
  Different security level:
    python main_gaxss.py xss -u "..." -p "name" --security medium --gen 30
            """
        )

        subparsers = parser.add_subparsers(dest='mode', help='Testing mode')

        # XSS mode
        xss_parser = subparsers.add_parser('xss', help='XSS vulnerability testing')
        xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
        xss_parser.add_argument('-p', '--param', help='Parameter name (required if --auto-discover not used)')
        xss_parser.add_argument('--auto-discover', action='store_true', 
                               help='Automatically discover vulnerable parameters')
        xss_parser.add_argument('--username', default='admin', help='DVWA username (default: admin)')
        xss_parser.add_argument('--password', default='password', help='DVWA password (default: password)')
        xss_parser.add_argument('--security', default='low', choices=['low', 'medium', 'high', 'impossible'], 
                               help='DVWA security level')
        xss_parser.add_argument('--pop', type=int, default=60, help='Population size (default: 60)')
        xss_parser.add_argument('--gen', type=int, default=30, help='Generations (default: 30)')
        xss_parser.add_argument('--context', default='outside', choices=['script', 'attribute', 'outside'], 
                               help='Injection context')
        xss_parser.add_argument('--patience', type=int, default=10, help='Early stopping patience (default: 10)')
        xss_parser.add_argument('-o', '--output', default='results', help='Output directory (default: results)')

        args = parser.parse_args()

        if not args.mode:
            parser.print_help()
            return

        if args.mode == 'xss':
            # Check if parameter specified or auto-discover requested
            if not args.param and not args.auto_discover:
                self.logger.error("Either -p/--param or --auto-discover must be specified")
                parser.print_help()
                return
            
            self.run_xss_test(args)


if __name__ == '__main__':
    cli = GAXSS_CLI()
    cli.main()
