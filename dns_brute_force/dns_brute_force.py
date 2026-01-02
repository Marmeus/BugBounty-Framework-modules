"""
DNS Brute Force Module
Combines DNS wordlist generation and domain checking functionality
Refactored from WORKER/Docker/bot/IG/dns_wordlist_generator.py and domain_checker.py
"""
import subprocess
import traceback
import logging
import os
from typing import Dict, Any, List, Optional
from utils_osint import (
    create_random_file, 
    remove_file, 
    save_list_to_file, 
    file_to_list, 
    read_errors,
    detect_domain_level,
    check_scope
)


def save_domain_to_file(domain: str, filename: str):
    """Save a single domain to a file"""
    with open(filename, 'w') as file:
        file.write(domain + '\n')


class DNSBruteForceModule:
    """DNS brute force module combining wordlist generation and domain checking"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize DNS brute force module
        
        Args:
            config: Configuration dictionary containing:
                - domains: List of domains to brute force
                - in_scope_rules: List of in-scope patterns
                - out_scope_rules: List of out-of-scope patterns
                - increase_depth: Number of depth levels to increase (default: 1)
                - tools: Tools to use (optional)
                - program_id: Program identifier (optional)
                - env_vars: Environment variables dict (optional, defaults to os.environ)
        
        Note:
            Debug mode is controlled via DEBUG environment variable (from Dockerfile),
            not through config parameter.
        """
        self.domains = config.get('domains', [])
        self.in_scope_rules = config.get('in_scope_rules', [])
        self.out_scope_rules = config.get('out_scope_rules', [])
        self.increase_depth = config.get('increase_depth', 1)
        self.tools = config.get('tools', None)
        # Get debug from environment variable (from Dockerfile)
        self.debug = os.getenv('DEBUG', 'false').lower() in ('true', '1', 'yes')
        self.program_id = config.get('program_id', -1)
        
        # Set up environment variables
        self.env_vars = config.get('env_vars', os.environ.copy())
        
        # Set up logger
        self.logger = self._setup_logger(config.get('logger_config', {}))
    
    def _setup_logger(self, logger_config: Dict[str, Any]) -> logging.Logger:
        """Setup logger for the module"""
        logger = logging.getLogger('DNSBruteForceModule')
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                logger_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def append_wordlist_data(self, domain: str, output_file: str):
        """Append wordlist data from amass and assetnote wordlists"""
        self.logger.info("BRUTE DOMAINS - Executing wordlist generator command...")
        try:
            # Use environment variables for wordlist paths (from Dockerfile)
            wordlists_path = os.getenv('WORDLISTS_PATH', '/wordlists')
            cmd = f"cat {wordlists_path}/best-dns-wordlist.txt {wordlists_path}/amass-all.txt | sed 's/$/.{domain}/' | anew -q {output_file}"
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                env=self.env_vars
            )
        except Exception as e:
            self.logger.error(f"BRUTE DOMAINS - WORDLIST GENERATOR Error: {e}")
            self.logger.error(f"Stack trace: {traceback.format_exc()}")
    
    def gotator(self, domain: str, output_file: str, error_file: str):
        """Run gotator to generate subdomain permutations"""
        self.logger.info("BRUTE DOMAINS - Executing gotator command...")
        domain_file = ""
        try:
            domain_file = create_random_file()
            save_domain_to_file(domain, domain_file)
            
            # Use environment variables for wordlist paths (from Dockerfile)
            wordlists_path = os.getenv('WORDLISTS_PATH', '/wordlists')
            
            if self.debug:
                cmd = f"gotator -sub {domain_file} -perm {wordlists_path}/magnalsix.txt -depth 1 -numbers 0 -mindup -adv -md -silent 2>{error_file} | anew -q {output_file}"
            else:
                cmd = f"gotator -sub {domain_file} -perm {wordlists_path}/magnalsix.txt -depth 2 -numbers 1 -mindup -adv -md -silent 2>{error_file} | anew -q {output_file}"
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                env=self.env_vars
            )
        except Exception as e:
            self.logger.error(f"BRUTE DOMAINS - GOTATOR Error: {e}")
            self.logger.error(f"Stack trace: {traceback.format_exc()}")
        finally:
            if domain_file:
                remove_file(domain_file)
    
    def generate_wordlist(self) -> Dict[str, Any]:
        """Generate wordlist using gotator and wordlist files"""
        results = {"output": [], "errors": []}
        output_file = ""
        gotator_error_file = ""
        new_domains = self.domains
        
        self.logger.debug(f"BRUTE DOMAINS - Domains: {self.domains}, Program ID: {self.program_id}")
        
        for i in range(self.increase_depth):
            scan_domains = new_domains
            for domain in scan_domains:
                try:
                    self.logger.info(f"BRUTE DOMAINS - Generating subdomains wordlist from domain '{domain}'...")
                    
                    output_file = create_random_file()
                    self.logger.debug(f"BRUTE DOMAINS - Output file: {output_file}")
                    gotator_error_file = create_random_file()
                    self.logger.debug(f"BRUTE DOMAINS - Gotator Error file: {gotator_error_file}")
                    
                    # Obtain domains using gotator
                    self.gotator(domain, output_file, gotator_error_file)
                    
                    # Read error_file to obtain the errors
                    error_content = read_errors(gotator_error_file)
                    if error_content:
                        results["errors"].append(f"BRUTE DOMAINS - ERROR GOTATOR '{domain}': {error_content}")
                    
                    # Append to the gotator wordlist a bunch of subdomains to brute force from amass and assetnote wordlists
                    self.append_wordlist_data(domain, output_file)
                    
                    new_domains = file_to_list(output_file)
                    if not new_domains:
                        self.logger.info("BRUTE DOMAINS - No new domains found")
                        continue
                    results["output"].extend(new_domains)
                except Exception as e:
                    self.logger.error(f"BRUTE DOMAINS - Error: {e}")
                    self.logger.error(f"Stack trace: {traceback.format_exc()}")
                finally:
                    if gotator_error_file:
                        remove_file(gotator_error_file)
                    if output_file:
                        remove_file(output_file)
        
        return results
    
    def tag_domains(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Tag domains with level, scope, and tools information"""
        results = []
        for domain in domains:
            domain_level = detect_domain_level(domain)
            in_scope = check_scope(domain, self.in_scope_rules, self.out_scope_rules)
            tools = ["gotator"]
            domain_data = {
                "host": domain,
                "level": domain_level,
                "in_scope": in_scope,
                "tools": tools,
                "program_id": self.program_id
            }
            results.append(domain_data)
        return results
    
    def check_domains(self, domains: List[str]) -> Dict[str, Any]:
        """Check if domains resolve using puredns"""
        results = {"output": [], "errors": []}
        error_file = ""
        domains_file = ""
        output_file = ""
        
        try:
            self.logger.info("DOMAIN CHECKER - Storing domains in a temporary file")
            domains_file = create_random_file()
            output_file = create_random_file()
            error_file = create_random_file()
            save_list_to_file(domains, domains_file)
            
            self.logger.info("DOMAIN CHECKER - Executing resolving domains")
            
            # Use environment variables for paths (from Dockerfile)
            massdns_path = os.getenv('MASSDNS_PATH', '/usr/local/bin/massdns')
            resolvers_path = os.getenv('RESOLVERS_PATH', '/resolvers/resolvers.txt')
            resolvers_trusted_path = os.getenv('RESOLVERS_TRUSTED_PATH', '/resolvers/resolvers-trusted.txt')
            
            cmd = (
                f"puredns resolve {domains_file} --bin {massdns_path} "
                f"-r {resolvers_path} --resolvers-trusted {resolvers_trusted_path} "
                f"-l 0 --rate-limit-trusted 500 --wildcard-tests 30 --wildcard-batch 1500000 -q "
                f"2>{error_file} | anew -q {output_file}"
            )
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=True,
                env=self.env_vars
            )
            
            resolved_domains = file_to_list(output_file)
            
            # If there are tools, means that we need to register the domains in the database
            if self.tools:
                results["output"].extend(self.tag_domains(resolved_domains))
            else:
                # Because the domains are already registered in the database, we only need to return the domains that respond to the query
                results['output'] = resolved_domains
            
            self.logger.debug(f"DOMAIN CHECKER - Output: {results['output']}")
            
            error_content = read_errors(error_file)
            if error_content:
                results["errors"].append(f"DOMAIN CHECKER - ERROR PUREDNS: {error_content}")
        except Exception as e:
            self.logger.error(f"DOMAIN CHECKER - Error: {e}")
            stack_trace = traceback.format_exc()
            self.logger.error(f"DOMAIN CHECKER - Stack trace: {stack_trace}")
        finally:
            if domains_file:
                remove_file(domains_file)
            if error_file:
                remove_file(error_file)
            if output_file:
                remove_file(output_file)
        
        return results
    
    def run(self) -> Dict[str, Any]:
        """Execute DNS brute force: generate wordlist and check domains"""
        self.logger.info(f"Running DNS brute force for {len(self.domains)} domains")
        
        # Step 1: Generate wordlist
        wordlist_results = self.generate_wordlist()
        
        # Step 2: Check if generated domains resolve
        if wordlist_results["output"]:
            check_results = self.check_domains(wordlist_results["output"])
            
            # Combine results
            results = {
                "output": check_results["output"],
                "errors": wordlist_results["errors"] + check_results["errors"]
            }
        else:
            results = wordlist_results
        
        return results

