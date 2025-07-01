from bandit.core import manager, config
import os
import sys
import argparse
import glob
from colorama import Fore, Style

class Scanner:
    def __init__(self):
        pass
           
    def run_bandit_scan(self, targets, test_ids=None):
        try:
            # Initialize the bandit manager
            bandit_config = config.BanditConfig()
            
            if test_ids:
                if not isinstance(test_ids, (list, tuple)):
                    raise ValueError(f"{Fore.RED}test_ids must be a list or tuple{Style.RESET_ALL}")
                bandit_config.config['tests'] = test_ids
                
            bandit_manager = manager.BanditManager(config=bandit_config, agg_type='file', debug=False, verbose=False)
                               
            # Configuration of the manager
            if not targets:
                raise ValueError(f"{Fore.RED}No targets provided for scanning{Style.RESET_ALL}")
            if not isinstance(targets, (list, tuple)):
                raise ValueError(f"{Fore.RED}Targets must be a list or tuple{Style.RESET_ALL}")
                
            bandit_manager.discover_files(targets, recursive=True)  
            bandit_manager.run_tests()
                
            return bandit_manager.results
        
        except Exception as e:
            print(f"{Fore.RED}Error during the scanning: {e}{Style.RESET_ALL}")
            return None                                              

    def display_results(self, results):
        if not results:
            print(f"{Fore.GREEN}No security issues found! Everything looks secured.{Style.RESET_ALL}")
            return
        
        try:
            print(f"{Fore.CYAN}Scan Results: {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Found {len(results)} potential vulnerabilities.{Style.RESET_ALL}")
        
            for issue in results:
                if not hasattr(issue, 'severity'):
                    continue  # Skip malformed results
                print(f"\n{Fore.YELLOW}Severity: {getattr(issue, 'severity', 'unknown').capitalize()}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Confidence: {getattr(issue, 'confidence', 'unknown').capitalize()}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Location: {getattr(issue, 'fname', 'unknown')}:{getattr(issue, 'lineno', 'unknown')}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Code: {getattr(issue, 'text', 'unknown')}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Description: {getattr(issue, 'test_id', 'unknown')}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Error displaying results: {str(e)}{Style.RESET_ALL}")
            
    
    def scan_file(self, file_path):
        try:
            if not file_path or not isinstance(file_path, str):
                raise ValueError(f"{Fore.RED}Invalid file path{Style.RESET_ALL}")
                
            if not os.path.exists(file_path):
                print(f"{Fore.RED}File not found!{Style.RESET_ALL}")
                return
                
            if not os.path.isfile(file_path):
                print(f"{Fore.RED}Path is not a file!{Style.RESET_ALL}")
                return
                
            print(f"{Fore.YELLOW}Scanning File: {file_path}{Style.RESET_ALL}")
            results = self.run_bandit_scan([file_path])
            self.display_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}Error scanning file: {str(e)}{Style.RESET_ALL}")

        
    def scan_directory(self, directory_path):
        try:
            if not directory_path or not isinstance(directory_path, str):
                raise ValueError(f"{Fore.RED}Invalid directory path{Style.RESET_ALL}")
                
            if not os.path.exists(directory_path):
                print(f"{Fore.RED}Directory not found!{Style.RESET_ALL}")
                return
                
            if not os.path.isdir(directory_path):
                print(f"{Fore.RED}Path is not a directory!{Style.RESET_ALL}")
                return
                
            print(f"{Fore.YELLOW}Scanning Directory: {directory_path}{Style.RESET_ALL}")
            python_files = glob.glob(os.path.join(directory_path, '**', '*.py'), recursive=True)
            if not python_files:
                print(f"{Fore.RED}No python files found in the directory!{Style.RESET_ALL}")
                return
            
            results = self.run_bandit_scan(python_files)
            self.display_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}Error scanning directory: {str(e)}{Style.RESET_ALL}")                  
         
 
       
    def check_injection_flaws(self, target_path):
        try:
            if not target_path or not isinstance(target_path, str):
                raise ValueError(f"{Fore.RED}Invalid target path{Style.RESET_ALL}")
                
            if not os.path.exists(target_path):
                print(f"{Fore.RED}Target not found!{Style.RESET_ALL}")
                return
                
            if os.path.isfile(target_path):
                target = [target_path]
            elif os.path.isdir(target_path):
                target = glob.glob(os.path.join(target_path, "**", "*.py"), recursive=True)
                if not target:
                    print(f"{Fore.RED}No python files found in the directory!{Style.RESET_ALL}")
                    return
            else:
                print(f"{Fore.RED}Target is neither file nor directory!{Style.RESET_ALL}")
                return                        
            
            print(f"{Fore.YELLOW}Checking for injection flaws in: {target_path}{Style.RESET_ALL}")
            
            test_ids = ["B601", "B602", "B603", "B604", "B605", "B606", "B607", "B608"]
            results = self.run_bandit_scan(target, test_ids=test_ids)   
            
            self.display_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}Error checking injection flaws: {str(e)}{Style.RESET_ALL}")
        
    
    def check_weak_cryptography(self, target_path):
        try:
            if not target_path or not isinstance(target_path, str):
                raise ValueError(f"{Fore.RED}Invalid target path{Style.RESET_ALL}")
                
            if not os.path.exists(target_path):
                print(f"{Fore.RED}Target not found!{Style.RESET_ALL}")
                return
                
            if os.path.isfile(target_path):
                target = [target_path]
            elif os.path.isdir(target_path):
                target = glob.glob(os.path.join(target_path, "**", "*.py"), recursive=True)
                if not target:
                    print(f"{Fore.RED}No python files found in the directory!{Style.RESET_ALL}")
                    return
            else:
                print(f"{Fore.RED}Target is neither file nor directory!{Style.RESET_ALL}")
                return                        

            print(f"{Fore.YELLOW}Checking for weak cryptography in: {target_path}{Style.RESET_ALL}")
            
            test_ids = ["B301", "B302", "B303", "B304", "B305", "B306"]
            results = self.run_bandit_scan(target, test_ids=test_ids)  
            self.display_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}Error checking weak cryptography: {str(e)}{Style.RESET_ALL}")
        
        
    def run_all_checks(self, target_path):
        try:
            if not target_path or not isinstance(target_path, str):
                raise ValueError(f"{Fore.RED}Invalid target path{Style.RESET_ALL}")
                
            if not os.path.exists(target_path):
                print(f"{Fore.RED}Target not found!{Style.RESET_ALL}")
                return
                
            if os.path.isfile(target_path):
                target = [target_path]
            elif os.path.isdir(target_path):
                target = glob.glob(os.path.join(target_path, "**", "*.py"), recursive=True)
                if not target:
                    print(f"{Fore.RED}No python files found in the directory!{Style.RESET_ALL}")
                    return
            else:
                print(f"{Fore.RED}Target is neither file nor directory!{Style.RESET_ALL}")
                return                

            print(f"{Fore.YELLOW}Running all security checks on: {target_path}{Style.RESET_ALL}")
            results = self.run_bandit_scan(target)
            self.display_results(results)
            
        except Exception as e:
            print(f"{Fore.RED}Error running all checks: {str(e)}{Style.RESET_ALL}")
 
                 
def main():
    parser = argparse.ArgumentParser(description=f'{Fore.CYAN}Bandit Analysis Tool - Security Scanner for Python Code{Style.RESET_ALL}')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--scan-file', metavar='PATH', help='Scan a single Python file')
    group.add_argument('-d', '--scan-dir', metavar='PATH', help='Scan a directory containing Python Files')
    group.add_argument('-i', '--injection', metavar='PATH', help='Check for injection flaws in file/directory')
    group.add_argument('-c', '--crypto', metavar='PATH', help='Check for Weak cryptography in file/directory')
    group.add_argument('-a', '--all', metavar='PATH', help='Run all security checks on file/directory')
    
    try:
        args = parser.parse_args()
        scanner = Scanner()
        
        try:
            if args.scan_file:
                scanner.scan_file(args.scan_file)
            elif args.scan_dir:
                scanner.scan_directory(args.scan_dir)
            elif args.injection:
                scanner.check_injection_flaws(args.injection)
            elif args.crypto:
                scanner.check_weak_cryptography(args.crypto)
            elif args.all:
                scanner.run_all_checks(args.all)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Operation cancelled by user{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}Error during operation: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)
            
    except argparse.ArgumentError as e:
        print(f"{Fore.RED}Argument error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
                                
        
if __name__ == "__main__":
    main()
