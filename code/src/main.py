import os
import sys
from colorama import Fore, Style

class CyberSecurityToolkit:
    def __init__(self):
        self.tools = {
            "1": ("Bandit Analysis", "bandit_analysis"),
            "2": ("Cryptography Tool", "crypto_tool"),
            "3": ("Network Toolkit", "network_toolkit"),
            "4": ("Nmap Scanner (User needs the actual Nmap executable!)", "nmap_scanner"),
            "5": ("Password Generator", "password_generator"),
            "6": ("SSH Defender (Only works on Linux)", "ssh_defender"),
            "7": ("Web Security Scanner", "web_security")
        }
        
        try:
            sys.path.append(os.path.dirname(__file__))
        except Exception as e:
            print(f"{Fore.RED}Error initializing system path: {e}{Style.RESET_ALL}")
            sys.exit(1)
        
    # Clear user screen for better readability        
    def clear_user_screen(self):
        try:
            os.system('cls' if os.name == "nt" else 'clear')
        except Exception as e:
            print(f"{Fore.RED}Error clearing screen: {e}{Style.RESET_ALL}")
        
    def display_menu(self):
        try:
            self.clear_user_screen()
            print(f"""{Fore.RED}

███████╗███████╗███╗   ██╗██╗ ██████╗ ███████╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
╚══███╔╝██╔════╝████╗  ██║██║██╔═══██╗██╔════╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
  ███╔╝ █████╗  ██╔██╗ ██║██║██║   ██║███████╗       ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
 ███╔╝  ██╔══╝  ██║╚██╗██║██║██║   ██║╚════██║       ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
███████╗███████╗██║ ╚████║██║╚██████╔╝███████║       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
                                                                                                         
            
              {Style.RESET_ALL}""")
            print("=" * 50)
            print("ZENIOS CYBERSECURITY TOOLKIT")
            print("=" * 50)
            
            for key, (name, _) in self.tools.items():
                print(f"{Fore.YELLOW}{key}. {name}{Style.RESET_ALL}")
                
            print(f"{Fore.YELLOW}0. Exit{Style.RESET_ALL}")
            print(Fore.MAGENTA + "=" * 50 + Style.RESET_ALL)
            
        except Exception as e:
            print(f"{Fore.RED}Error displaying menu: {e}{Style.RESET_ALL}")
            sys.exit(1)
            
    def run_tool(self, module_name):
        try:
            module = __import__(module_name)
            if hasattr(module, 'main'):
                try:
                    module.main()
                except Exception as e:
                    print(f"{Fore.RED}Error running {module_name}: {e}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}The {module_name} does not have a main function{Style.RESET_ALL}") 
                
        except ImportError:
            print(f"{Fore.RED}Module {module_name} could not be found!{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}") 
            
    def run(self):
        while True:
            try:
                self.display_menu()
                choice = input(f"{Fore.BLUE}Select an option (0 to exit): {Style.RESET_ALL}").strip()
                
                if not choice:  # Handle empty input
                    print(f"{Fore.RED}Please enter a valid option.{Style.RESET_ALL}")
                    continue
                    
                if choice == "0":
                    print(f"{Fore.GREEN}Thank you for using my tool. Goodbye!{Style.RESET_ALL}")
                    break

                if choice in self.tools:
                    _, module_name = self.tools[choice]
                    self.run_tool(module_name)
                else:
                    print(f"{Fore.RED}Invalid Option. Please try a number between 0-7.{Style.RESET_ALL}")
                    
                input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
                
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}Operation cancelled by user. Exiting...{Style.RESET_ALL}")
                break
            except EOFError:
                print(f"\n{Fore.RED}End of input reached. Exiting...{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}Unexpected error: {e}. Returning to menu...{Style.RESET_ALL}")
                continue
                
if __name__ == "__main__":
    try:
        toolkit = CyberSecurityToolkit()
        toolkit.run()
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)
                