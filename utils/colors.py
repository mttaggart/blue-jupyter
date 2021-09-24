from colorama import *

# Print statement colors
info = (Fore.BLUE + "[*]" + Fore.RESET + " ")
recc = (Fore.YELLOW + "[*]" + Fore.RESET + " ")
good = (Fore.GREEN + "[+]" + Fore.RESET + " ")
important = (Fore.CYAN + "[!]" + Fore.RESET + " ")
printError = (Fore.RED + "[X]" + Fore.RESET + " ")

# Confidence interval colors
"""
None: 0-2 | Low: 3-4 | Med: 5-6 | High: 7-8 | Crit: 9-10
"""
none = (Fore.GREEN + "[*]" + Fore.RESET + " ")
low = (Fore.CYAN + "[*]" + Fore.RESET + " ")
med = (Fore.YELLOW + "[*]" + Fore.RESET + " ")
high = (Fore.MAGENTA + "[*]" + Fore.RESET + " ")
crit = (Fore.RED + "[*]" + Fore.RESET + " ")