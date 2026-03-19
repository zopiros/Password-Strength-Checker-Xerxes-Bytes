# Password-Strength-Checker-Xerxes-Bytes
Password Tool — Xerxes Bytes  A command-line password generator and strength checker built for security awareness and education.  Built and developed by Xerxes Bytes — a student-driven cybersecurity group focused on scripting, vulnerability analysis, and hands-on security research.
[password_tool.py](https://github.com/user-attachments/files/26124751/password_tool.py)
#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║        Password Tool — Xerxes Bytes                  ║
║   Password Generator + Strength Checker              ║
║     Educational tool for authorized use only         ║
╚══════════════════════════════════════════════════════╝

USAGE:
  python3 password_tool.py                    # حالت تعاملی منو
  python3 password_tool.py --generate         # تولید رمز عبور
  python3 password_tool.py --check            # بررسی قدرت رمز
  python3 password_tool.py --generate -l 20  # رمز ۲۰ کاراکتری
"""

import random
import string
import hashlib
import argparse
import sys
import re
import math
from datetime import datetime


# ─── رنگ‌بندی ترمینال ───────────────────────────────────────────────────────
class Color:
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


# ─── رمزهای عبور رایج (لیست کوچک برای نمونه) ────────────────────────────────
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "welcome", "monkey",
    "dragon", "master", "sunshine", "princess", "iloveyou",
    "football", "shadow", "superman", "michael", "password1",
    "123qwe", "pass", "test", "root", "toor", "admin123",
}

# ─── الگوهای ضعیف ─────────────────────────────────────────────────────────
KEYBOARD_PATTERNS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1qaz2wsx", "qazwsx",
    "123456", "654321", "abcdef", "fedcba",
]


def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
  ____  ____  ____ ____ _ _ _ __  __  ____  ____
 |  _ \\|  _ \\/ ___/ ___| | | |  \\/  |/ __ \\|  _ \\
 | |_) | |_) \\___ \\___ \\ | | | |\\/| | |  | | |_) |
 |  __/|  __/ ___) |__) | |_| | |  | | |__| |  _ <
 |_|   |_|   |____/____/ \\___/|_|  |_|\\____/|_| \\_\\
{Color.RESET}
{Color.YELLOW}              Xerxes Bytes — Password Tool v1.0{Color.RESET}
{Color.CYAN}         Password Generator  +  Strength Checker{Color.RESET}
""")


# ══════════════════════════════════════════════════════
#   بخش اول: PASSWORD GENERATOR
# ══════════════════════════════════════════════════════

def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_symbols: str = None
) -> str:
    """
    تولید رمز عبور امن با استفاده از random.SystemRandom()
    
    چرا SystemRandom؟
    - از /dev/urandom سیستم‌عامل استفاده می‌کنه
    - Cryptographically secure — قابل پیش‌بینی نیست
    - برخلاف random.random() که pseudo-random است
    """
    
    charset = ""
    guaranteed = []  # حداقل یه کاراکتر از هر نوع
    
    # کاراکترهای مبهم که ممکنه اشتباه خونده بشن: l,1,I,0,O
    ambiguous = "l1Io0O" if exclude_ambiguous else ""
    
    if use_lower:
        chars = "".join(c for c in string.ascii_lowercase if c not in ambiguous)
        charset += chars
        guaranteed.append(random.SystemRandom().choice(chars))
    
    if use_upper:
        chars = "".join(c for c in string.ascii_uppercase if c not in ambiguous)
        charset += chars
        guaranteed.append(random.SystemRandom().choice(chars))
    
    if use_digits:
        chars = "".join(c for c in string.digits if c not in ambiguous)
        charset += chars
        guaranteed.append(random.SystemRandom().choice(chars))
    
    if use_symbols:
        symbols = custom_symbols if custom_symbols else "!@#$%^&*()-_=+[]{}|;:,.<>?"
        chars = "".join(c for c in symbols if c not in ambiguous)
        charset += chars
        guaranteed.append(random.SystemRandom().choice(chars))
    
    if not charset:
        raise ValueError("At least one character type must be selected!")
    
    # پر کردن بقیه طول رمز
    rng = random.SystemRandom()
    remaining = [rng.choice(charset) for _ in range(length - len(guaranteed))]
    
    # shuffle برای جلوگیری از pattern قابل پیش‌بینی
    all_chars = guaranteed + remaining
    rng.shuffle(all_chars)
    
    return "".join(all_chars)


def calculate_entropy(password: str) -> float:
    """
    محاسبه entropy رمز عبور
    
    فرمول: H = L × log2(N)
    H = entropy (bits)
    L = طول رمز
    N = اندازه charset
    
    هر چه entropy بیشتر، رمز قوی‌تر
    - < 28 bits : خیلی ضعیف
    - 28-35 bits: ضعیف
    - 36-59 bits: متوسط
    - 60-127 bits: قوی
    - 128+ bits  : خیلی قوی
    """
    charset_size = 0
    
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password):
        charset_size += 32
    
    if charset_size == 0:
        return 0.0
    
    return len(password) * math.log2(charset_size)


def estimate_crack_time(entropy: float) -> str:
    """
    تخمین زمان crack با فرض ۱ میلیارد تلاش در ثانیه (GPU brute force)
    """
    # تعداد حالت‌های ممکن
    combinations = 2 ** entropy
    
    # ۱ میلیارد تلاش در ثانیه (GPU)
    attempts_per_second = 1_000_000_000
    seconds = combinations / attempts_per_second
    
    if seconds < 1:
        return f"{Color.RED}instantly{Color.RESET}"
    elif seconds < 60:
        return f"{Color.RED}{seconds:.1f} seconds{Color.RESET}"
    elif seconds < 3600:
        return f"{Color.RED}{seconds/60:.1f} minutes{Color.RESET}"
    elif seconds < 86400:
        return f"{Color.YELLOW}{seconds/3600:.1f} hours{Color.RESET}"
    elif seconds < 2_592_000:
        return f"{Color.YELLOW}{seconds/86400:.1f} days{Color.RESET}"
    elif seconds < 31_536_000:
        return f"{Color.GREEN}{seconds/2_592_000:.1f} months{Color.RESET}"
    elif seconds < 3_153_600_000:
        return f"{Color.GREEN}{seconds/31_536_000:.1f} years{Color.RESET}"
    else:
        return f"{Color.GREEN}centuries{Color.RESET}"


# ══════════════════════════════════════════════════════
#   بخش دوم: STRENGTH CHECKER
# ══════════════════════════════════════════════════════

def check_strength(password: str) -> dict:
    """
    بررسی جامع قدرت رمز عبور
    
    معیارها:
    1. طول
    2. تنوع کاراکتر (uppercase, lowercase, digits, symbols)
    3. عدم وجود در لیست رمزهای رایج
    4. عدم وجود الگوهای keyboard
    5. عدم تکرار کاراکتر
    6. entropy محاسبه‌شده
    """
    
    issues   = []
    warnings = []
    score    = 0  # 0-100
    
    length = len(password)
    
    # ─── ۱. بررسی طول ────────────────────────────────────────────────────────
    if length < 8:
        issues.append("Too short (minimum 8 characters)")
    elif length < 12:
        warnings.append("Short password — consider 16+ characters")
        score += 10
    elif length < 16:
        score += 20
    else:
        score += 30
    
    # ─── ۲. بررسی تنوع کاراکتر ───────────────────────────────────────────────
    has_lower   = bool(re.search(r'[a-z]', password))
    has_upper   = bool(re.search(r'[A-Z]', password))
    has_digit   = bool(re.search(r'\d', password))
    has_symbol  = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]', password))
    
    types_count = sum([has_lower, has_upper, has_digit, has_symbol])
    
    if not has_lower:
        issues.append("No lowercase letters")
    if not has_upper:
        issues.append("No uppercase letters")
    if not has_digit:
        issues.append("No digits")
    if not has_symbol:
        warnings.append("No symbols — adding symbols greatly increases strength")
    
    score += types_count * 10  # max 40
    
    # ─── ۳. رمزهای رایج ──────────────────────────────────────────────────────
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common passwords!")
        score = max(0, score - 40)
    
    # ─── ۴. الگوهای keyboard ─────────────────────────────────────────────────
    pwd_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in pwd_lower:
            issues.append(f"Contains keyboard pattern: '{pattern}'")
            score = max(0, score - 15)
            break
    
    # ─── ۵. تکرار کاراکتر ────────────────────────────────────────────────────
    if length > 0:
        unique_ratio = len(set(password)) / length
        if unique_ratio < 0.5:
            issues.append("Too many repeated characters")
            score = max(0, score - 10)
        elif unique_ratio < 0.7:
            warnings.append("Several repeated characters")
    
    # ─── ۶. الگوی تکراری (مثل ababab) ────────────────────────────────────────
    if length >= 4:
        for chunk_size in range(1, length // 2 + 1):
            chunk = password[:chunk_size]
            if password == chunk * (length // chunk_size) + chunk[:length % chunk_size]:
                issues.append(f"Password is a repeated pattern: '{chunk}'")
                score = max(0, score - 20)
                break
    
    # ─── ۷. فقط اعداد یا فقط حروف ────────────────────────────────────────────
    if password.isdigit():
        issues.append("Password is all digits — very easy to brute force")
        score = max(0, score - 20)
    elif password.isalpha():
        warnings.append("Password is all letters — add digits and symbols")
    
    # ─── محاسبه entropy و زمان crack ─────────────────────────────────────────
    entropy      = calculate_entropy(password)
    crack_time   = estimate_crack_time(entropy)
    
    # ─── تعیین سطح ───────────────────────────────────────────────────────────
    score = max(0, min(100, score))
    
    if score < 25 or issues:
        level = "VERY WEAK"
        color = Color.RED
    elif score < 50:
        level = "WEAK"
        color = Color.RED
    elif score < 70:
        level = "MODERATE"
        color = Color.YELLOW
    elif score < 85:
        level = "STRONG"
        color = Color.GREEN
    else:
        level = "VERY STRONG"
        color = Color.GREEN
    
    return {
        "score":      score,
        "level":      level,
        "color":      color,
        "entropy":    entropy,
        "crack_time": crack_time,
        "has_lower":  has_lower,
        "has_upper":  has_upper,
        "has_digit":  has_digit,
        "has_symbol": has_symbol,
        "length":     length,
        "issues":     issues,
        "warnings":   warnings,
    }


def print_strength_bar(score: int, color: str):
    """نمایش بار قدرت رمز"""
    filled = int(score / 5)
    empty  = 20 - filled
    bar    = "█" * filled + "░" * empty
    print(f"\n  Strength  [{color}{bar}{Color.RESET}] {score}/100")


def print_check_details(result: dict):
    """نمایش جزئیات بررسی رمز"""
    
    r = result
    
    print_strength_bar(r["score"], r["color"])
    
    print(f"\n  Level     : {r['color']}{Color.BOLD}{r['level']}{Color.RESET}")
    print(f"  Length    : {r['length']} characters")
    print(f"  Entropy   : {r['entropy']:.1f} bits")
    print(f"  Crack time: {r['crack_time']}  (@ 1B attempts/sec)")
    
    # ─── چک‌لیست ─────────────────────────────────────────────────────────────
    print(f"\n  {'─' * 40}")
    print(f"  Character types:")
    
    def check_icon(val):
        return f"{Color.GREEN}✔{Color.RESET}" if val else f"{Color.RED}✘{Color.RESET}"
    
    print(f"    {check_icon(r['has_lower'])}  Lowercase letters (a-z)")
    print(f"    {check_icon(r['has_upper'])}  Uppercase letters (A-Z)")
    print(f"    {check_icon(r['has_digit'])}  Digits (0-9)")
    print(f"    {check_icon(r['has_symbol'])}  Symbols (!@#$...)")
    
    # ─── مشکلات ──────────────────────────────────────────────────────────────
    if r["issues"]:
        print(f"\n  {Color.RED}Issues:{Color.RESET}")
        for issue in r["issues"]:
            print(f"    {Color.RED}✘  {issue}{Color.RESET}")
    
    if r["warnings"]:
        print(f"\n  {Color.YELLOW}Warnings:{Color.RESET}")
        for warning in r["warnings"]:
            print(f"    {Color.YELLOW}⚠  {warning}{Color.RESET}")
    
    if not r["issues"] and not r["warnings"]:
        print(f"\n  {Color.GREEN}✔  No issues found — great password!{Color.RESET}")
    
    print()


# ══════════════════════════════════════════════════════
#   بخش سوم: منو تعاملی
# ══════════════════════════════════════════════════════

def interactive_generate():
    """منو تعاملی برای تولید رمز عبور"""
    
    print(f"\n{Color.CYAN}{'─' * 50}{Color.RESET}")
    print(f"{Color.BOLD}  PASSWORD GENERATOR{Color.RESET}")
    print(f"{Color.CYAN}{'─' * 50}{Color.RESET}\n")
    
    # طول
    try:
        length_input = input(f"  Length (default 16): ").strip()
        length = int(length_input) if length_input else 16
        length = max(8, min(128, length))
    except ValueError:
        length = 16
    
    # گزینه‌ها
    def ask(prompt, default=True):
        val = input(f"  {prompt} [Y/n]: ").strip().lower()
        if val == "":
            return default
        return val != "n"
    
    use_upper   = ask("Include uppercase (A-Z)?")
    use_lower   = ask("Include lowercase (a-z)?")
    use_digits  = ask("Include digits (0-9)?")
    use_symbols = ask("Include symbols (!@#...)?")
    exclude_amb = ask("Exclude ambiguous chars (l,1,I,0,O)?", default=False)
    
    # تعداد رمز
    try:
        count_input = input(f"  How many passwords to generate? (default 5): ").strip()
        count = int(count_input) if count_input else 5
        count = max(1, min(20, count))
    except ValueError:
        count = 5
    
    print(f"\n{Color.CYAN}{'─' * 50}{Color.RESET}")
    print(f"{Color.BOLD}  Generated Passwords:{Color.RESET}\n")
    
    passwords = []
    for i in range(count):
        try:
            pwd = generate_password(
                length           = length,
                use_upper        = use_upper,
                use_lower        = use_lower,
                use_digits       = use_digits,
                use_symbols      = use_symbols,
                exclude_ambiguous= exclude_amb
            )
            passwords.append(pwd)
            entropy = calculate_entropy(pwd)
            result  = check_strength(pwd)
            
            print(
                f"  {Color.BOLD}{i+1:>2}.{Color.RESET} "
                f"{Color.GREEN}{pwd}{Color.RESET}  "
                f"  [{result['color']}{result['level']}{Color.RESET}]"
                f"  entropy: {entropy:.0f}b"
            )
        except ValueError as e:
            print(f"  {Color.RED}Error: {e}{Color.RESET}")
            return
    
    print(f"\n{Color.CYAN}{'─' * 50}{Color.RESET}")
    
    # آنالیز رمز اول
    if passwords:
        show = input(f"\n  Analyze first password in detail? [Y/n]: ").strip().lower()
        if show != "n":
            print(f"\n{Color.BOLD}  Analyzing: {Color.GREEN}{passwords[0]}{Color.RESET}\n")
            result = check_strength(passwords[0])
            print_check_details(result)


def interactive_check():
    """منو تعاملی برای بررسی قدرت رمز عبور"""
    
    print(f"\n{Color.CYAN}{'─' * 50}{Color.RESET}")
    print(f"{Color.BOLD}  PASSWORD STRENGTH CHECKER{Color.RESET}")
    print(f"{Color.CYAN}{'─' * 50}{Color.RESET}\n")
    
    import getpass
    
    while True:
        try:
            # getpass رمز رو بدون نمایش در ترمینال می‌گیره
            password = getpass.getpass("  Enter password (hidden): ")
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Color.YELLOW}  Cancelled.{Color.RESET}")
            return
        
        if not password:
            print(f"  {Color.YELLOW}Empty password — try again.{Color.RESET}\n")
            continue
        
        print(f"\n{Color.BOLD}  Analyzing password...{Color.RESET}")
        result = check_strength(password)
        print_check_details(result)
        
        again = input("  Check another password? [y/N]: ").strip().lower()
        if again != "y":
            break


def main_menu():
    """منو اصلی"""
    
    print(f"\n{Color.CYAN}{'─' * 50}{Color.RESET}")
    print(f"  {Color.BOLD}What would you like to do?{Color.RESET}\n")
    print(f"  {Color.GREEN}1{Color.RESET}  Generate password(s)")
    print(f"  {Color.CYAN}2{Color.RESET}  Check password strength")
    print(f"  {Color.YELLOW}3{Color.RESET}  Both (generate + analyze)")
    print(f"  {Color.RED}0{Color.RESET}  Exit")
    print(f"{Color.CYAN}{'─' * 50}{Color.RESET}\n")
    
    choice = input("  Choice: ").strip()
    
    if choice == "1":
        interactive_generate()
    elif choice == "2":
        interactive_check()
    elif choice == "3":
        interactive_generate()
        interactive_check()
    elif choice == "0":
        print(f"\n  {Color.CYAN}Goodbye — stay secure!{Color.RESET}\n")
        sys.exit(0)
    else:
        print(f"\n  {Color.RED}Invalid choice.{Color.RESET}")


def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description="Password Generator + Strength Checker — Xerxes Bytes"
    )
    parser.add_argument("--generate",   action="store_true", help="Generate password(s)")
    parser.add_argument("--check",      action="store_true", help="Check password strength")
    parser.add_argument("-l", "--length",type=int, default=16, help="Password length (default: 16)")
    parser.add_argument("-n", "--count", type=int, default=5,  help="Number of passwords (default: 5)")
    parser.add_argument("--no-upper",   action="store_true",   help="Exclude uppercase")
    parser.add_argument("--no-lower",   action="store_true",   help="Exclude lowercase")
    parser.add_argument("--no-digits",  action="store_true",   help="Exclude digits")
    parser.add_argument("--no-symbols", action="store_true",   help="Exclude symbols")
    parser.add_argument("--no-ambiguous",action="store_true",  help="Exclude ambiguous chars")
    
    args = parser.parse_args()
    
    if args.generate:
        print(f"\n{Color.BOLD}  Generated Passwords ({args.length} chars):{Color.RESET}\n")
        for i in range(args.count):
            pwd = generate_password(
                length            = args.length,
                use_upper         = not args.no_upper,
                use_lower         = not args.no_lower,
                use_digits        = not args.no_digits,
                use_symbols       = not args.no_symbols,
                exclude_ambiguous = args.no_ambiguous
            )
            result  = check_strength(pwd)
            entropy = calculate_entropy(pwd)
            print(
                f"  {i+1:>2}. {Color.GREEN}{pwd}{Color.RESET}"
                f"  [{result['color']}{result['level']}{Color.RESET}]"
                f"  {entropy:.0f} bits"
            )
        print()
    
    elif args.check:
        interactive_check()
    
    else:
        main_menu()


if __name__ == "__main__":
    main()
