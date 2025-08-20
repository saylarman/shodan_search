import shodan
import os
import sys
import argparse
import datetime
import csv
import json

# ==============================================================================
# 1. ARGUMENT PARSING
# ==============================================================================
def parse_arguments():
    """
    Parses command-line arguments using a sub-parser structure.
    """
    parser = argparse.ArgumentParser(
        description="یک ابزار خط فرمان چندمنظوره برای کار با Shodan.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--api-key',
        metavar='KEY',
        type=str,
        default=None, # Default is now None, logic is handled in main
        help='کلید API شودان شما. اگر مشخص نشود، از متغیر محیطی یا فایل کانفیگ خوانده می‌شود.'
    )

    subparsers = parser.add_subparsers(dest='command', required=True, help='دستور مورد نظر')

    # --- Search Sub-command ---
    search_parser = subparsers.add_parser('search', help='جستجو در شودان و ذخیره نتایج.')
    query_group = search_parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument('-q', '--query', metavar='QUERY', type=str, help='کوئری جستجو برای شودان.')
    query_group.add_argument('-qf', '--query-file', metavar='FILE', type=str, help='فایلی شامل لیستی از کوئری‌ها.')
    search_parser.add_argument('-o', '--output', metavar='FILENAME', type=str, help='نام پایه برای فایل خروجی.')
    search_parser.add_argument('-f', '--format', type=str, choices=['txt', 'csv', 'json'], default='txt', help='فرمت فایل خروجی (پیش‌فرض: txt).')
    search_parser.add_argument('--timestamp', action='store_true', help='افزودن برچسب زمانی به نام فایل.')
    search_parser.add_argument('--country', type=str, metavar='CODE', help="فیلتر بر اساس کد کشور.")
    search_parser.add_argument('--port', type=str, metavar='PORT', help="فیلتر بر اساس پورت.")
    search_parser.add_argument('--vuln', type=str, metavar='CVE', help="فیلتر بر اساس شناسه آسیب‌پذیری.")
    search_parser.add_argument(
        '--fields',
        type=str,
        default=None,
        help='فیلدهای مشخص برای خروجی CSV (جدا شده با کاما).\nمثال: ip_str,port,org,vulns'
    )

    # --- Host Sub-command ---
    host_parser = subparsers.add_parser('host', help='مشاهده جزئیات کامل یک IP خاص.')
    host_parser.add_argument('ip_address', metavar='IP_ADDRESS', help='آدرس IP مورد نظر.')

    # --- Stats Sub-command ---
    stats_parser = subparsers.add_parser('stats', help='مشاهده آمار کلی یک کوئری.')
    stats_parser.add_argument('query', metavar='QUERY', help='کوئری برای مشاهده آمار.')

    args = parser.parse_args()
    return args

# ==============================================================================
# 2. HELPER, COLOR & WRITER FUNCTIONS
# ==============================================================================
class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

def sanitize_filename(query):
    """Sanitizes a string to be used as a valid filename."""
    invalid_chars = '<>:"/\\|?*'
    filename = query.strip().replace(' ', '_')
    for char in invalid_chars:
        filename = filename.replace(char, '')
    return filename

def write_txt(results, filename, query):
    """Writes results to a simple TXT file."""
    print(f"{Colors.BLUE}[+] در حال نوشتن {len(results)} نتیجه در فایل متنی: {filename}{Colors.RESET}")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"نتایج جستجو برای کوئری: {query}\n{'='*50}\n\n")
        for res in results:
            ip = res.get('ip_str', 'N/A')
            port = res.get('port', 'N/A')
            hostnames = ', '.join(res.get('hostnames', [])) or 'N/A'
            f.write(f"IP: {ip}\tPort: {port}\tHostnames: {hostnames}\n")

def write_csv(results, filename, query, custom_fields=None):
    """Writes results to a CSV file, allowing for custom fields."""
    print(f"{Colors.BLUE}[+] در حال نوشتن {len(results)} نتیجه در فایل CSV: {filename}{Colors.RESET}")

    if custom_fields:
        # Use user-defined fields
        headers = [field.strip() for field in custom_fields.split(',')]
    else:
        # Fallback to default headers
        headers = ['ip_str', 'port', 'hostnames', 'isp', 'org', 'country', 'timestamp', 'data']

    with open(filename, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        for res in results:
            # Flatten nested data for easier CSV reading, as some fields might be nested
            if 'country' in headers:
                res['country'] = res.get('location', {}).get('country_name', 'N/A')
            if 'hostnames' in headers:
                res['hostnames'] = ", ".join(res.get('hostnames', []))
            if 'vulns' in headers:
                res['vulns'] = ", ".join(res.get('vulns', []))

            writer.writerow(res)

def write_json(results, filename, query):
    """Writes results to a JSON file."""
    print(f"{Colors.BLUE}[+] در حال نوشتن {len(results)} نتیجه در فایل JSON: {filename}{Colors.RESET}")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

# ==============================================================================
# 3. COMMAND HANDLERS
# ==============================================================================
def handle_search_command(api, args):
    """Handles the logic for the 'search' command."""
    print(f"{Colors.BLUE}[INFO] اجرای دستور 'search'...{Colors.RESET}")
    queries_to_run = []
    if args.query:
        queries_to_run.append(args.query)
    elif args.query_file:
        try:
            with open(args.query_file, 'r', encoding='utf-8') as f:
                queries_to_run = [line.strip() for line in f if line.strip()]
            if not queries_to_run:
                print(f"{Colors.RED}[ERROR] فایل کوئری '{args.query_file}' خالی است.{Colors.RESET}")
                sys.exit(1)
        except FileNotFoundError:
            print(f"{Colors.RED}[ERROR] فایل کوئری '{args.query_file}' پیدا نشد.{Colors.RESET}")
            sys.exit(1)

    for i, query in enumerate(queries_to_run):
        print(f"\n{Colors.YELLOW}--- پردازش کوئری {i+1}/{len(queries_to_run)}: '{query}' ---{Colors.RESET}")
        query_parts = [query]
        if args.country: query_parts.append(f"country:{args.country}")
        if args.port: query_parts.append(f"port:{args.port}")
        if args.vuln: query_parts.append(f"vuln:{args.vuln}")
        final_query = " ".join(query_parts)

        if final_query != query:
            print(f"{Colors.CYAN}[INFO] کوئری نهایی با اعمال فیلترها: '{final_query}'{Colors.RESET}")

        print(f"{Colors.BLUE}[INFO] در حال جستجو...{Colors.RESET}")
        results = []
        try:
            for result in api.search_cursor(final_query):
                results.append(result)
        except shodan.APIError as e:
            print(f"{Colors.RED}[ERROR] خطا در هنگام جستجو: {e}{Colors.RESET}")
            continue

        if not results:
            print(f"{Colors.YELLOW}[INFO] هیچ نتیجه‌ای یافت نشد.{Colors.RESET}")
            continue

        base_filename = args.output if len(queries_to_run) == 1 and args.output else sanitize_filename(query)
        if args.timestamp:
            base_filename = f"{base_filename}_{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        output_filename = f"{base_filename}.{args.format}"

        # Adjust writer logic to handle custom fields for CSV
        if args.format == 'csv':
            write_csv(results, output_filename, final_query, custom_fields=args.fields)
        else:
            # For TXT and JSON, custom fields are not applicable in the same way
            writer_map = {'txt': write_txt, 'json': write_json}
            writer_map[args.format](results, output_filename, final_query)

        print(f"{Colors.GREEN}[SUCCESS] نتایج در فایل '{os.path.abspath(output_filename)}' ذخیره شد.{Colors.RESET}")

def handle_host_command(api, args):
    """Handles the logic for the 'host' command."""
    ip = args.ip_address
    print(f"{Colors.BLUE}[INFO] در حال دریافت اطلاعات برای IP: {ip}...{Colors.RESET}")
    try:
        host_info = api.host(ip)

        # --- General Information ---
        print(f"\n{Colors.YELLOW}--- General Information ---{Colors.RESET}")
        print(f"  {Colors.CYAN}{'IP:':<15}{Colors.RESET} {host_info.get('ip_str')}")
        print(f"  {Colors.CYAN}{'Organization:':<15}{Colors.RESET} {host_info.get('org', 'N/A')}")
        print(f"  {Colors.CYAN}{'ISP:':<15}{Colors.RESET} {host_info.get('isp', 'N/A')}")
        print(f"  {Colors.CYAN}{'Hostnames:':<15}{Colors.RESET} {', '.join(host_info.get('hostnames', ['N/A']))}")
        location_info = f"{host_info.get('city', 'N/A')}, {host_info.get('country_name', 'N/A')}"
        print(f"  {Colors.CYAN}{'Location:':<15}{Colors.RESET} {location_info}")

        # --- Ports and Services ---
        print(f"\n{Colors.YELLOW}--- Ports & Services ---{Colors.RESET}")
        if not host_info.get('data'):
             print("  No open ports found.")
        for item in host_info.get('data', []):
            port = item.get('port')
            transport = item.get('transport', 'tcp').upper()
            service = item.get('_shodan', {}).get('module', 'N/A')
            product = item.get('product', 'N/A')

            print(f"  {Colors.GREEN}Port: {port}/{transport}{Colors.RESET}")
            print(f"    {'Service:':<12} {service}")
            print(f"    {'Product:':<12} {product}")

            # Display banner if it exists and is not empty
            if item.get('data', '').strip():
                banner_lines = item['data'].strip().split('\n')
                print(f"    {'Banner:':<12}")
                for line in banner_lines:
                    print(f"      {line.strip()}")

        # --- Vulnerabilities ---
        print(f"\n{Colors.YELLOW}--- Vulnerabilities ---{Colors.RESET}")
        vulns = host_info.get('vulns', [])
        if vulns:
            for vuln in vulns:
                cve = vuln.replace('!','') # Remove exclamation mark for cleaner output
                print(f"  {Colors.RED}- {cve}{Colors.RESET}")
        else:
            print(f"  {Colors.GREEN}No known vulnerabilities found.{Colors.RESET}")

    except shodan.APIError as e:
        print(f"{Colors.RED}[ERROR] An error occurred: {e}{Colors.RESET}")
        sys.exit(1)

def handle_stats_command(api, args):
    """Handles the logic for the 'stats' command."""
    query = args.query
    print(f"{Colors.BLUE}[INFO] در حال دریافت آمار برای کوئری: '{query}'...{Colors.RESET}")

    # Define the facets we want Shodan to summarize
    FACETS = [
        ('country_name', 10),
        ('org', 10),
        ('port', 10),
        ('vulns', 5)  # Top 5 vulnerabilities
    ]

    try:
        # Use the count() method to get summary information
        result = api.count(query, facets=FACETS)

        print(f"\n{Colors.YELLOW}--- آمار کلی کوئری ---{Colors.RESET}")
        print(f"  {Colors.CYAN}{'Total Results:':<20}{Colors.RESET} {result.get('total', 0):,}")

        # Display the results for each facet
        for facet_name, top_values in result.get('facets', {}).items():
            # Make facet title more readable
            title = facet_name.replace('_', ' ').title()
            print(f"\n  {Colors.YELLOW}برترین {len(top_values)} مورد برای {title}:{Colors.RESET}")

            if not top_values:
                print("    - موردی یافت نشد.")
                continue

            for value in top_values:
                # Format with thousands separators for readability
                count_str = f"{value['count']:,}"
                print(f"    {value['name']:<35} {Colors.GREEN}{count_str}{Colors.RESET}")

    except shodan.APIError as e:
        print(f"{Colors.RED}[ERROR] An error occurred: {e}{Colors.RESET}")
        sys.exit(1)

# ==============================================================================
# 4. MAIN EXECUTION
# ==============================================================================
def get_api_key(args):
    """Gets the API key from args, environment, or config file."""
    # 1. From --api-key argument
    if args.api_key:
        return args.api_key

    # 2. From SHODAN_API_KEY environment variable
    env_key = os.environ.get('SHODAN_API_KEY')
    if env_key:
        return env_key

    # 3. From ~/.shodan/api config file
    try:
        config_path = os.path.expanduser('~/.shodan/api')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return f.read().strip()
    except Exception:
        pass # Ignore errors in reading the config file

    return None

def main():
    """Main function to parse args and dispatch to the correct handler."""
    args = parse_arguments()

    api_key = get_api_key(args)
    if not api_key:
        print(f"{Colors.RED}[ERROR] کلید API شودان یافت نشد.{Colors.RESET}")
        print("لطفا آن را از یکی از روش‌های زیر مشخص کنید:")
        print("  1. آرگومان خط فرمان: --api-key YOUR_KEY")
        print("  2. متغیر محیطی: SHODAN_API_KEY")
        print("  3. فایل پیکربندی: ~/.shodan/api")
        sys.exit(1)

    try:
        api = shodan.Shodan(api_key)
        api.info() # Validate API key
    except shodan.APIError as e:
        print(f"{Colors.RED}[ERROR] خطا در اتصال به شودان: {e}{Colors.RESET}")
        sys.exit(1)

    if args.command == 'search':
        handle_search_command(api, args)
    elif args.command == 'host':
        handle_host_command(api, args)
    elif args.command == 'stats':
        handle_stats_command(api, args)
    else:
        # This case should not be reachable due to 'required=True' in subparsers
        print(f"[ERROR] دستور نامعتبر: {args.command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
