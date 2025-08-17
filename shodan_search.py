import shodan
import os
import sys
import argparse
import datetime
import csv
import json

def parse_arguments():
    """
    Parses all command-line arguments for the script.
    """
    api_key_env = os.environ.get('SHODAN_API_KEY')
    parser = argparse.ArgumentParser(
        description="یک ابزار قدرتمند برای جستجو در Shodan و ذخیره نتایج از طریق خط فرمان.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
مثال‌های استفاده:
  # جستجوی ساده و ذخیره در فایل txt
  python shodan_search.py -q "apache"

  # مشخص کردن فرمت خروجی و نام فایل به همراه برچسب زمانی
  python shodan_search.py --query "port:22" --format csv --output ssh_results --timestamp

  # خواندن کوئری‌ها از یک فایل و استفاده از فیلتر کشور
  python shodan_search.py --query-file queries.txt --country US

  # استفاده از کلید API از طریق آرگومان (اگر متغیر محیطی تنظیم نشده باشد)
  python shodan_search.py --api-key YOUR_API_KEY -q "nginx"
"""
    )
    parser.add_argument('--api-key', metavar='KEY', type=str, default=api_key_env, help='کلید API شودان شما.\nمی‌توانید از متغیر محیطی (SHODAN_API_KEY) نیز استفاده کنید.')
    query_group = parser.add_mutually_exclusive_group(required=True)
    query_group.add_argument('-q', '--query', metavar='QUERY', type=str, help='کوئری جستجو برای شودان.')
    query_group.add_argument('-qf', '--query-file', metavar='FILE', type=str, help='فایلی که شامل لیستی از کوئری‌ها است (هر کوئری در یک خط).')
    parser.add_argument('-o', '--output', metavar='FILENAME', type=str, help='نام پایه برای فایل خروجی (بدون پسوند).\nاگر مشخص نشود، از خود کوئری استفاده می‌شود.')
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'csv', 'json'], default='txt', help='فرمت فایل خروجی. گزینه‌ها: [txt, csv, json]. پیش‌فرض: txt')
    parser.add_argument('--timestamp', action='store_true', help='افزودن برچسب زمانی به نام فایل خروجی برای جلوگیری از بازنویسی.')
    parser.add_argument('--country', type=str, metavar='CODE', help="فیلتر بر اساس کد دو حرفی کشور (مثال: US, DE).")
    parser.add_argument('--port', type=str, metavar='PORT', help="فیلتر بر اساس پورت.")
    parser.add_argument('--vuln', type=str, metavar='CVE', help="فیلتر بر اساس شناسه آسیب‌پذیری (CVE).")
    args = parser.parse_args()
    if not args.api_key:
        parser.error('کلید API شودان مشخص نشده است. آن را با --api-key یا متغیر محیطی SHODAN_API_KEY ارائه دهید.')
    return args

def sanitize_filename(query):
    """Sanitizes a string to be used as a valid filename."""
    invalid_chars = '<>:"/\\|?*'
    filename = query.strip().replace(' ', '_')
    for char in invalid_chars:
        filename = filename.replace(char, '')
    return filename

# --- Writer Functions ---

def write_txt(results, filename, query):
    """Writes results to a simple TXT file."""
    print(f"[+] در حال نوشتن {len(results)} نتیجه در فایل متنی: {filename}")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"نتایج جستجو برای کوئری: {query}\n")
        f.write("="*50 + "\n\n")
        for res in results:
            ip = res.get('ip_str', 'N/A')
            port = res.get('port', 'N/A')
            hostnames = ", ".join(res.get('hostnames', [])) or "پیدا نشد"
            f.write(f"IP: {ip}\tPort: {port}\tHostnames: {hostnames}\n")

def write_csv(results, filename, query):
    """Writes results to a CSV file."""
    print(f"[+] در حال نوشتن {len(results)} نتیجه در فایل CSV: {filename}")
    headers = ['ip_str', 'port', 'hostnames', 'isp', 'org', 'country', 'timestamp', 'data']
    with open(filename, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        for res in results:
            # Flatten nested data for easier CSV reading
            res['country'] = res.get('location', {}).get('country_name', 'N/A')
            res['hostnames'] = ", ".join(res.get('hostnames', []))
            writer.writerow(res)

def write_json(results, filename, query):
    """Writes results to a JSON file, preserving all data."""
    print(f"[+] در حال نوشتن {len(results)} نتیجه در فایل JSON: {filename}")
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

def main():
    """Main function to orchestrate the script's execution."""
    args = parse_arguments()

    print("--- Shodan Command-Line Search Tool ---")

    # 1. Initialize Shodan API
    try:
        api = shodan.Shodan(args.api_key)
        api.info()
        print("[INFO] کلید API معتبر است و اتصال به شودان برقرار شد.")
    except shodan.APIError as e:
        print(f"[ERROR] خطا در اتصال به شودان: {e}")
        sys.exit(1)

    # 2. Build the list of queries to run
    queries_to_run = []
    if args.query:
        queries_to_run.append(args.query)
    elif args.query_file:
        try:
            with open(args.query_file, 'r', encoding='utf-8') as f:
                queries_to_run = [line.strip() for line in f if line.strip()]
            if not queries_to_run:
                print(f"[ERROR] فایل کوئری '{args.query_file}' خالی است یا هیچ کوئری معتبری ندارد.")
                sys.exit(1)
            print(f"[INFO] {len(queries_to_run)} کوئری از فایل '{args.query_file}' با موفقیت خوانده شد.")
        except FileNotFoundError:
            print(f"[ERROR] فایل کوئری '{args.query_file}' پیدا نشد.")
            sys.exit(1)

    # 3. Loop through each query and process it
    for i, query in enumerate(queries_to_run):
        print(f"\n--- پردازش کوئری {i+1}/{len(queries_to_run)}: '{query}' ---")

        # Build the final query string with advanced filters
        query_parts = [query]
        if args.country:
            query_parts.append(f"country:{args.country}")
        if args.port:
            query_parts.append(f"port:{args.port}")
        if args.vuln:
            query_parts.append(f"vuln:{args.vuln}")
        final_query = " ".join(query_parts)

        if final_query != query:
            print(f"[INFO] کوئری نهایی با اعمال فیلترها: '{final_query}'")

        # --- Perform Search ---
        print(f"[INFO] در حال جستجو برای '{final_query}'...")
        results = []
        try:
            for result in api.search_cursor(final_query):
                results.append(result)
                if len(results) % 100 == 0:
                    print(f"... {len(results)} نتیجه تاکنون پیدا شده است.")
        except shodan.APIError as e:
            print(f"[ERROR] خطا در هنگام جستجو برای کوئری '{final_query}': {e}")
            continue # Skip to the next query

        if not results:
            print("[INFO] هیچ نتیجه‌ای برای این کوئری یافت نشد.")
            continue # Skip to the next query

        print(f"[INFO] جستجو کامل شد. تعداد کل نتایج یافت شده: {len(results)}")

        # --- Write Results ---
        # If -o is specified for a single query, use it. Otherwise, use the query itself as the filename.
        base_filename = args.output if len(queries_to_run) == 1 and args.output else sanitize_filename(query)

        # Add timestamp to the filename if the flag is set
        if args.timestamp:
            timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            base_filename = f"{base_filename}_{timestamp}"

        output_filename = f"{base_filename}.{args.format}"

        writer_map = {
            'txt': write_txt,
            'csv': write_csv,
            'json': write_json
        }

        writer_function = writer_map.get(args.format)
        writer_function(results, output_filename, query)

        print(f"[SUCCESS] نتایج کوئری '{query}' در فایل زیر ذخیره شد:")
        print(f"   -> {os.path.abspath(output_filename)}")

    print("\n--- تمام عملیات با موفقیت انجام شد ---")

if __name__ == "__main__":
    main()
