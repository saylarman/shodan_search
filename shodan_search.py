import shodan
import os
import sys

def sanitize_filename(query):
    """
    Sanitizes the query string to be used as a valid filename.
    """
    # A list of characters that are invalid in filenames on most OSes
    invalid_chars = '<>:"/\\|?*'
    filename = query.strip()
    for char in invalid_chars:
        filename = filename.replace(char, '_')

    # Avoid empty filenames or filenames that are just dots
    if not filename or filename.strip('.') == '':
        filename = 'shodan_results' # Default filename

    return f"{filename}.txt"

def main():
    """
    Main function to run the Shodan search script.
    """
    print("--- Shodan Search Script ---")
    print("این اسکریپت به شما کمک می‌کند تا با استفاده از API شودان، نتایج جستجو را ذخیره کنید.")

    # 1. Get Shodan API Key from user
    api_key = input("لطفا کلید API شودان خود را وارد کنید (Shodan API Key): ").strip()
    if not api_key:
        print("\nخطا: کلید API نمی‌تواند خالی باشد. برنامه متوقف شد.")
        sys.exit(1)

    # 2. Get search query from user
    query = input("لطفا کوئری جستجوی خود را وارد کنید: ").strip()
    if not query:
        print("\nخطا: کوئری جستجو نمی‌تواند خالی باشد. برنامه متوقف شد.")
        sys.exit(1)

    # Initialize the Shodan API client
    try:
        api = shodan.Shodan(api_key)
        # Check if the API key is valid by making a small, inexpensive request
        api.info()
        print("\nکلید API معتبر است. در حال اتصال به شودان...")
    except shodan.APIError as e:
        print(f"\nخطا در اتصال به شودان: {e}")
        print("لطفا از صحیح بودن کلید API خود اطمینان حاصل کنید. برنامه متوقف شد.")
        sys.exit(1)

    # 3. Perform the search and save results
    output_filename = sanitize_filename(query)
    print(f"\nدر حال جستجو برای کوئری: '{query}'")
    print(f"نتایج در فایلی به نام '{output_filename}' ذخیره خواهند شد...")

    count = 0
    try:
        # Open the output file for writing
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(f"نتایج جستجو برای کوئری: {query}\n")
            f.write("="*50 + "\n\n")

            # Use the search_cursor to automatically handle pagination and get all results.
            # This is the most efficient way to download all results.
            for result in api.search_cursor(query):
                ip = result.get('ip_str', 'N/A')
                port = result.get('port', 'N/A')
                hostnames = ", ".join(result.get('hostnames', []))
                if not hostnames:
                    hostnames = "دامنه یا هاست‌نیم پیدا نشد"

                # Write the desired information to the file
                output_line = f"IP: {ip}\tPort: {port}\tHostnames: {hostnames}\n"
                f.write(output_line)

                count += 1
                # Provide progress feedback to the user for every 100 results
                if count % 100 == 0:
                    print(f"... {count} نتیجه تاکنون پیدا و ذخیره شده است.")

    except shodan.APIError as e:
        print(f"\nخطا در هنگام جستجو: {e}")
        print("ممکن است کوئری شما پیچیده باشد یا محدودیت‌هایی در حساب کاربری شما وجود داشته باشد.")
        sys.exit(1)
    except Exception as e:
        print(f"\nیک خطای پیش‌بینی نشده رخ داد: {e}")
        sys.exit(1)

    print("\n----------------------------------------")
    print("عملیات با موفقیت به پایان رسید.")
    print(f"تعداد کل نتایج ذخیره شده: {count}")
    print(f"فایل خروجی در مسیر زیر ذخیره شد: {os.path.abspath(output_filename)}")
    print("----------------------------------------")

if __name__ == "__main__":
    main()
