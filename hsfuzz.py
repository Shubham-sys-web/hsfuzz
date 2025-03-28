#!/usr/bin/env python3
import asyncio
import aiohttp
import hashlib
import argparse
import time
from colorama import Fore, Style, init
import logging
import json

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

baseline_length = None
baseline_hash = None

def print_banner():
    banner = f"""{Fore.YELLOW}
#     #  #####  ####### #     # ####### ####### 
#     # #     # #       #     #      #       #  
#     # #       #       #     #     #       #   
#######  #####  #####   #     #    #       #    
#     #       # #       #     #   #       #     
#     # #     # #       #     #  #       #      
#     #  #####  #        #####  ####### ####### 
{Fore.RED}BY HEXSHUBZ | Enhanced by Grok 3 (xAI){Style.RESET_ALL}
    """
    print(banner)

async def fetch_url(session, url, method="GET", headers=None, data=None, timeout=10):
    global baseline_length, baseline_hash
    try:
        timeout_config = aiohttp.ClientTimeout(total=timeout)
        if method.upper() == "POST":
            async with session.post(url, headers=headers, data=data, timeout=timeout_config) as response:
                content = await response.read()
        else:
            async with session.get(url, headers=headers, allow_redirects=False, timeout=timeout_config) as response:
                content = await response.read()
        
        content_length = len(content)
        content_hash = hashlib.md5(content).hexdigest()
        banner = response.headers.get("Server", "Unknown")

        if baseline_length is None and method == "GET":
            try:
                async with session.get(f"{args.url.split('FUZZ')[0]}/nonexistent123456789", headers=headers, timeout=timeout_config) as baseline_resp:
                    baseline_content = await baseline_resp.read()
                    baseline_length = len(baseline_content)
                    baseline_hash = hashlib.md5(baseline_content).hexdigest()
            except Exception as e:
                logging.warning(f"Failed to set baseline: {str(e)}")

        if method == "GET" and content_length == baseline_length and content_hash == baseline_hash:
            return None

        return response.status, content_length, url, banner, data
    except asyncio.TimeoutError:
        logging.error(f"Timeout on {url}")
        return None
    except Exception as e:
        logging.error(f"Exception on {url}: {str(e)}")
        return None

def handle_result(result, filtered_statuses, success_codes):
    if not result:
        return False
    status_code = str(result[0])
    if status_code in filtered_statuses:
        return False
    if success_codes and status_code not in success_codes:
        return False
    return True

def print_result(result, output_file=None):
    status_color = Fore.GREEN if str(result[0]).startswith('2') else Fore.RED if str(result[0]).startswith('4') or str(result[0]).startswith('5') else Fore.YELLOW
    output_str = f"{status_color}[{result[0]}]{Style.RESET_ALL} {result[1]}B {Fore.YELLOW}{result[2]}{Style.RESET_ALL} | Banner: {Fore.MAGENTA}{result[3]}{Style.RESET_ALL}"
    if len(result) > 4:
        output_str += f" | Data: {result[4]}"
    print(output_str)
    
    if output_file:
        with open(output_file, 'a') as f:
            f.write(f"[{result[0]}] {result[1]}B {result[2]} | Banner: {result[3]}")
            if len(result) > 4:
                f.write(f" | Data: {result[4]}")
            f.write("\n")

async def fuzz(url, wordlist, threads, filter_codes, method="GET", headers=None, data_template=None, success_codes=None, proxy=None, timeout=10, output_file=None, brute_login=False, username=None, password_list=None, brute_otp=False, otp_range=None):
    filtered_statuses = set(filter_codes.split(',')) if filter_codes else set()
    success_codes = set(success_codes.split(',')) if success_codes else None
    tasks = []
    total_requests = 0
    start_time = time.time()

    header_dict = {}
    if headers:
        for header in headers:
            header = header.replace('\n', '').replace('\t', '')
            if ':' in header:
                key, value = header.split(":", 1)
                header_dict[key.strip()] = value.strip()
            else:
                logging.warning(f"Invalid header format: {header}")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        if proxy:
            session._default_proxies = {'http': proxy, 'https': proxy}
        
        try:
            with open(wordlist, "r") as f:
                wordlist_lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                total_words = len(wordlist_lines)

                if brute_login and username and password_list:
                    with open(password_list, "r") as pf:
                        passwords = [line.strip() for line in pf if line.strip() and not line.startswith('#')]
                        for password in passwords:
                            data = data_template.replace("USERNAME", username).replace("PASSWORD", password)
                            tasks.append(fetch_url(session, url, "POST", header_dict, data, timeout))
                            
                            total_requests += 1
                            if len(tasks) >= threads:
                                results = await asyncio.gather(*tasks)
                                for result in results:
                                    if handle_result(result, filtered_statuses, success_codes):
                                        print_result(result, output_file)
                                elapsed_time = time.time() - start_time
                                req_per_sec = total_requests / elapsed_time if elapsed_time > 0 else 0
                                print(f"\r{Fore.CYAN}[*] Progress: {total_requests}/{len(passwords)} | Req/s: {req_per_sec:.2f}{Style.RESET_ALL}", end="")
                                tasks = []

                elif brute_otp and otp_range:
                    start, end = map(int, otp_range.split('-'))
                    otp_list = [f"{i:04d}" for i in range(start, end + 1)]
                    for otp in otp_list:
                        data = data_template.replace("OTP", otp)
                        tasks.append(fetch_url(session, url, "POST", header_dict, data, timeout))
                        
                        total_requests += 1
                        if len(tasks) >= threads:
                            results = await asyncio.gather(*tasks)
                            for result in results:
                                if handle_result(result, filtered_statuses, success_codes):
                                    print_result(result, output_file)
                            elapsed_time = time.time() - start_time
                            req_per_sec = total_requests / elapsed_time if elapsed_time > 0 else 0
                            print(f"\r{Fore.CYAN}[*] Progress: {total_requests}/{len(otp_list)} | Req/s: {req_per_sec:.2f}{Style.RESET_ALL}", end="")
                            tasks = []

                else:
                    for word in wordlist_lines:
                        if method == "GET":
                            target_url = url.replace("FUZZ", word) if "FUZZ" in url else f"{url.rstrip('/')}/{word}"
                            tasks.append(fetch_url(session, target_url, method, header_dict, timeout=timeout))
                        elif method == "POST":
                            target_url = url
                            if data_template:
                                data = data_template.replace("FUZZ", word)
                            else:
                                data = None
                            tasks.append(fetch_url(session, target_url, method, header_dict, data, timeout))

                        total_requests += 1
                        if len(tasks) >= threads:
                            results = await asyncio.gather(*tasks)
                            for result in results:
                                if handle_result(result, filtered_statuses, success_codes):
                                    print_result(result, output_file)
                            elapsed_time = time.time() - start_time
                            req_per_sec = total_requests / elapsed_time if elapsed_time > 0 else 0
                            print(f"\r{Fore.CYAN}[*] Progress: {total_requests}/{total_words} | Req/s: {req_per_sec:.2f}{Style.RESET_ALL}", end="")
                            tasks = []

                if tasks:
                    results = await asyncio.gather(*tasks)
                    for result in results:
                        if handle_result(result, filtered_statuses, success_codes):
                            print_result(result, output_file)
                    elapsed_time = time.time() - start_time
                    req_per_sec = total_requests / elapsed_time if elapsed_time > 0 else 0
                    print(f"\r{Fore.CYAN}[*] Progress: {total_requests}/{total_words if not (brute_login or brute_otp) else (len(passwords) if brute_login else len(otp_list))}{Style.RESET_ALL}")
        except FileNotFoundError as e:
            logging.error(f"File not found: {str(e)}")
        except Exception as e:
            logging.error(f"Exception in fuzzing: {str(e)}")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="HSFuzz - Web Fuzzer by HEXSHUBZ, Enhanced by Grok 3 (xAI)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (use FUZZ as placeholder for GET)")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist file path for fuzzing")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("-fc", "--filter-codes", help="Comma-separated status codes to filter out")
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST"], help="HTTP method (GET or POST)")
    parser.add_argument("-H", "--headers", action="append", help="Custom headers (e.g., 'Content-Type: application/json')")
    parser.add_argument("-d", "--data", help="Data payload for POST (use FUZZ, USERNAME, PASSWORD, OTP as placeholders)")
    parser.add_argument("-sc", "--success-codes", help="Comma-separated status codes to consider as success (e.g., 200)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="File to save results")
    parser.add_argument("--brute-login", action="store_true", help="Enable login brute force mode")
    parser.add_argument("--username", help="Username for brute force login")
    parser.add_argument("--password-list", help="Password list file for brute force login")
    parser.add_argument("--brute-otp", action="store_true", help="Enable OTP brute force mode")
    parser.add_argument("--otp-range", help="OTP range (e.g., 0000-9999)")
    args = parser.parse_args()

    if args.brute_login and (not args.username or not args.password_list or not args.data):
        parser.error("--brute-login requires --username, --password-list, and --data with USERNAME and PASSWORD placeholders")
    if args.brute_otp and (not args.data or not args.otp_range):
        parser.error("--brute-otp requires --data with OTP placeholder and --otp-range")

    try:
        asyncio.run(fuzz(args.url, args.wordlist, args.threads, args.filter_codes, args.method, args.headers, args.data, args.success_codes, args.proxy, args.timeout, args.output, args.brute_login, args.username, args.password_list, args.brute_otp, args.otp_range))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
    except Exception as e:
        logging.error(f"Main execution failed: {str(e)}")
