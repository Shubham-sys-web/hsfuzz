# HSFuzz - Web Fuzzer

HSFuzz is a versatile, asynchronous web fuzzing tool designed for security researchers and penetration testers. It supports directory enumeration, POST-based fuzzing, login brute force, OTP brute force, and more.

## Features
- **Asynchronous Requests**: High-speed concurrent requests with `aiohttp`.
- **GET and POST Support**: Fuzz URLs or POST data with `FUZZ`.
- **Login Brute Force**: Test username/password combinations.
- **OTP Brute Force**: Brute force OTP fields with a custom range.
- **Proxy Support**: Route traffic through proxies.
- **Output Saving**: Save results to a file.
- **Custom Headers**: Add headers for advanced testing.
- **Status Code Filtering**: Filter out unwanted responses.

## Installation
1. Clone the repository:
   bash
   git clone https://github.com/Shubham-sys-web/hsfuzz.git
   cd hsfuzz
   
2. Install dependencies:
   bash
   pip3 install aiohttp colorama
   

## Usage ⚡

### Directory Fuzzing
bash
python3 hsfuzz.py -u http://example.com -w wordlist.txt -t 50 -fc 403,404 -o results.txt


### Login Brute Force
bash
python3 hsfuzz.py -u http://example.com/login -w dummy.txt -X POST -d "username=USERNAME&password=PASSWORD" --brute-login --username admin --password-list passwords.txt


### OTP Brute Force
bash
python3 hsfuzz.py -u http://example.com/verify -w dummy.txt -X POST -d "otp=OTP" --brute-otp --otp-range 0000-9999 -o otp_results.txt


## Requirements
- Python 3.7+
- aiohttp
- colorama

## Credits
- **HEXSHUBZ**: Original Author
- **Grok 3 (xAI)**: Enhancements and Features

## License
MIT License

