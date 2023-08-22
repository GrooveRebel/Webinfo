import argparse
import requests
import socket
import re
import whois
import nmap
import random
import string
import colorama
from tqdm import tqdm
import multiprocessing
import sys
from whatweb import whatweb

# 当前软件版本信息
def banner():
    colorama.init(autoreset=True)
    print("\033[36m" + """           
\ \    / / ___   | |__     (_)    _ _       / _|   ___   
 \ \/\/ / / -_)  | '_ \    | |   | ' \     |  _|  / _ \  
  \_/\_/  \___|  |_.__/   _|_|_  |_||_|   _|_|_   \___/  
V1.0.0      """ + "\033[0m")
    print("\033[1;32m#Coded by ZT  Update:2023.07.28\033[0m")

#第一部分：准备工作，处理输入信息的函数

# 请求头库
def headers_lib():
    lib = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:58.0) Gecko/20100101 Firefox/58.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:25.0) Gecko/20100101 Firefox/25.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 OPR/50.0.2762.58",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0"]
    headers = {
        "User-Agent": random.choice(lib)}
    return headers

# 判断输入是IP还是域名
def isIP(str):
    try:
        check_ip = re.compile(
            '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        if check_ip.match(str):
            return True
        else:
            return False
    except:
        return False

# 检测http头是否缺失
def check_head(url):
    if url[:4] == "http":
        return url
    else:
        head = "https://"
        fix_url = head + url
        try:
            res = requests.get(url=url, headers=headers_lib(), verify=False)
            if res.status_code == 200:
                return fix_url
            else:
                return "http://" + url
        except:
            return "http://" + url

# 格式化url,提取url
def get_domain(url):
    if "https://" in url or "http://" in url:
        url = url.replace("https://", "").replace("http://", "")
    domain = "{}".format(url).split("/")[0]
    return domain

#第二部分：获取网站基本信息

# 获取网页标题
def get_title(url):
    try:
        res = requests.get(url=url, headers=headers_lib(), verify=False, timeout=3)
        res.encoding = res.apparent_encoding
        html = res.text
        title = re.findall("<title>(.*?)</title>", html, re.S)[0]
    except:
        title = "None"
    return title.replace(" ", "").replace("\r", "").replace("\n", "")

# 获取ip地址和所属位置，存储在ip_list
def check_ip(ip):
    ip_list = []
    for i in ip:
        url = "https://ip.cn/ip/{}.html".format(i)
        res = requests.get(url=url, timeout=10, headers=headers_lib())
        html = res.text
        site = re.findall('<div id="tab0_address">(.*?)</div>', html, re.S)[0]
        result = "{}-{}".format(i, site).replace("  ", "-").replace(" ", "-")
        ip_list.append(result)
    return ip_list

# 获取网站的中间件、服务器等版本信息
def what_web(url):
    cms = whatweb(url)
    server_type = re.search(r'HTTPServer\[(.*?)\]',cms).group(1)
    print("\033[1;32m[Server_Type]:\033[0m\033[36m{}\033[0m".format(server_type))

# 获取网站whois等基本信息,输出基本信息
def get_base_info(url):
    domain_url = get_domain(url)
    ip = []
    try:
        addrs = socket.getaddrinfo(domain_url, None)
        for item in addrs:
            if item[4][0] not in ip:
                ip.append(item[4][0])
        if len(ip) > 1:
            print("\033[1;32m[Ip]:\033[0m\033[36m{}\033[0m \033[1;31m PS:CDN may be used\033[0m".format(check_ip(ip)))

        else:
            print("\033[1;32m[Ip]:\033[0m\033[36m{}\033[0m".format(check_ip(ip)[0]))
    except Exception as e:
        print("\033[1;32m[Ip_Error]:\033[0m\033[36m{}\033[0m".format(e))

    title = get_title(url)
    print("\033[1;32m[Website_title]:\033[0m\033[36m{}\033[0m".format(
        title.replace(" ", "").replace("/r", "").replace("/n", "")))
    what_web(url)

    if isIP(domain_url):
        url_d = "https://site.ip138.com/{}/".format(domain_url)                     #域名反查
        res = requests.get(url=url_d, headers=headers_lib())
        html = res.text
        site = re.findall('<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', html, re.S)
        if len(site) > 0:
            print("\033[1;32m[The bound domain_name]:\033[0m")
            for a, b, c in site:
                print("\033[36m{} {}\033[0m".format(a, b))
    else:
        whois_info = whois.whois(domain_url)
        format_print(whois_info)

    return ip

# 美化输出whois内容
def format_print(res_info):
    res_info = dict(res_info)
    for key in res_info.keys():
        try:
            if res_info[key] is not None:
                isList = True if type(res_info[key]) == list else False
                if isList:
                    print("\033[1;32m[{}]:\033[0m\033[36m{}\033[0m".format(key, ','.join(map(str, res_info[key]))))
                else:
                    print("\033[1;32m[{}]:\033[0m\033[36m{}\033[0m".format(key, str(res_info[key])))
        except Exception as e:
            print('\033[1;31m[Error]:{}\033[0m'.format(e))



#第三部分：各种功能实现

# 读文件，批量扫描功能模块
def bat_scan(filename):
    with open(filename, "r+", encoding="utf-8") as f:
        url_list = f.readlines()
    return url_list

# 调用本地nmap进行端口扫描模块
def port_scan(ip_list):
    for ip in ip_list:
        arguments = '-sS -T5 -Pn'
        nm = nmap.PortScanner()
        try:
            nm.scan(hosts=ip, arguments=arguments, sudo=True)
        except:
            nm.scan(hosts=ip, arguments=arguments)
        scan_info = nm[ip]
        tcp = scan_info["tcp"]
        print("\033[1;32m[Port_info_{}]:\033[0m".format(ip))
        for i in tcp.keys():
            print("\033[1;34m{} {} {} {}\033[0m".format(i, tcp[i]['state'], tcp[i]['name'], tcp[i]['version']))



# 存在虚假页面进行目录扫描
def func1(url, key, check_value):
    b = key.strip()
    url = url + b
    try:
        c = requests.get(url=url, timeout=3, headers=headers_lib())
        if c.status_code == 200 and c.content not in check_value[0]:
            return '[url]:' + c.url + '\t200 OK'
    except:
        return


# 不存在虚假页面进行目录扫描
def func2(url, key):
    b = key.strip()
    url = url + b
    try:
        c = requests.get(url=url, timeout=3, headers=headers_lib())
        if c.status_code == 200:
            return '200 OK ' + '\t' + 'URL:' + c.url
    except:
        return


# 随机生成字符串
def genRandomString(slen=10):
    return ''.join(random.sample(string.ascii_letters + string.digits, slen))


# 目录扫描前检测是否存在虚假页面
def check_fake_res(url):
    check_value = []
    for i in range(3):
        test_url = url + "/" + genRandomString(slen=24)
        res = requests.get(url=test_url, headers=headers_lib())
        if res.status_code == 200:
            html = res.content
            check_value.append(html)
    check_value = list(set(check_value))
    if len(check_value) == 1:
        print(colorama.Fore.RED + '存在伪响应页面')
        return check_value


# 更新目录扫描进度条
def update_dir(url):
    if url and url not in dir:
        dir.append(url)
        pbar.write(colorama.Fore.BLUE + url)
    pbar.update()


# 读取字典
def read_dict(filename):
    with open(filename, 'r') as a:
        dict_lib = a.readlines()
    return dict_lib


# 目录扫描主方法
def dir_scan(url):
    print("\033[1;32m[Website_directory]:\033[0m")
    if url.count("/") == 2:
        url = url + "/"
    if "." in url[url.rfind("/"):]:
        url = url.replace(url[url.rfind("/"):], "")
    url = url.rstrip("/")
    check_value = check_fake_res(url)
    dir_dict = read_dict("dict/fuzz.txt")
    pool_num = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=5 * pool_num)
    global pbar
    pbar = tqdm(total=len(dir_dict), ncols=75)
    pbar.set_description(colorama.Fore.BLUE + "进度条")
    global dir
    dir = []
    if check_value:
        for key in dir_dict:
            if key[:1] != "/":
                key = "/{}".format(key)
            pool.apply_async(func1, args=(url, key, check_value),
                             callback=update_dir)  # 维持执行的进程总数为processes，当一个进程执行完毕后会添加新的进程进去
    else:
        for key in dir_dict:
            if key[:1] != "/":
                key = "/{}".format(key)
            pool.apply_async(func2, args=(url, key), callback=update_dir)
    pool.close()
    pool.join()


# 检测子域名是否存在
def check_subname(subname, url):
    try:
        domain_url = "https://{}.{}".format(subname, url)
        res1 = requests.get(url=domain_url, headers=headers_lib(), timeout=3)
        if res1.status_code == 200:
            domain_url = "{}.{}".format(subname, url)
            return domain_url
    except:
        domain_url = None
    try:
        domain_url = "http://{}.{}".format(subname, url)
        res2 = requests.get(url=domain_url, headers=headers_lib(), timeout=3)
        if res2.status_code == 200:
            domain_url = "{}.{}".format(subname, url)
            return domain_url
    except:
        domain_url = None
    domain_url = None
    return domain_url


# 更新子域名扫描进度条
def update_sub(domain_url):
    ip = []
    if domain_url:
        try:
            addrs = socket.getaddrinfo(domain_url, None)
            for item in addrs:
                if item[4][0] not in ip:
                    ip.append(item[4][0])
            title = get_title(check_head(domain_url))
            if len(ip) > 1:

                sub.write(colorama.Fore.BLUE + "{}-{}-{}\033[1;31m PS:CDN may be used\033[0m".format(
                    domain_url, title,
                    check_ip(ip)))
            else:
                sub.write(
                    colorama.Fore.BLUE + "{}-{}-{}".format(domain_url, title, check_ip(ip)[0]))
        except Exception as e:
            sub.write("\033[1;32m[Sub_Error]:\033[0m\033[36m{}\033[0m".format(e))
    sub.update()


# 子域名扫描主方法
def sub_scan(url):
    print("\033[1;32m[Subdomain]:\033[0m")
    url = ".".join(get_domain(url).split(".")[1:])
    sub_dict = read_dict("dict/subdomain.txt")
    pool_num = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(processes=5 * pool_num)
    global sub
    sub = tqdm(total=len(sub_dict), ncols=75)
    sub.set_description(colorama.Fore.BLUE + "进度条")
    for subname in sub_dict:
        subname = subname.replace("\n", "")
        pool.apply_async(check_subname, args=(subname, url), callback=update_sub)
    pool.close()
    pool.join()


# 程序功能选择模块
def switch(url, port, dirscan, subscan, fullscan):
    ip = get_base_info(url)
    if fullscan:
        print('\033[1;31m正在启动端口扫描······\033[0m')
        port_scan(ip)
        print('\n\033[1;31m正在启动目录扫描······\033[0m')
        dir_scan(url)
        print('\n\n\033[1;31m正在启动子域名扫描······\033[0m')
        sub_scan(url)
    if port:
        print('\033[1;31m正在启动端口扫描······\033[0m')
        port_scan(ip)
    if dirscan:
        print('\033[1;31m正在启动目录扫描······\033[0m')
        dir_scan(url)
    if subscan:
        print('\033[1;31m正在启动子域名扫描······\033[0m')
        sub_scan(url)


# 日志功能
class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "w+")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(
            "{}".format(message).replace("[1;31m", "").replace("[1;32m", "").replace("[36m", "").replace(
                "[34m", "").replace("[0m", ""))

    def flush(self):
        pass

#主程序入口
if __name__ == '__main__':
    banner()
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(
        description="BugMap (An automatic information collection tool for pre penetration testing)")
    parser.add_argument('-u', '--url', help='Scan target banner')
    parser.add_argument('-r', '--read', help='Batch scan target url')
    parser.add_argument('-p', '--port', help='Scan target port', action='store_true')
    parser.add_argument('-d', '--dirscan', help='Scan target directory', action='store_true')
    parser.add_argument('-s', '--subscan', help='Scan target subdomain', action='store_true')
    parser.add_argument('-a', '--fullscan', help='Use all options', action='store_true')
    parser.add_argument('-o', '--outlog', help='Output log')
    args = parser.parse_args()
    url = args.url
    filename = args.read
    port = args.port
    dirscan = args.dirscan
    subscan = args.subscan
    fullscan = args.fullscan
    outlog = args.outlog
    if outlog:
        sys.stdout = Logger(outlog)
    if filename is not None:
        url_list = bat_scan(filename)
        print("\033[1;32m[Total_task]:\033[0m\033[36m{}\033[0m".format(len(url_list)))
        i = 0
        for url in url_list:
            try:
                i += 1
                url = url.replace("\n", "")
                print("\033[1;32m[Task_{}]:\033[0m\033[36m{}\033[0m".format(i, url))
                switch(check_head(url), port, dirscan, subscan, fullscan)
                print()
            except Exception as e:
                print('\033[1;31m[Error]:{}\033[0m'.format(e))
    else:
        if url:
            print("\033[1;32m[Task]:\033[0m\033[36m{}\033[0m".format(url))
            switch(check_head(url), port, dirscan, subscan, fullscan)

