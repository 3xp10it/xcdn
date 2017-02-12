#############################################################
###                                                  
###   ▄▄▄▄                ▄▄▄     ▄▄▄▄    ▀      ▄   
###  ▀   ▀█ ▄   ▄  ▄▄▄▄     █    ▄▀  ▀▄ ▄▄▄    ▄▄█▄▄ 
###    ▄▄▄▀  █▄█   █▀ ▀█    █    █  ▄ █   █      █   
###      ▀█  ▄█▄   █   █    █    █    █   █      █   
###  ▀▄▄▄█▀ ▄▀ ▀▄  ██▄█▀  ▄▄█▄▄   █▄▄█  ▄▄█▄▄    ▀▄▄ 
###                █                                 
###                ▀                                 
###                                                          
### name: xcdn.py
### function: try to get the actual ip behind cdn
### date: 2016-11-05
### author: quanyechavshuo
### blog: http://3xp10it.cc
#############################################################
# usage:python3 xcdn.py www.baidu.com
import time
import os
os.system("pip3 install exp10it -U --no-cache")    
from exp10it import figlet2file
figlet2file("3xp10it",0,True)
time.sleep(1)

from exp10it import CLIOutput
from exp10it import get_root_domain
from exp10it import get_string_from_command
from exp10it import get_http_or_https
from exp10it import post_request
from exp10it import get_request
from exp10it import checkvpn
import sys
import re

class Xcdn(object):

    def __init__(self,domain):
        #必须保证连上了vpn,要在可以ping通google的条件下使用本工具,否则有些domain由于被GFW拦截无法正常访问会导致
        #本工具判断错误,checkvpn在可以ping通google的条件下返回1
        while 1:
            if checkvpn()==1:
                break
            else:
                time.sleep(1)
                print("vpn is off,connect vpn first")
        if domain[:4]=="http":
            print("domain format error,make sure domain has no http,like www.baidu.com but not \
http://www.baidu.com")
            sys.exit(0)
        #首先保证hosts文件中没有与domain相关的项,有则删除相关
        domainPattern=domain.replace(".","\.")
        #下面的sed的正则中不能有\n,sed匹配\n比较特殊
        #http://stackoverflow.com/questions/1251999/how-can-i-replace-a-newline-n-using-sed
        command="sed -ri 's/.*\s+%s//' /etc/hosts" % domainPattern
        os.system(command)

        self.domain=domain
        self.http_or_https=get_http_or_https(self.domain)
        print('domain的http或https是:%s' % self.http_or_https)
        result=get_request(self.http_or_https+"://"+self.domain,'seleniumPhantomJS')
        self.domain_title=result['title']
        #下面调用相当于main函数的get_actual_ip_from_domain函数
        actual_ip = self.get_actual_ip_from_domain()
        if actual_ip != 0:
            print("恭喜,%s的真实ip是%s" % (self.domain, actual_ip))
        #下面用来存放关键返回值
        self.return_value=actual_ip

        
    def domain_has_cdn(self):
        # 检测domain是否有cdn
        # 有cdn时,返回一个字典,如果cdn是cloudflare，返回{'has_cdn':1,'is_cloud_flare':1}
        # 否则返回{'has_cdn':1,'is_cloud_flare':0}或{'has_cdn':0,'is_cloud_flare':0}
        import re
        CLIOutput().good_print("现在检测domain:%s是否有cdn" % self.domain)
        has_cdn = 0
        # ns记录和mx记录一样,都要查顶级域名,eg.dig +short www.baidu.com ns VS dig +short baidu.com ns
        result = get_string_from_command("dig ns %s +short" % get_root_domain(self.domain))
        pattern = re.compile(
            r"(cloudflare)|(cdn)|(cloud)|(fast)|(incapsula)|(photon)|(cachefly)|(wppronto)|(softlayer)|(incapsula)|(jsdelivr)|(akamai)", re.I)
        cloudflare_pattern = re.compile(r"cloudflare", re.I)
        if re.search(pattern, result):
            if re.search(cloudflare_pattern, result):
                print("has_cdn=1 from ns,and cdn is cloudflare")
                return {'has_cdn': 1, 'is_cloud_flare': 1}
            else:
                print("has_cdn=1 from ns")
                return {'has_cdn': 1, 'is_cloud_flare': 0}
        else:
            # 下面通过a记录个数来判断,如果a记录个数>1个,认为有cdn
            result = get_string_from_command("dig a %s +short" % self.domain)
            find_a_record_pattern = re.findall(r"((\d{1,3}\.){3}\d{1,3})", result)
            if find_a_record_pattern:
                ip_count = 0
                for each in find_a_record_pattern:
                    ip_count += 1
                if ip_count > 1:
                    has_cdn = 1
                    return {'has_cdn': 1, 'is_cloud_flare': 0}
        return {'has_cdn': 0, 'is_cloud_flare': 0}


    def get_domain_actual_ip_from_phpinfo(self):
        # 从phpinfo页面尝试获得真实ip
        CLIOutput().good_print("现在尝试从domain:%s可能存在的phpinfo页面获取真实ip" % self.domain)
        phpinfo_page_list = ["info.php", "phpinfo.php", "test.php", "l.php"]
        for each in phpinfo_page_list:
            url = self.http_or_https + "://" + self.domain + "/" + each
            CLIOutput().good_print("现在访问%s" % url)
            visit = get_request(url,'seleniumPhantomJS')
            code = visit['code']
            content = visit['content']
            pattern = re.compile(r"remote_addr", re.I)
            if code == 200 and re.search(pattern, content):
                print(each)
                actual_ip = re.search(r"REMOTE_ADDR[^\.\d]+([\d\.]{7,15})[^\.\d]+", content).group(1)
                return actual_ip
        # return 0代表没有通过phpinfo页面得到真实ip
        return 0


    def flush_dns(self):
        # 这个函数用来刷新本地dns cache
        # 要刷新dns cache才能让修改hosts文件有效
        CLIOutput().good_print("现在刷新系统的dns cache")
        command = "/etc/init.d/dns-clean start && /etc/init.d/networking force-reload"
        os.system(command)
        import time
        time.sleep(3)


    def modify_hosts_file_with_ip_and_domain(self,ip):
        # 这个函数用来修改hosts文件
        CLIOutput().good_print("现在修改hosts文件")
        exists_domain_line = False
        with open("/etc/hosts", "r+") as f:
            file_content = f.read()
        if re.search(r"%s" % self.domain.replace(".", "\."), file_content):
            exists_domain_line = True
        if exists_domain_line == True:
            os.system("sed -ri 's/.*%s.*/%s    %s/' %s" % (self.domain.replace(".", "\."), ip, self.domain, "/etc/hosts"))
        else:
            os.system("echo %s %s >> /etc/hosts" % (ip, self.domain))


    def check_if_ip_is_actual_ip_of_domain(self,ip):
        # 通过修改hosts文件检测ip是否是domain对应的真实ip
        # 如果是则返回True,否则返回False
        CLIOutput().good_print("现在通过修改hosts文件并刷新dns的方法检测ip:%s是否是domain:%s的真实ip" % (ip,
            self.domain))
        os.system("cp /etc/hosts /etc/hosts.bak")
        self.modify_hosts_file_with_ip_and_domain(ip)
        self.flush_dns()
        hosts_changed_domain_title= get_request(self.http_or_https + "://%s" % self.domain,'seleniumPhantomJS')['title']
        os.system("rm /etc/hosts && mv /etc/hosts.bak /etc/hosts")
        #这里要用title判断,html判断不可以,title相同则认为相同
        if self.domain_title== hosts_changed_domain_title:
            print("是的！！！！！！！！！！！！")
            return True
        else:
            print("不是的！！！！！！！！！！！！")
            return False


    def get_c_80_or_443_list(self,ip):
        # 得到ip的整个c段的开放80端口或443端口的ip列表
        if "not found" in get_string_from_command("masscan"):
            #这里不用nmap扫描,nmap扫描结果不准
            os.system("apt-get install masscan")
        if self.http_or_https=="http":
            scanPort=80
            CLIOutput().good_print("现在进行%s的c段开了80端口机器的扫描" % ip)
        if self.http_or_https=="https":
            scanPort=443
            CLIOutput().good_print("现在进行%s的c段开了443端口机器的扫描" % ip)
        masscan_command = "masscan -p%d %s/24 > /tmp/masscan.out" % (scanPort,ip)
        os.system(masscan_command)
        with open("/tmp/masscan.out", "r+") as f:
            strings = f.read()
        #os.system("rm /tmp/masscan.out")
        import re
        allIP=re.findall(r"((\d{1,3}\.){3}\d{1,3})",strings)
        ipList=[]
        for each in allIP:
            ipList.append(each[0])
        print(ipList)
        return ipList


    def check_if_ip_c_machines_has_actual_ip_of_domain(self,ip):
        # 检测ip的c段有没有domain的真实ip,如果有则返回真实ip,如果没有则返回0
        CLIOutput().good_print("现在检测ip为%s的c段中有没有%s的真实ip" % (ip,self.domain))
        target_list=self.get_c_80_or_443_list(ip)
        for each_ip in target_list:
            if True == self.check_if_ip_is_actual_ip_of_domain(each_ip):
                return each_ip
        return 0


    def get_ip_from_mx_record(self):
        # 从mx记录中得到ip列表,尝试从mx记录中的c段中找真实ip
        print("尝试从mx记录中找和%s顶级域名相同的mx主机" % self.domain)
        import socket
        # domain.eg:www.baidu.com
        from exp10it import get_root_domain
        root_domain = get_root_domain(self.domain)
        from exp10it import get_string_from_command
        result = get_string_from_command("dig %s +short mx" % root_domain)
        sub_domains_list = re.findall(r"\d{1,} (.*\.%s)\." % root_domain.replace(".", "\."), result)
        ip_list = []
        for each in sub_domains_list:
            print(each)
            ip = socket.gethostbyname_ex(each)[2]
            if ip[0] not in ip_list:
                ip_list.append(ip[0])
        return ip_list


    def check_if_mx_c_machines_has_actual_ip_of_domain(self):
        # 检测domain的mx记录所在ip[或ip列表]的c段中有没有domain的真实ip
        # 有则返回真实ip,没有则返回0
        CLIOutput().good_print("尝试从mx记录的c段中查找是否存在%s的真实ip" % self.domain)
        ip_list = self.get_ip_from_mx_record()
        if ip_list != []:
            for each_ip in ip_list:
                result = self.check_if_ip_c_machines_has_actual_ip_of_domain(each_ip)
                if result != 0:
                    return result
                else:
                    continue
        return 0


    def get_ip_value_from_online_cloudflare_interface(self):
        # 从在线的cloudflare查询真实ip接口处查询真实ip
        # 如果查询到真实ip则返回ip值,如果没有查询到则返回0
        CLIOutput().good_print("现在从在线cloudflare类型cdn查询真实ip接口尝试获取真实ip")
        url = "http://www.crimeflare.com/cgi-bin/cfsearch.cgi"
        post_data = 'cfS=%s' % self.domain
        content = post_request(url, post_data)
        findIp = re.search(r"((\d{1,3}\.){3}\d{1,3})", content)
        if findIp:
            return findIp.group(1)
        return 0


    def get_actual_ip_from_domain(self):
        # 尝试获得domain背后的真实ip,前提是domain有cdn
        # 如果找到了则返回ip,如果没有找到返回0
        CLIOutput().good_print("进入获取真实ip函数,认为每个domain都是有cdn的情况来处理")
        import socket
        has_cdn_value = self.domain_has_cdn()
        if has_cdn_value['has_cdn'] == 1:
            CLIOutput().good_print("检测到domain:%s的A记录不止一个,认为它有cdn" % self.domain)
            pass
        else:
            CLIOutput().good_print("Attention...!!! Domain doesn't have cdn,I will return the only one ip")
            true_ip = socket.gethostbyname_ex(self.domain)[2][0]
            return true_ip
        # 下面尝试通过cloudflare在线查询真实ip接口获取真实ip
        if has_cdn_value['is_cloud_flare'] == 1:
            ip_value = self.get_ip_value_from_online_cloudflare_interface()
            if ip_value != 0:
                return ip_value
            else:
                pass
        # 下面尝试通过可能存在的phpinfo页面获得真实ip
        ip_from_phpinfo = self.get_domain_actual_ip_from_phpinfo()
        if ip_from_phpinfo == 0:
            pass
        else:
            return ip_from_phpinfo
        # 下面通过mx记录来尝试获得真实ip
        result = self.check_if_mx_c_machines_has_actual_ip_of_domain()
        if result == 0:
            pass
        else:
            return result
        print("很遗憾,在下认为%s有cdn,但是目前在下的能力没能获取它的真实ip,当前函数将返回0" % self.domain)
        return 0


if __name__ == '__main__':
    import sys
    domain=sys.argv[1]
    Xcdn(domain)
