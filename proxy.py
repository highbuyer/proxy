import requests
from bs4 import BeautifulSoup
import random
import re
from typing import List, Optional
from pydantic import BaseModel


class ProxyNode(BaseModel):
    type: str  # 代理协议类型，如 "vmess"、"trojan" 等等。
    address: str  # 服务器地址
    port: int  # 服务端口号





def parse_proxy(proxy_str):
    # 匹配 ss:// 和 ssr:// 链接格式
    pattern = re.compile(r'(ssr?|vmess|trojan)://([^/]+)/?.*$')
    m = pattern.match(proxy_str)

    if m:
        protocol, node_info = m.groups()

        # 解析节点信息
        if protocol == 'vmess':
            node_type, addr, port, method, uid, security = node_info.split(':')
            return {'type': protocol,
                    'server': addr,
                    'port': int(port),
                    'uuid': uid,
                    'alterId': 0,
                    'cipher': method}

        elif protocol == 'trojan':
            password, server_addr_port = node_info.split('@')
            server_addr_port_list = server_addr_port.split(':')

            return {'type': protocol,
                    'password': password,
                    "server": server_addr_port_list[0],
                    "port": int(server_addr_port_list[1])}

        else:  # shadowsocks and shadowsocksr protocols
            param_dict = {}

        for param in node_info.split('&'):
            k, v = param.split('=')
            param_dict[k] = v

        if (protocol == 'ss'):
            cipher = param_dict['cipher']
            passwd = param_dict['password']
            obfs = None
            obfs_param = None

        elif (protocol == 'ssr'):

            cipher, param_str, param_b64, pwd_and_obfs_method = decode_base64(param_dict['obfs']) \
                .split(':', 3)

            passwd, proto, mixPortAndFlag, obfs_name, \
                obfs_param = decode_base64(param_b64).split(':', 4)

            # 解析出节点信息
        server_addr_port = param_str.split(':')[0:2]

        return {'type': protocol,
                'server': server_addr_port[0],
                'port': int(server_addr_port[1]),
                'cipher': cipher,
                'password': passwd,
                'protocol': proto or None,
                "obfs": obfs_name or None,
                "obfs_param": obfs_param or None}

    else:
        raise ValueError('Invalid proxy string')

def find_proxies_url(available_sources):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                             '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/5373'}

    # 随机选择一个URL进行尝试
    proxy_sites = ['https://www.xicidaili.com/', 'http://www.ip3366.net/',
                   'https://www.kuaidaili.com/free/inha/',
                   'http://ip.zdaye.com/dayProxy.html']

    random.shuffle(proxy_sites)

    for site in proxy_sites:
        if site not in available_sources:
            try:
                response = requests.get(site, headers=headers)
                if response.status_code == 200:
                    print(f"已找到可用的代理源：{site}")
                    return site

            except Exception as e:
                pass

            available_sources.add(site)

        else:  # 如果该源已经被访问过，则直接跳过
            continue

    raise ValueError("无法找到可用的免费代理IP源")


def validate_proxy(proxy):
    proxies = {"http": proxy, "https": proxy}

    try:

        google_search_url = "https://www.google.com/search?q=apple"
        response = requests.get(google_search_url, proxies=proxies, timeout=5)

        if response.status_code == 200 and "Apple" in response.text:  # 检查响应是否包含“Apple”关键字
            return True

    except Exception as e:

        pass

    return False


def get_proxies(max_num_proxies=10, source_url=None):
    available_sources = set()
    num_proxies_found = 0
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                             '(KHTML, like Gecko) Chrome/58.0.3029.110 Safari/5373'}

    response = requests.get(source_url, headers=headers)

    while num_proxies_found < max_num_proxies:
        proxy_url = None

        try:
            # 获取代理源链接
            source_url = find_proxies_url(available_sources)

            # 爬取页面内容并解析出所有代理URL
            response = requests.get(source_url, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')

            for tr in soup.find_all('tr'):
                tds = tr.find_all('td')

                if len(tds) >= 2 and ":" in tds[1].text:  # 匹配有效的IP地址格式

                    address_port_strs = re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", str(tds))

                    for address_port_str in address_port_strs:
                        proxy_node = parse_proxy("http://" + address_port_str)

                        if proxy_node is not None and validate_proxy(proxy_node.address + ":" + str(proxy_node.port)):
                            yield proxy_node
                            num_proxies_found += 1

                            if num_proxies_found == max_num_proxies:
                                break

        except Exception as e:

            print("Error: ", e)

    print(f"共找到 {num_proxies_found} 个可用的代理IP地址")


def get_proxies():
    # 添加处理 vmess:// 和 trojan:// 链接格式的代码

    proxies = []

    with open('proxies.txt', 'r') as f:
        for line in f.readlines():
            line = line.strip()

            if not line.startswith('#'):
                try:
                    proxy_config = parse_proxy(line)
                    proxies.append(proxy_config)

                except Exception as e:
                    print(f'Error parsing proxy config: {line}. {str(e)}')

    return proxies


# 将 validate_proxy() 函数更名为 test_proxy(), 并使其支持所有协议类型。
if __name__ == "__main__":

    for proxy_node in list(get_proxies(max_num_proxies=5)):
        print(proxy_node.dict())
