import requests
import re
import socket
import datetime
import os


# ==================== 工具函数 ====================

def get_web_info(url):
    try:
        response = requests.get(url, timeout=5)
        print(f"状态码：{response.status_code}")
        print(f"响应头：{response.headers}")

        response.encoding = response.apparent_encoding
        title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
        title = title_match.group(1) if title_match else "无标题"
        print(f"页面标题：{title}")
        return response.status_code, title

    except Exception as e:
        print(f"请求失败：{e}")
        return None, None


def dir_scan(url, dict_file, results=None):
    if not url.endswith('/'):
        url = url + '/'

    found_paths = []

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
                        found_paths.append(target_url)
                    elif resp.status_code == 403:
                        print(f"[!] 禁止访问: {target_url} (状态码: 403)")
                        found_paths.append(f"{target_url} (403)")
                except Exception as e:
                    pass
    except FileNotFoundError:
        print(f"字典文件不存在: {dict_file}")

    # 如果传入了results字典，就保存结果
    if results is not None:
        results['dirs'] = found_paths

    return found_paths


def check_sql_injection(url, param, results=None):
    """SQL注入检测"""
    cookies = {
        'PHPSESSID': '135ii86jtki1r9putrf1j8f2bc',
        'security': 'low'
    }

    payloads = [
        "'",
        '"',
        "' OR '1'='1",
        "' AND SLEEP(5)--",
        "1' AND '1'='1"
    ]

    vuln_payloads = []

    print(f"\n[*] 测试目标: {url}?{param}=1")

    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=5, cookies=cookies)

            if "login.php" in response.url:
                print(f"[-] 需要登录: {test_url}")
                continue

            error_keywords = ['sql', 'mysql', 'syntax', 'error', 'warning', 'unclosed', 'mysql_fetch']
            has_error = any(keyword in response.text.lower() for keyword in error_keywords)

            if has_error:
                print(f"[!] 可能存在SQL注入: {test_url}")
                print(f"    payload: {payload}")
                vuln_payloads.append(payload)
            else:
                print(f"[-] 未检测到明显注入: {payload}")

        except Exception as e:
            print(f"[-] 请求失败: {payload} - {e}")

    if results is not None:
        results['sql_injection'] = vuln_payloads

    return vuln_payloads


def check_xss(url, param, results=None):
    """XSS检测"""
    cookies = {
        'PHPSESSID': '135ii86jtki1r9putrf1j8f2bc',
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

    vuln_payloads = []

    print(f"\n[*] 开始XSS检测...")

    for payload in payloads:
        test_url = f"{url}?{param}={payload}"
        try:
            response = requests.get(test_url, timeout=5, cookies=cookies)

            if payload in response.text:
                print(f"[!] 可能存在XSS: {test_url}")
                print(f"    payload: {payload}")
                vuln_payloads.append(payload)
            else:
                if payload == payloads[0]:
                    print(f"[-] 未检测到明显XSS: {payload}")

        except Exception as e:
            print(f"[-] 请求失败: {payload} - {e}")

    if results is not None:
        results['xss'] = vuln_payloads

    return vuln_payloads


def port_scan(host, ports=None, results=None):
    """端口扫描"""
    if ports is None:
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
        sock.close()

    if open_ports:
        print(f"\n[*] 开放端口: {open_ports}")

    if results is not None:
        results['open_ports'] = open_ports

    return open_ports


# ==================== 报告生成 ====================

def generate_report(target_url, scan_results):
    """
    生成完整的HTML扫描报告
    scan_results: 字典，包含所有扫描结果
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 统计漏洞数量
    sql_count = len(scan_results.get('sql_injection', []))
    xss_count = len(scan_results.get('xss', []))
    total_vulns = sql_count + xss_count

    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Web安全扫描报告 - {target_url}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.1);
            margin-bottom: 20px;
            overflow: hidden;
        }}

        .card-header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 25px;
        }}

        .card-header h1 {{
            font-size: 24px;
            margin-bottom: 5px;
        }}

        .card-header p {{
            opacity: 0.9;
            font-size: 14px;
        }}

        .card-body {{
            padding: 25px;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}

        .stat-box {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            border-left: 4px solid #667eea;
        }}

        .stat-box.critical {{
            border-left-color: #dc3545;
        }}

        .stat-box.warning {{
            border-left-color: #ffc107;
        }}

        .stat-number {{
            font-size: 28px;
            font-weight: bold;
            color: #333;
        }}

        .stat-label {{
            color: #666;
            font-size: 14px;
            margin-top: 5px;
        }}

        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}

        .vuln-table th,
        .vuln-table td {{
            border: 1px solid #e0e0e0;
            padding: 12px;
            text-align: left;
        }}

        .vuln-table th {{
            background: #f5f5f5;
            font-weight: 600;
        }}

        .vuln-table tr:hover {{
            background: #fafafa;
        }}

        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}

        .badge-high {{
            background: #dc3545;
            color: white;
        }}

        .badge-medium {{
            background: #ffc107;
            color: #333;
        }}

        .badge-low {{
            background: #28a745;
            color: white;
        }}

        .path-list {{
            list-style: none;
            padding: 0;
        }}

        .path-list li {{
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
            font-family: monospace;
        }}

        .suggestion {{
            background: #e8f4fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin-top: 20px;
            border-radius: 8px;
        }}

        .suggestion h4 {{
            color: #2196f3;
            margin-bottom: 10px;
        }}

        .suggestion ul {{
            margin-left: 20px;
            color: #555;
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: #888;
            font-size: 12px;
        }}

        @media (max-width: 768px) {{
            .stats {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h1>🔒 Web安全扫描报告</h1>
                <p>扫描目标: {target_url}</p>
                <p>扫描时间: {now}</p>
            </div>
            <div class="card-body">

                <!-- 统计卡片 -->
                <div class="stats">
                    <div class="stat-box {'critical' if total_vulns > 0 else ''}">
                        <div class="stat-number">{total_vulns}</div>
                        <div class="stat-label">发现漏洞总数</div>
                    </div>
                    <div class="stat-box {'warning' if sql_count > 0 else ''}">
                        <div class="stat-number">{sql_count}</div>
                        <div class="stat-label">SQL注入漏洞</div>
                    </div>
                    <div class="stat-box {'warning' if xss_count > 0 else ''}">
                        <div class="stat-number">{xss_count}</div>
                        <div class="stat-label">XSS漏洞</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(scan_results.get('open_ports', []))}</div>
                        <div class="stat-label">开放端口</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{len(scan_results.get('dirs', []))}</div>
                        <div class="stat-label">发现路径</div>
                    </div>
                </div>

                <!-- SQL注入检测结果 -->
                <h3>🗄️ SQL注入检测结果</h3>
                <table class="vuln-table">
                    <thead>
                        <tr><th>Payload</th><th>风险等级</th><th>状态</th></tr>
                    </thead>
                    <tbody>
"""

    # SQL注入结果
    sql_payloads = scan_results.get('sql_injection', [])
    if sql_payloads:
        for payload in sql_payloads:
            html += f"""
                        <tr>
                            <td><code>{payload}</code></td>
                            <td><span class="badge badge-high">高危</span></td>
                            <td style="color: red;">⚠️ 可能存在注入</td>
                        </tr>
"""
    else:
        html += """
                        <tr>
                            <td colspan="3" style="text-align: center;">未检测到SQL注入漏洞</td>
                        </tr>
"""

    html += """
                    </tbody>
                </table>

                <!-- XSS检测结果 -->
                <h3 style="margin-top: 25px;">🌐 XSS检测结果</h3>
                <table class="vuln-table">
                    <thead>
                        <tr><th>Payload</th><th>风险等级</th><th>状态</th></tr>
                    </thead>
                    <tbody>
"""

    # XSS结果
    xss_payloads = scan_results.get('xss', [])
    if xss_payloads:
        for payload in xss_payloads:
            # 截断过长的payload
            display_payload = payload if len(payload) <= 50 else payload[:47] + "..."
            html += f"""
                        <tr>
                            <td><code>{display_payload}</code></td>
                            <td><span class="badge badge-medium">中危</span></td>
                            <td style="color: orange;">⚠️ 可能存在XSS</td>
                        </tr>
"""
    else:
        html += """
                        <tr>
                            <td colspan="3" style="text-align: center;">未检测到XSS漏洞</td>
                        </tr>
"""

    html += """
                    </tbody>
                </table>

                <!-- 开放端口 -->
                <h3 style="margin-top: 25px;">🔌 端口扫描结果</h3>
                <ul class="path-list">
"""

    ports = scan_results.get('open_ports', [])
    if ports:
        for port in ports:
            html += f"<li>🔓 端口 {port} 开放</li>"
    else:
        html += "<li>未发现开放端口</li>"

    html += """
                </ul>

                <!-- 发现的路径 -->
                <h3 style="margin-top: 25px;">📁 目录扫描结果</h3>
                <ul class="path-list">
"""

    dirs = scan_results.get('dirs', [])
    if dirs:
        for path in dirs[:20]:  # 最多显示20条
            html += f"<li>📄 {path}</li>"
        if len(dirs) > 20:
            html += f"<li>... 还有 {len(dirs) - 20} 条结果未显示</li>"
    else:
        html += "<li>未发现额外路径</li>"

    html += f"""
                </ul>

                <!-- 修复建议 -->
                <div class="suggestion">
                    <h4>📋 修复建议</h4>
                    <ul>
"""

    if sql_payloads:
        html += """
                        <li><strong>SQL注入修复：</strong>使用参数化查询（Prepared Statements），对所有用户输入进行校验，避免直接拼接SQL语句。</li>
"""
    if xss_payloads:
        html += """
                        <li><strong>XSS修复：</strong>对输出内容进行HTML实体编码，设置CSP（内容安全策略），Cookie设置HttpOnly属性。</li>
"""
    if ports:
        html += """
                        <li><strong>端口暴露：</strong>关闭不必要的端口，使用防火墙限制访问，数据库等服务不要暴露在公网。</li>
"""

    if not sql_payloads and not xss_payloads:
        html += """
                        <li>本次扫描未发现明显漏洞，建议定期进行安全扫描，保持系统更新。</li>
"""

    html += f"""
                    </ul>
                </div>

                <div class="suggestion" style="background: #f5f5f5; border-left-color: #666;">
                    <h4>📊 扫描统计</h4>
                    <ul>
                        <li>SQL注入测试: {len(sql_payloads)} 个payload触发漏洞</li>
                        <li>XSS测试: {len(xss_payloads)} 个payload触发漏洞</li>
                        <li>端口扫描: 共扫描 {len(ports)} 个开放端口</li>
                    </ul>
                </div>
            </div>
        </div>
        <div class="footer">
            <p>Web Security Scanner - 自动生成的安全扫描报告</p>
            <p>本报告仅供参考，请结合人工验证确认漏洞真实性</p>
        </div>
    </div>
</body>
</html>
"""

    # 保存报告
    filename = f"scan_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

    # 获取完整路径
    full_path = os.path.abspath(filename)
    print(f"\n" + "=" * 50)
    print(f"[+] 报告已生成: {full_path}")
    print(f"[+] 用浏览器打开即可查看")
    print("=" * 50)

    return filename


# ==================== 主函数 ====================

def main():
    """主函数 - 执行所有扫描并生成报告"""
    target_url = "http://localhost/DVWA/"
    scan_results = {
        'sql_injection': [],
        'xss': [],
        'open_ports': [],
        'dirs': []
    }

    print("=" * 60)
    print("Web Security Scanner - 开始扫描")
    print("=" * 60)

    # 1. 目录爆破
    print("\n[1/4] 执行目录爆破...")
    dir_scan("https://www.baidu.com", "dict.txt", scan_results)

    # 2. SQL注入检测
    print("\n[2/4] 执行SQL注入检测...")
    check_sql_injection(target_url + "vulnerabilities/sqli/", "id", scan_results)

    # 3. XSS检测
    print("\n[3/4] 执行XSS检测...")
    check_xss(target_url + "vulnerabilities/xss_r/", "name", scan_results)

    # 4. 端口扫描
    print("\n[4/4] 执行端口扫描...")
    port_scan("localhost", None, scan_results)

    # 5. 生成报告
    print("\n" + "=" * 60)
    print("生成扫描报告...")
    print("=" * 60)
    generate_report(target_url, scan_results)

    print("\n扫描完成！")


# 运行主函数
if __name__ == "__main__":
    main()