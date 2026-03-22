# Web Security Scanner
一个轻量级的Web安全扫描工具，用于检测常见Web漏洞。

## 功能

- 目录爆破：扫描网站隐藏路径
- SQL注入检测：通过5种payload检测SQL注入漏洞
- XSS检测：通过6种payload检测反射型XSS漏洞
- 端口扫描：扫描常见端口（21、22、23、80、443、3306、3389、8080、8443）
- HTML报告：自动生成带统计和修复建议的扫描报告

## 使用

```bash
pip install requests beautifulsoup4
python get_web_info.py
```

## 测试环境

- DVWA (Damn Vulnerable Web Application) 本地测试环境

## 检测效果

在DVWA测试环境中成功检测到：
- SQL注入漏洞（3个payload触发）
- 反射型XSS漏洞（6个payload触发）

## 作者

Doux-x
