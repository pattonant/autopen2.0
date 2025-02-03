#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import json
import re
from rich.console import Console
from typing import Dict, Any, List
from retry import retry

console = Console()

class VulnScanner:
    def __init__(self, target: str, ports: List[int]):
        self.target = target
        self.ports = ports
        self.results: Dict[str, Any] = {}
    
    @retry(tries=3, delay=2)
    def run_nikto(self, port: int) -> Dict[str, Any]:
        """运行Nikto Web漏洞扫描"""
        try:
            cmd = f"nikto -h {self.target} -p {port} -Format json"
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            if process.returncode == 0:
                return json.loads(output.decode())
            else:
                console.print(f"[red]Nikto扫描失败: {error.decode()}[/red]")
                return {}
        except Exception as e:
            console.print(f"[red]Nikto执行错误: {str(e)}[/red]")
            return {}
    
    @retry(tries=3, delay=2)
    def run_sqlmap(self, url: str) -> Dict[str, Any]:
        """运行SQLMap检测SQL注入"""
        try:
            cmd = f"sqlmap -u {url} --batch --random-agent --level 1 --risk 1 --output-dir=./sqlmap_results"
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            # 解析SQLMap输出
            result = {
                'vulnerable': False,
                'injection_points': [],
                'details': output.decode()
            }
            
            if 'SQL injection vulnerability has been detected' in output.decode():
                result['vulnerable'] = True
                # 提取注入点
                injection_points = re.findall(r'Parameter: (\w+)', output.decode())
                result['injection_points'] = injection_points
            
            return result
        except Exception as e:
            console.print(f"[red]SQLMap执行错误: {str(e)}[/red]")
            return {}
    
    def check_smb_vuln(self) -> Dict[str, Any]:
        """检查SMB漏洞"""
        try:
            # 运行永恒之蓝检测脚本
            cmd = f"nmap -p445 --script smb-vuln-ms17-010 {self.target}"
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            result = {
                'vulnerable': False,
                'details': output.decode()
            }
            
            if 'VULNERABLE' in output.decode():
                result['vulnerable'] = True
            
            return result
        except Exception as e:
            console.print(f"[red]SMB漏洞检测错误: {str(e)}[/red]")
            return {}
    
    def scan_web_service(self, port: int) -> Dict[str, Any]:
        """扫描Web服务漏洞"""
        results = {}
        
        # 运行Nikto
        console.print(f"[blue]正在使用Nikto扫描Web服务 (端口 {port})...[/blue]")
        results['nikto'] = self.run_nikto(port)
        
        # 检查常见Web路径
        target_url = f"http://{self.target}:{port}"
        common_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin']
        
        for path in common_paths:
            url = f"{target_url}{path}"
            console.print(f"[blue]正在检查SQL注入 ({url})...[/blue]")
            results[f'sqlmap_{path}'] = self.run_sqlmap(url)
        
        return results
    
    def scan_all(self) -> Dict[str, Any]:
        """执行所有漏洞扫描"""
        console.print("[bold blue]开始漏洞扫描...[/bold blue]")
        
        for port in self.ports:
            if port in [80, 443, 8080]:  # Web端口
                self.results[f'web_{port}'] = self.scan_web_service(port)
            elif port == 445:  # SMB端口
                self.results['smb'] = self.check_smb_vuln()
        
        return self.results
    
    def export_json(self, filepath: str) -> None:
        """导出扫描结果为JSON格式"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4)
            console.print(f"[green]漏洞扫描结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出结果失败: {str(e)}[/red]") 