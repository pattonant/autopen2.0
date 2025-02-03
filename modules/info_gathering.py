#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import whois
import dns.resolver
import subprocess
import json
from rich.console import Console
from typing import Dict, Any

console = Console()

class InfoGathering:
    def __init__(self, target: str):
        self.target = target
        self.results: Dict[str, Any] = {}
    
    def gather_whois(self) -> Dict[str, Any]:
        """获取WHOIS信息"""
        try:
            whois_info = whois.whois(self.target)
            self.results['whois'] = whois_info
            return whois_info
        except Exception as e:
            console.print(f"[red]WHOIS查询失败: {str(e)}[/red]")
            return {}
    
    def gather_dns(self) -> Dict[str, Any]:
        """获取DNS信息"""
        dns_info = {
            'A': [],
            'MX': [],
            'NS': [],
            'TXT': []
        }
        
        for record_type in dns_info.keys():
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                dns_info[record_type] = [str(rdata) for rdata in answers]
            except Exception as e:
                console.print(f"[yellow]DNS {record_type}记录查询失败: {str(e)}[/yellow]")
        
        self.results['dns'] = dns_info
        return dns_info
    
    def run_dnsrecon(self) -> Dict[str, Any]:
        """运行dnsrecon工具"""
        try:
            cmd = f"dnsrecon -d {self.target} -t std"
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, error = process.communicate()
            
            if process.returncode == 0:
                self.results['dnsrecon'] = output.decode()
                return {'output': output.decode()}
            else:
                console.print(f"[red]DNSRecon执行失败: {error.decode()}[/red]")
                return {}
        except Exception as e:
            console.print(f"[red]DNSRecon执行错误: {str(e)}[/red]")
            return {}
    
    def gather_all(self) -> Dict[str, Any]:
        """执行所有信息收集任务"""
        console.print("[bold blue]开始信息收集...[/bold blue]")
        
        self.gather_whois()
        self.gather_dns()
        self.run_dnsrecon()
        
        return self.results 