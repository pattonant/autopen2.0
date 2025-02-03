#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import nmap
import json
from rich.console import Console
from typing import Dict, Any
from retry import retry

console = Console()

class PortScanner:
    def __init__(self, target: str, level: int = 1):
        self.target = target
        self.level = level
        self.nm = nmap.PortScanner()
        self.results: Dict[str, Any] = {}
        
        # 根据扫描级别设置扫描参数
        self.scan_profiles = {
            1: "-sS -T3 -F",  # 快速扫描
            2: "-sS -sV -T3 -p-",  # 全端口扫描
            3: "-sS -sV -sC -O -T4 -p-",  # 带系统识别
            4: "-sS -sV -sC -O -A -T4 -p-",  # 高级扫描
            5: "-sS -sV -sC -O -A -T4 -p- --script vuln"  # 漏洞扫描
        }
    
    @retry(tries=3, delay=2)
    def scan(self) -> Dict[str, Any]:
        """执行端口扫描"""
        try:
            console.print(f"[bold blue]开始端口扫描 (级别 {self.level})...[/bold blue]")
            
            # 获取扫描参数
            scan_args = self.scan_profiles.get(self.level, self.scan_profiles[1])
            
            # 执行扫描
            self.nm.scan(self.target, arguments=scan_args)
            
            # 解析结果
            for host in self.nm.all_hosts():
                self.results[host] = {
                    'state': self.nm[host].state(),
                    'protocols': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    self.results[host]['protocols'][proto] = {}
                    
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        self.results[host]['protocols'][proto][port] = {
                            'state': port_info['state'],
                            'service': port_info.get('name', ''),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
            
            return self.results
            
        except Exception as e:
            console.print(f"[red]端口扫描失败: {str(e)}[/red]")
            raise
    
    def get_open_ports(self) -> Dict[str, list]:
        """获取开放端口列表"""
        open_ports = {}
        
        for host in self.results:
            open_ports[host] = []
            for proto in self.results[host]['protocols']:
                for port, info in self.results[host]['protocols'][proto].items():
                    if info['state'] == 'open':
                        open_ports[host].append({
                            'port': port,
                            'protocol': proto,
                            'service': info['service']
                        })
        
        return open_ports
    
    def export_json(self, filepath: str) -> None:
        """导出扫描结果为JSON格式"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4)
            console.print(f"[green]扫描结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出结果失败: {str(e)}[/red]") 