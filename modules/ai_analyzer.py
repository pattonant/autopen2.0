#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from typing import Dict, Any, List
from rich.console import Console
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import pandas as pd

console = Console()

class AIAnalyzer:
    def __init__(self, model_path: str = "TinyLlama/TinyLlama-1.1B-intermediate-step-1431k-3T"):
        """初始化AI分析器"""
        self.results: Dict[str, Any] = {}
        
        try:
            # 加载模型和分词器
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_path,
                torch_dtype=torch.float16,
                device_map="auto"
            )
            console.print("[green]AI模型加载成功[/green]")
        except Exception as e:
            console.print(f"[red]AI模型加载失败: {str(e)}[/red]")
            raise
    
    def predict_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """预测可能存在的漏洞"""
        try:
            # 构建提示
            prompt = self._build_vulnerability_prompt(scan_results)
            
            # 生成预测
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            outputs = self.model.generate(
                **inputs,
                max_length=1000,
                temperature=0.7,
                num_return_sequences=1
            )
            prediction = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # 解析预测结果
            vulnerabilities = self._parse_vulnerability_prediction(prediction)
            self.results['predictions'] = vulnerabilities
            
            return vulnerabilities
        except Exception as e:
            console.print(f"[red]漏洞预测失败: {str(e)}[/red]")
            return []
    
    def _build_vulnerability_prompt(self, scan_results: Dict[str, Any]) -> str:
        """构建漏洞预测提示"""
        prompt = "基于以下扫描结果，分析可能存在的漏洞：\n\n"
        
        # 添加端口扫描信息
        if 'port_scan' in scan_results:
            prompt += "开放端口和服务：\n"
            for host, data in scan_results['port_scan'].items():
                for proto in data.get('protocols', {}):
                    for port, info in data['protocols'][proto].items():
                        prompt += f"- 端口 {port}/{proto}: {info['service']} {info.get('version', '')}\n"
        
        # 添加Web扫描结果
        if 'web_scan' in scan_results:
            prompt += "\nWeb应用发现：\n"
            for finding in scan_results['web_scan']:
                prompt += f"- {finding}\n"
        
        prompt += "\n请分析上述信息，识别潜在的安全漏洞，包括：\n"
        prompt += "1. 常见漏洞（如CVE）\n"
        prompt += "2. 配置错误\n"
        prompt += "3. 过时的软件版本\n"
        prompt += "4. 不安全的服务\n"
        
        return prompt
    
    def _parse_vulnerability_prediction(self, prediction: str) -> List[Dict[str, Any]]:
        """解析模型预测结果"""
        vulnerabilities = []
        
        # 简单的文本分割处理
        for line in prediction.split('\n'):
            if line.strip():
                if 'CVE-' in line:
                    # CVE漏洞
                    vulnerabilities.append({
                        'type': 'cve',
                        'description': line.strip(),
                        'severity': self._estimate_severity(line)
                    })
                elif any(keyword in line.lower() for keyword in ['配置', '错误', 'misconfiguration']):
                    # 配置问题
                    vulnerabilities.append({
                        'type': 'misconfiguration',
                        'description': line.strip(),
                        'severity': 'medium'
                    })
                elif any(keyword in line.lower() for keyword in ['版本', 'version', 'outdated']):
                    # 版本问题
                    vulnerabilities.append({
                        'type': 'version',
                        'description': line.strip(),
                        'severity': 'low'
                    })
        
        return vulnerabilities
    
    def _estimate_severity(self, text: str) -> str:
        """估计漏洞严重性"""
        if any(keyword in text.lower() for keyword in ['严重', 'critical', 'rce', '远程代码']):
            return 'critical'
        elif any(keyword in text.lower() for keyword in ['高危', 'high']):
            return 'high'
        elif any(keyword in text.lower() for keyword in ['中危', 'medium']):
            return 'medium'
        else:
            return 'low'
    
    def generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """生成修复建议"""
        try:
            recommendations = {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            }
            
            for vuln in vulnerabilities:
                # 构建提示
                prompt = f"为以下安全问题生成修复建议：\n{vuln['description']}\n\n建议："
                
                # 生成建议
                inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
                outputs = self.model.generate(
                    **inputs,
                    max_length=200,
                    temperature=0.7,
                    num_return_sequences=1
                )
                recommendation = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
                
                # 添加到对应严重性级别
                severity = vuln.get('severity', 'medium')
                recommendations[severity].append({
                    'vulnerability': vuln['description'],
                    'recommendation': recommendation.strip()
                })
            
            self.results['recommendations'] = recommendations
            return recommendations
        except Exception as e:
            console.print(f"[red]生成修复建议失败: {str(e)}[/red]")
            return {}
    
    def export_to_csv(self, filepath: str) -> None:
        """导出分析结果为CSV格式"""
        try:
            # 创建数据框
            data = []
            
            # 添加预测的漏洞
            if 'predictions' in self.results:
                for vuln in self.results['predictions']:
                    row = {
                        'Type': vuln['type'],
                        'Description': vuln['description'],
                        'Severity': vuln['severity'],
                        'Recommendation': ''
                    }
                    
                    # 查找对应的建议
                    if 'recommendations' in self.results:
                        for rec in self.results['recommendations'][vuln['severity']]:
                            if rec['vulnerability'] == vuln['description']:
                                row['Recommendation'] = rec['recommendation']
                                break
                    
                    data.append(row)
            
            # 创建DataFrame并保存
            df = pd.DataFrame(data)
            df.to_csv(filepath, index=False, encoding='utf-8')
            console.print(f"[green]分析结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出CSV失败: {str(e)}[/red]")
    
    def export_results(self, filepath: str) -> None:
        """导出完整结果为JSON格式"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            console.print(f"[green]AI分析结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出结果失败: {str(e)}[/red]") 