#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from typing import Dict, Any, List
from rich.console import Console
from dataclasses import dataclass
from enum import Enum

console = Console()

class AssetType(Enum):
    WEB_SERVER = "web_server"
    DATABASE = "database"
    FILE_SERVER = "file_server"
    MAIL_SERVER = "mail_server"
    DOMAIN_CONTROLLER = "domain_controller"
    NETWORK_DEVICE = "network_device"

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Asset:
    name: str
    type: AssetType
    value: int  # 1-10
    exposed: bool
    services: List[str]
    description: str

@dataclass
class Threat:
    name: str
    level: ThreatLevel
    likelihood: int  # 1-10
    impact: int     # 1-10
    description: str
    affected_assets: List[str]
    attack_vectors: List[str]

class ThreatModeling:
    def __init__(self):
        self.results: Dict[str, Any] = {}
        self.assets: List[Asset] = []
        self.threats: List[Threat] = []
    
    def analyze_assets(self, scan_results: Dict[str, Any]) -> List[Asset]:
        """分析目标系统资产"""
        try:
            # 从端口扫描结果分析资产
            if 'port_scan' in scan_results:
                for host, data in scan_results['port_scan'].items():
                    for proto in data.get('protocols', {}):
                        for port, info in data['protocols'][proto].items():
                            # 识别Web服务器
                            if info['service'] in ['http', 'https']:
                                self.assets.append(Asset(
                                    name=f"Web Server ({host}:{port})",
                                    type=AssetType.WEB_SERVER,
                                    value=8,
                                    exposed=True,
                                    services=[info['service']],
                                    description=f"Web服务器 运行 {info.get('product', '')} {info.get('version', '')}"
                                ))
                            
                            # 识别数据库服务器
                            elif info['service'] in ['mysql', 'mssql', 'postgresql', 'mongodb']:
                                self.assets.append(Asset(
                                    name=f"Database Server ({host}:{port})",
                                    type=AssetType.DATABASE,
                                    value=9,
                                    exposed=True,
                                    services=[info['service']],
                                    description=f"数据库服务器 运行 {info.get('product', '')} {info.get('version', '')}"
                                ))
                            
                            # 识别域控制器
                            elif port == 389 or info['service'] in ['ldap', 'kerberos']:
                                self.assets.append(Asset(
                                    name=f"Domain Controller ({host})",
                                    type=AssetType.DOMAIN_CONTROLLER,
                                    value=10,
                                    exposed=True,
                                    services=[info['service']],
                                    description="域控制器"
                                ))
            
            self.results['assets'] = [self._asset_to_dict(asset) for asset in self.assets]
            return self.assets
            
        except Exception as e:
            console.print(f"[red]资产分析失败: {str(e)}[/red]")
            return []
    
    def identify_threats(self, scan_results: Dict[str, Any]) -> List[Threat]:
        """识别潜在威胁"""
        try:
            # 分析漏洞扫描结果
            if 'vuln_scan' in scan_results:
                for service_type, results in scan_results['vuln_scan'].items():
                    if isinstance(results, dict):
                        for tool, findings in results.items():
                            if findings.get('vulnerable', False):
                                # 创建威胁对象
                                threat = Threat(
                                    name=f"Vulnerability in {service_type}",
                                    level=self._determine_threat_level(findings),
                                    likelihood=self._calculate_likelihood(findings),
                                    impact=self._calculate_impact(findings),
                                    description=findings.get('details', '未知漏洞'),
                                    affected_assets=[asset.name for asset in self.assets if service_type in asset.services],
                                    attack_vectors=self._identify_attack_vectors(findings)
                                )
                                self.threats.append(threat)
            
            # 分析WAF检测结果
            if 'waf_bypass' in scan_results:
                waf_info = scan_results['waf_bypass'].get('waf_info', {})
                if waf_info.get('detected', False):
                    threat = Threat(
                        name="WAF Bypass Potential",
                        level=ThreatLevel.HIGH,
                        likelihood=7,
                        impact=8,
                        description="检测到WAF可能被绕过",
                        affected_assets=[asset.name for asset in self.assets if asset.type == AssetType.WEB_SERVER],
                        attack_vectors=["WAF绕过", "注入攻击"]
                    )
                    self.threats.append(threat)
            
            self.results['threats'] = [self._threat_to_dict(threat) for threat in self.threats]
            return self.threats
            
        except Exception as e:
            console.print(f"[red]威胁识别失败: {str(e)}[/red]")
            return []
    
    def calculate_risk_scores(self) -> Dict[str, float]:
        """计算风险评分"""
        try:
            risk_scores = {}
            
            for asset in self.assets:
                # 基础风险分数
                base_score = asset.value * 10  # 0-100
                
                # 受影响的威胁数量
                affecting_threats = [
                    threat for threat in self.threats
                    if asset.name in threat.affected_assets
                ]
                
                # 威胁加权
                threat_score = sum(
                    threat.likelihood * threat.impact
                    for threat in affecting_threats
                ) if affecting_threats else 0
                
                # 暴露程度调整
                exposure_multiplier = 1.5 if asset.exposed else 1.0
                
                # 最终风险分数
                final_score = (base_score + threat_score) * exposure_multiplier
                
                risk_scores[asset.name] = min(100, final_score)  # 上限100
            
            self.results['risk_scores'] = risk_scores
            return risk_scores
            
        except Exception as e:
            console.print(f"[red]风险评分计算失败: {str(e)}[/red]")
            return {}
    
    def generate_attack_surface_report(self) -> Dict[str, Any]:
        """生成攻击面分析报告"""
        try:
            report = {
                'exposed_services': [],
                'critical_assets': [],
                'high_risk_threats': [],
                'attack_vectors': set(),
                'mitigation_suggestions': []
            }
            
            # 分析暴露的服务
            for asset in self.assets:
                if asset.exposed:
                    report['exposed_services'].extend(asset.services)
            
            # 识别关键资产
            for asset in self.assets:
                if asset.value >= 8:
                    report['critical_assets'].append({
                        'name': asset.name,
                        'type': asset.type.value,
                        'description': asset.description
                    })
            
            # 高风险威胁
            for threat in self.threats:
                if threat.level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                    report['high_risk_threats'].append({
                        'name': threat.name,
                        'level': threat.level.value,
                        'description': threat.description
                    })
                    report['attack_vectors'].update(threat.attack_vectors)
            
            # 生成缓解建议
            report['mitigation_suggestions'] = self._generate_mitigation_suggestions(
                report['exposed_services'],
                report['attack_vectors']
            )
            
            self.results['attack_surface'] = report
            return report
            
        except Exception as e:
            console.print(f"[red]攻击面分析失败: {str(e)}[/red]")
            return {}
    
    def _determine_threat_level(self, finding: Dict[str, Any]) -> ThreatLevel:
        """确定威胁等级"""
        if 'severity' in finding:
            severity = finding['severity'].lower()
            if severity == 'critical':
                return ThreatLevel.CRITICAL
            elif severity == 'high':
                return ThreatLevel.HIGH
            elif severity == 'medium':
                return ThreatLevel.MEDIUM
            else:
                return ThreatLevel.LOW
        return ThreatLevel.MEDIUM
    
    def _calculate_likelihood(self, finding: Dict[str, Any]) -> int:
        """计算威胁发生的可能性"""
        base_score = 5
        
        # 根据漏洞类型调整
        if 'type' in finding:
            if finding['type'] in ['rce', 'sqli', 'upload']:
                base_score += 3
            elif finding['type'] in ['xss', 'csrf']:
                base_score += 2
        
        # 根据难度调整
        if 'difficulty' in finding:
            if finding['difficulty'] == 'easy':
                base_score += 2
            elif finding['difficulty'] == 'hard':
                base_score -= 2
        
        return max(1, min(10, base_score))
    
    def _calculate_impact(self, finding: Dict[str, Any]) -> int:
        """计算威胁影响"""
        base_score = 5
        
        # 根据影响范围调整
        if 'impact' in finding:
            impact = finding['impact'].lower()
            if 'system' in impact or 'root' in impact:
                base_score += 4
            elif 'data' in impact or 'confidential' in impact:
                base_score += 3
            elif 'user' in impact:
                base_score += 2
        
        return max(1, min(10, base_score))
    
    def _identify_attack_vectors(self, finding: Dict[str, Any]) -> List[str]:
        """识别攻击向量"""
        vectors = []
        
        if 'type' in finding:
            if finding['type'] == 'rce':
                vectors.extend(['命令注入', '远程代码执行'])
            elif finding['type'] == 'sqli':
                vectors.extend(['SQL注入', '数据库攻击'])
            elif finding['type'] == 'xss':
                vectors.extend(['跨站脚本', '客户端攻击'])
        
        if 'method' in finding:
            vectors.append(finding['method'])
        
        return list(set(vectors))
    
    def _generate_mitigation_suggestions(self, exposed_services: List[str], attack_vectors: set) -> List[str]:
        """生成缓解建议"""
        suggestions = []
        
        # 基于暴露服务的建议
        for service in exposed_services:
            if service in ['http', 'https']:
                suggestions.extend([
                    "实施Web应用防火墙(WAF)",
                    "启用HTTPS并配置安全headers",
                    "实施输入验证和输出编码"
                ])
            elif service in ['mysql', 'mssql', 'postgresql']:
                suggestions.extend([
                    "限制数据库服务器访问",
                    "实施强密码策略",
                    "定期备份数据库"
                ])
        
        # 基于攻击向量的建议
        for vector in attack_vectors:
            if '注入' in vector:
                suggestions.extend([
                    "使用参数化查询",
                    "实施输入验证",
                    "最小权限原则"
                ])
            elif '跨站' in vector:
                suggestions.extend([
                    "实施CSP策略",
                    "使用安全的Cookie标志",
                    "输入验证和输出编码"
                ])
        
        return list(set(suggestions))
    
    def _asset_to_dict(self, asset: Asset) -> Dict[str, Any]:
        """将Asset对象转换为字典"""
        return {
            'name': asset.name,
            'type': asset.type.value,
            'value': asset.value,
            'exposed': asset.exposed,
            'services': asset.services,
            'description': asset.description
        }
    
    def _threat_to_dict(self, threat: Threat) -> Dict[str, Any]:
        """将Threat对象转换为字典"""
        return {
            'name': threat.name,
            'level': threat.level.value,
            'likelihood': threat.likelihood,
            'impact': threat.impact,
            'description': threat.description,
            'affected_assets': threat.affected_assets,
            'attack_vectors': threat.attack_vectors
        }
    
    def export_results(self, filepath: str) -> None:
        """导出威胁建模结果"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            console.print(f"[green]威胁建模结果已保存到: {filepath}[/green]")
        except Exception as e:
            console.print(f"[red]导出结果失败: {str(e)}[/red]") 