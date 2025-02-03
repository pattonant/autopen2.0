#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from datetime import datetime
from typing import Dict, Any, List
from rich.console import Console
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, ListFlowable, ListItem
)

console = Console()

class ReportGenerator:
    def __init__(self, target: str, scan_results: Dict[str, Any]):
        self.target = target
        self.scan_results = scan_results
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.styles = getSampleStyleSheet()
        
        # 创建自定义样式
        self.styles.add(ParagraphStyle(
            'VulnTitle',
            parent=self.styles['Heading2'],
            textColor=colors.red,
            spaceAfter=12
        ))
        
        self.styles.add(ParagraphStyle(
            'RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=12
        ))
        
        self.styles.add(ParagraphStyle(
            'RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=12
        ))
        
        self.styles.add(ParagraphStyle(
            'RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontSize=12
        ))
    
    def generate_html(self, output_path: str) -> None:
        """生成HTML格式报告"""
        try:
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>渗透测试报告 - {self.target}</title>
                <meta charset="utf-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .header {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
                    .section {{ margin: 20px 0; }}
                    .vulnerability {{ 
                        border-left: 4px solid #ff4444;
                        padding: 10px;
                        margin: 10px 0;
                        background: #fff5f5;
                    }}
                    .critical {{ color: #ff0000; }}
                    .high {{ color: #ff4444; }}
                    .medium {{ color: #ffa500; }}
                    .low {{ color: #00aa00; }}
                    .info {{ color: #666; }}
                    table {{ 
                        width: 100%;
                        border-collapse: collapse;
                        margin: 10px 0;
                    }}
                    th, td {{
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }}
                    th {{ background: #f5f5f5; }}
                    .risk-matrix {{
                        margin: 20px 0;
                        padding: 10px;
                        border: 1px solid #ddd;
                    }}
                    .recommendations {{
                        background: #f8f8f8;
                        padding: 15px;
                        border-radius: 5px;
                    }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>渗透测试报告</h1>
                    <p><strong>目标:</strong> {self.target}</p>
                    <p><strong>测试时间:</strong> {self.timestamp}</p>
                </div>
                
                <div class="section">
                    <h2>1. 执行摘要</h2>
                    {self._format_executive_summary_html()}
                </div>
                
                <div class="section">
                    <h2>2. 测试范围</h2>
                    {self._format_scope_html()}
                </div>
                
                <div class="section">
                    <h2>3. 风险评估</h2>
                    {self._format_risk_assessment_html()}
                </div>
                
                <div class="section">
                    <h2>4. 发现的漏洞</h2>
                    {self._format_vulnerabilities_html()}
                </div>
                
                <div class="section">
                    <h2>5. 攻击面分析</h2>
                    {self._format_attack_surface_html()}
                </div>
                
                <div class="section">
                    <h2>6. 修复建议</h2>
                    {self._format_recommendations_html()}
                </div>
                
                <div class="section">
                    <h2>7. 技术细节</h2>
                    {self._format_technical_details_html()}
                </div>
            </body>
            </html>
            """
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            console.print(f"[green]HTML报告已生成: {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]HTML报告生成失败: {str(e)}[/red]")
    
    def generate_pdf(self, output_path: str) -> None:
        """生成PDF格式报告"""
        try:
            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            story = []
            
            # 封面
            self._add_cover_page(story)
            
            # 目录
            self._add_table_of_contents(story)
            
            # 执行摘要
            self._add_executive_summary(story)
            
            # 测试范围
            self._add_scope(story)
            
            # 风险评估
            self._add_risk_assessment(story)
            
            # 漏洞发现
            self._add_vulnerabilities(story)
            
            # 攻击面分析
            self._add_attack_surface(story)
            
            # 修复建议
            self._add_recommendations(story)
            
            # 技术细节
            self._add_technical_details(story)
            
            # 附录
            self._add_appendices(story)
            
            doc.build(story)
            console.print(f"[green]PDF报告已生成: {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]PDF报告生成失败: {str(e)}[/red]")
    
    def _format_executive_summary_html(self) -> str:
        """格式化执行摘要为HTML"""
        summary = "<div class='executive-summary'>"
        
        # 关键发现
        if 'vuln_scan' in self.scan_results:
            vuln_count = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            for service_type, results in self.scan_results['vuln_scan'].items():
                if isinstance(results, dict):
                    for tool, findings in results.items():
                        if findings.get('vulnerable', False):
                            severity = findings.get('severity', 'medium').lower()
                            vuln_count[severity] += 1
            
            summary += "<h3>关键发现</h3>"
            summary += "<ul>"
            summary += f"<li class='critical'>发现 {vuln_count['critical']} 个严重漏洞</li>"
            summary += f"<li class='high'>发现 {vuln_count['high']} 个高危漏洞</li>"
            summary += f"<li class='medium'>发现 {vuln_count['medium']} 个中危漏洞</li>"
            summary += f"<li class='low'>发现 {vuln_count['low']} 个低危漏洞</li>"
            summary += "</ul>"
        
        # 整体风险评估
        if 'risk_scores' in self.scan_results:
            total_score = sum(self.scan_results['risk_scores'].values()) / len(self.scan_results['risk_scores'])
            risk_level = "高危" if total_score >= 75 else "中危" if total_score >= 50 else "低危"
            summary += f"<h3>整体风险评估</h3>"
            summary += f"<p>目标系统的整体风险等级为 <span class='{risk_level.lower()}'>{risk_level}</span></p>"
        
        summary += "</div>"
        return summary
    
    def _format_scope_html(self) -> str:
        """格式化测试范围为HTML"""
        scope = "<div class='scope'>"
        
        # 目标信息
        scope += "<h3>测试目标</h3>"
        scope += f"<p>目标系统: {self.target}</p>"
        
        # 测试的服务
        if 'port_scan' in self.scan_results:
            scope += "<h3>测试的服务</h3>"
            scope += "<ul>"
            for host, data in self.scan_results['port_scan'].items():
                for proto in data.get('protocols', {}):
                    for port, info in data['protocols'][proto].items():
                        scope += f"<li>{info['service']} ({port}/{proto})</li>"
            scope += "</ul>"
        
        scope += "</div>"
        return scope
    
    def _format_risk_assessment_html(self) -> str:
        """格式化风险评估为HTML"""
        risk = "<div class='risk-assessment'>"
        
        # 风险矩阵
        if 'threats' in self.scan_results:
            risk += "<div class='risk-matrix'>"
            risk += "<h3>风险矩阵</h3>"
            risk += "<table>"
            risk += "<tr><th>威胁</th><th>可能性</th><th>影响</th><th>风险等级</th></tr>"
            
            for threat in self.scan_results['threats']:
                likelihood = threat['likelihood']
                impact = threat['impact']
                level = threat['level']
                
                risk += f"""
                <tr>
                    <td>{threat['name']}</td>
                    <td>{likelihood}/10</td>
                    <td>{impact}/10</td>
                    <td class='{level.lower()}'>{level}</td>
                </tr>
                """
            
            risk += "</table>"
            risk += "</div>"
        
        risk += "</div>"
        return risk
    
    def _format_vulnerabilities_html(self) -> str:
        """格式化漏洞发现为HTML"""
        vulns = "<div class='vulnerabilities'>"
        
        if 'vuln_scan' in self.scan_results:
            for service_type, results in self.scan_results['vuln_scan'].items():
                if isinstance(results, dict):
                    for tool, findings in results.items():
                        if findings.get('vulnerable', False):
                            severity = findings.get('severity', 'medium').lower()
                            vulns += f"""
                            <div class='vulnerability'>
                                <h3 class='{severity}'>{findings.get('name', '未命名漏洞')}</h3>
                                <p><strong>影响服务:</strong> {service_type}</p>
                                <p><strong>风险等级:</strong> <span class='{severity}'>{severity.upper()}</span></p>
                                <p><strong>描述:</strong> {findings.get('description', '无描述')}</p>
                                <p><strong>影响:</strong> {findings.get('impact', '未知')}</p>
                                <p><strong>修复建议:</strong> {findings.get('recommendation', '无建议')}</p>
                            </div>
                            """
        
        vulns += "</div>"
        return vulns
    
    def _format_attack_surface_html(self) -> str:
        """格式化攻击面分析为HTML"""
        attack = "<div class='attack-surface'>"
        
        if 'attack_surface' in self.scan_results:
            surface = self.scan_results['attack_surface']
            
            # 暴露的服务
            attack += "<h3>暴露的服务</h3>"
            attack += "<ul>"
            for service in surface.get('exposed_services', []):
                attack += f"<li>{service}</li>"
            attack += "</ul>"
            
            # 攻击向量
            attack += "<h3>可能的攻击向量</h3>"
            attack += "<ul>"
            for vector in surface.get('attack_vectors', []):
                attack += f"<li>{vector}</li>"
            attack += "</ul>"
        
        attack += "</div>"
        return attack
    
    def _format_recommendations_html(self) -> str:
        """格式化修复建议为HTML"""
        recs = "<div class='recommendations'>"
        
        if 'recommendations' in self.scan_results:
            for severity, items in self.scan_results['recommendations'].items():
                recs += f"<h3 class='{severity.lower()}'>{severity.upper()}级别建议</h3>"
                recs += "<ul>"
                for item in items:
                    recs += f"<li>{item['recommendation']}</li>"
                recs += "</ul>"
        
        recs += "</div>"
        return recs
    
    def _format_technical_details_html(self) -> str:
        """格式化技术细节为HTML"""
        tech = "<div class='technical-details'>"
        
        # 端口扫描结果
        if 'port_scan' in self.scan_results:
            tech += "<h3>端口扫描详情</h3>"
            tech += "<table>"
            tech += "<tr><th>主机</th><th>端口</th><th>服务</th><th>版本</th></tr>"
            
            for host, data in self.scan_results['port_scan'].items():
                for proto in data.get('protocols', {}):
                    for port, info in data['protocols'][proto].items():
                        tech += f"""
                        <tr>
                            <td>{host}</td>
                            <td>{port}/{proto}</td>
                            <td>{info['service']}</td>
                            <td>{info.get('version', 'unknown')}</td>
                        </tr>
                        """
            
            tech += "</table>"
        
        tech += "</div>"
        return tech
    
    def _add_cover_page(self, story: list) -> None:
        """添加封面"""
        # 标题
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1  # 居中
        )
        story.append(Paragraph("渗透测试报告", title_style))
        story.append(Spacer(1, 60))
        
        # 目标信息
        story.append(Paragraph(f"测试目标: {self.target}", self.styles['Normal']))
        story.append(Paragraph(f"报告时间: {self.timestamp}", self.styles['Normal']))
        story.append(PageBreak())
    
    def _add_table_of_contents(self, story: list) -> None:
        """添加目录"""
        story.append(Paragraph("目录", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        toc_items = [
            "1. 执行摘要",
            "2. 测试范围",
            "3. 风险评估",
            "4. 发现的漏洞",
            "5. 攻击面分析",
            "6. 修复建议",
            "7. 技术细节",
            "8. 附录"
        ]
        
        for item in toc_items:
            story.append(Paragraph(item, self.styles['Normal']))
            story.append(Spacer(1, 6))
        
        story.append(PageBreak())
    
    def _add_executive_summary(self, story: list) -> None:
        """添加执行摘要"""
        story.append(Paragraph("1. 执行摘要", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # 添加关键发现统计
        if 'vuln_scan' in self.scan_results:
            vuln_count = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            for service_type, results in self.scan_results['vuln_scan'].items():
                if isinstance(results, dict):
                    for tool, findings in results.items():
                        if findings.get('vulnerable', False):
                            severity = findings.get('severity', 'medium').lower()
                            vuln_count[severity] += 1
            
            story.append(Paragraph("关键发现", self.styles['Heading2']))
            story.append(Spacer(1, 6))
            
            findings = [
                [Paragraph("风险等级", self.styles['Heading2']), Paragraph("数量", self.styles['Heading2'])],
                [Paragraph("严重", self.styles['RiskHigh']), Paragraph(str(vuln_count['critical']), self.styles['Normal'])],
                [Paragraph("高危", self.styles['RiskHigh']), Paragraph(str(vuln_count['high']), self.styles['Normal'])],
                [Paragraph("中危", self.styles['RiskMedium']), Paragraph(str(vuln_count['medium']), self.styles['Normal'])],
                [Paragraph("低危", self.styles['RiskLow']), Paragraph(str(vuln_count['low']), self.styles['Normal'])]
            ]
            
            t = Table(findings, colWidths=[2*inch, inch])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,0), (-1,0), colors.grey)
            ]))
            story.append(t)
        
        story.append(PageBreak())
    
    def _add_scope(self, story: list) -> None:
        """添加测试范围"""
        story.append(Paragraph("2. 测试范围", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # 目标信息
        story.append(Paragraph("测试目标", self.styles['Heading2']))
        story.append(Paragraph(f"目标系统: {self.target}", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # 测试的服务
        if 'port_scan' in self.scan_results:
            story.append(Paragraph("测试的服务", self.styles['Heading2']))
            services = []
            for host, data in self.scan_results['port_scan'].items():
                for proto in data.get('protocols', {}):
                    for port, info in data['protocols'][proto].items():
                        services.append(
                            Paragraph(f"• {info['service']} ({port}/{proto})", self.styles['Normal'])
                        )
            
            for service in services:
                story.append(service)
        
        story.append(PageBreak())
    
    def _add_risk_assessment(self, story: list) -> None:
        """添加风险评估"""
        story.append(Paragraph("3. 风险评估", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if 'threats' in self.scan_results:
            # 风险矩阵
            story.append(Paragraph("风险矩阵", self.styles['Heading2']))
            story.append(Spacer(1, 6))
            
            matrix_data = [['威胁', '可能性', '影响', '风险等级']]
            for threat in self.scan_results['threats']:
                matrix_data.append([
                    threat['name'],
                    f"{threat['likelihood']}/10",
                    f"{threat['impact']}/10",
                    threat['level']
                ])
            
            t = Table(matrix_data, colWidths=[2.5*inch, inch, inch, 1.5*inch])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,0), (-1,0), colors.grey)
            ]))
            story.append(t)
        
        story.append(PageBreak())
    
    def _add_vulnerabilities(self, story: list) -> None:
        """添加漏洞发现"""
        story.append(Paragraph("4. 发现的漏洞", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if 'vuln_scan' in self.scan_results:
            for service_type, results in self.scan_results['vuln_scan'].items():
                if isinstance(results, dict):
                    for tool, findings in results.items():
                        if findings.get('vulnerable', False):
                            # 漏洞标题
                            story.append(Paragraph(
                                findings.get('name', '未命名漏洞'),
                                self.styles['VulnTitle']
                            ))
                            
                            # 漏洞详情
                            details = [
                                ['属性', '描述'],
                                ['影响服务', service_type],
                                ['风险等级', findings.get('severity', 'MEDIUM')],
                                ['描述', findings.get('description', '无描述')],
                                ['影响', findings.get('impact', '未知')],
                                ['修复建议', findings.get('recommendation', '无建议')]
                            ]
                            
                            t = Table(details, colWidths=[1.5*inch, 4.5*inch])
                            t.setStyle(TableStyle([
                                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                                ('GRID', (0,0), (-1,-1), 1, colors.black),
                                ('BACKGROUND', (0,0), (-1,0), colors.grey)
                            ]))
                            story.append(t)
                            story.append(Spacer(1, 12))
        
        story.append(PageBreak())
    
    def _add_attack_surface(self, story: list) -> None:
        """添加攻击面分析"""
        story.append(Paragraph("5. 攻击面分析", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if 'attack_surface' in self.scan_results:
            surface = self.scan_results['attack_surface']
            
            # 暴露的服务
            story.append(Paragraph("暴露的服务", self.styles['Heading2']))
            for service in surface.get('exposed_services', []):
                story.append(Paragraph(f"• {service}", self.styles['Normal']))
            story.append(Spacer(1, 12))
            
            # 攻击向量
            story.append(Paragraph("可能的攻击向量", self.styles['Heading2']))
            for vector in surface.get('attack_vectors', []):
                story.append(Paragraph(f"• {vector}", self.styles['Normal']))
        
        story.append(PageBreak())
    
    def _add_recommendations(self, story: list) -> None:
        """添加修复建议"""
        story.append(Paragraph("6. 修复建议", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        if 'recommendations' in self.scan_results:
            for severity, items in self.scan_results['recommendations'].items():
                story.append(Paragraph(
                    f"{severity.upper()}级别建议",
                    self.styles[f'Risk{severity.capitalize()}']
                ))
                story.append(Spacer(1, 6))
                
                for item in items:
                    story.append(Paragraph(f"• {item['recommendation']}", self.styles['Normal']))
                    story.append(Spacer(1, 3))
        
        story.append(PageBreak())
    
    def _add_technical_details(self, story: list) -> None:
        """添加技术细节"""
        story.append(Paragraph("7. 技术细节", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # 端口扫描结果
        if 'port_scan' in self.scan_results:
            story.append(Paragraph("端口扫描详情", self.styles['Heading2']))
            story.append(Spacer(1, 6))
            
            scan_data = [['主机', '端口', '服务', '版本']]
            for host, data in self.scan_results['port_scan'].items():
                for proto in data.get('protocols', {}):
                    for port, info in data['protocols'][proto].items():
                        scan_data.append([
                            host,
                            f"{port}/{proto}",
                            info['service'],
                            info.get('version', 'unknown')
                        ])
            
            t = Table(scan_data, colWidths=[2*inch, inch, 1.5*inch, 2*inch])
            t.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('GRID', (0,0), (-1,-1), 1, colors.black),
                ('BACKGROUND', (0,0), (-1,0), colors.grey)
            ]))
            story.append(t)
        
        story.append(PageBreak())
    
    def _add_appendices(self, story: list) -> None:
        """添加附录"""
        story.append(Paragraph("8. 附录", self.styles['Heading1']))
        story.append(Spacer(1, 12))
        
        # 工具列表
        story.append(Paragraph("使用的工具", self.styles['Heading2']))
        tools = [
            "nmap - 网络扫描",
            "nikto - Web漏洞扫描",
            "sqlmap - SQL注入检测",
            "metasploit - 漏洞利用框架",
            "mimikatz - 凭据提取",
            "bloodhound - 域环境分析"
        ]
        
        for tool in tools:
            story.append(Paragraph(f"• {tool}", self.styles['Normal']))
            story.append(Spacer(1, 3))
        
        story.append(PageBreak()) 