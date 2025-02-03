#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from dataclasses import dataclass
from datetime import datetime
from typing import List, Dict, Any
from rich.console import Console
import json

console = Console()

@dataclass
class Contact:
    name: str
    role: str
    email: str
    phone: str

@dataclass
class Scope:
    included_targets: List[str]
    excluded_targets: List[str]
    test_types: List[str]
    special_requirements: List[str]

@dataclass
class TimeFrame:
    start_date: datetime
    end_date: datetime
    blackout_periods: List[Dict[str, datetime]]

class PreEngagement:
    def __init__(self):
        self.project_info: Dict[str, Any] = {}
        self.contacts: List[Contact] = []
        self.scope: Scope = None
        self.timeframe: TimeFrame = None
        self.legal_docs: Dict[str, str] = {}
    
    def set_project_info(self, name: str, description: str, client: str) -> None:
        """设置项目基本信息"""
        self.project_info = {
            'name': name,
            'description': description,
            'client': client,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def add_contact(self, name: str, role: str, email: str, phone: str) -> None:
        """添加联系人"""
        contact = Contact(name=name, role=role, email=email, phone=phone)
        self.contacts.append(contact)
    
    def set_scope(self, included: List[str], excluded: List[str], 
                  test_types: List[str], requirements: List[str]) -> None:
        """设置测试范围"""
        self.scope = Scope(
            included_targets=included,
            excluded_targets=excluded,
            test_types=test_types,
            special_requirements=requirements
        )
    
    def set_timeframe(self, start: datetime, end: datetime, 
                     blackouts: List[Dict[str, datetime]]) -> None:
        """设置时间安排"""
        self.timeframe = TimeFrame(
            start_date=start,
            end_date=end,
            blackout_periods=blackouts
        )
    
    def add_legal_document(self, doc_type: str, content: str) -> None:
        """添加法律文档"""
        self.legal_docs[doc_type] = content
    
    def validate_setup(self) -> bool:
        """验证所有必要信息是否完整"""
        try:
            if not self.project_info:
                raise ValueError("缺少项目基本信息")
            
            if not self.contacts:
                raise ValueError("缺少联系人信息")
            
            if not self.scope:
                raise ValueError("缺少测试范围信息")
            
            if not self.timeframe:
                raise ValueError("缺少时间安排信息")
            
            if 'authorization' not in self.legal_docs:
                raise ValueError("缺少授权文档")
            
            return True
            
        except Exception as e:
            console.print(f"[red]前期准备验证失败: {str(e)}[/red]")
            return False
    
    def export_setup(self, filepath: str) -> None:
        """导出前期准备信息"""
        try:
            setup_data = {
                'project_info': self.project_info,
                'contacts': [vars(c) for c in self.contacts],
                'scope': vars(self.scope),
                'timeframe': {
                    'start_date': self.timeframe.start_date.isoformat(),
                    'end_date': self.timeframe.end_date.isoformat(),
                    'blackout_periods': self.timeframe.blackout_periods
                },
                'legal_docs': self.legal_docs
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(setup_data, f, indent=4, ensure_ascii=False)
            
            console.print(f"[green]前期准备信息已保存到: {filepath}[/green]")
            
        except Exception as e:
            console.print(f"[red]导出前期准备信息失败: {str(e)}[/red]")
    
    def generate_engagement_letter(self) -> str:
        """生成项目委托书"""
        try:
            letter = f"""
渗透测试项目委托书

项目信息:
- 项目名称: {self.project_info['name']}
- 客户名称: {self.project_info['client']}
- 项目描述: {self.project_info['description']}

测试范围:
- 目标系统: {', '.join(self.scope.included_targets)}
- 排除目标: {', '.join(self.scope.excluded_targets)}
- 测试类型: {', '.join(self.scope.test_types)}
- 特殊要求: {', '.join(self.scope.special_requirements)}

时间安排:
- 开始时间: {self.timeframe.start_date.strftime('%Y-%m-%d')}
- 结束时间: {self.timeframe.end_date.strftime('%Y-%m-%d')}

联系人信息:
"""
            for contact in self.contacts:
                letter += f"""
- 姓名: {contact.name}
  角色: {contact.role}
  邮箱: {contact.email}
  电话: {contact.phone}
"""
            
            return letter
            
        except Exception as e:
            console.print(f"[red]生成项目委托书失败: {str(e)}[/red]")
            return "" 