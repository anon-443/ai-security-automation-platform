from __future__ import annotations
import logging, uuid
from typing import Any
from .utils import append_jsonl, read_jsonl, utc_now
log=logging.getLogger(__name__)

class SOAREngine:
    def __init__(self,cfg:dict[str,Any]):
        self.cfg=cfg; self.auto=float(cfg['soar']['auto_execute_threshold']); self.review=float(cfg['soar']['analyst_review_threshold'])
    def create_case(self,alert:dict[str,Any], status:str, action:str)->dict[str,Any]:
        case={'case_id':'CASE-'+uuid.uuid4().hex[:10].upper(),'created_at':utc_now(),'status':status,'priority':alert.get('alert_severity','medium'),'action':action,'title':f"{alert.get('action','event')} from {alert.get('src_ip','unknown')}",'alert_id':alert.get('event_id'),'src_ip':alert.get('src_ip'),'confidence':alert.get('confidence',0),'analyst_notes':'','approval_required':status=='analyst_review'}
        append_jsonl(self.cfg['storage']['cases_file'],case); return case
    def process(self,alert:dict[str,Any])->dict[str,Any]:
        c=float(alert.get('confidence',0))
        if c>=self.auto: status,action='automated','create_case_and_isolation_recommendation'
        elif c>=self.review: status,action='analyst_review','create_analyst_queue_case'
        else: status,action='closed','no_action'
        case=self.create_case(alert,status,action)
        audit={'audit_id':uuid.uuid4().hex[:12],'timestamp':utc_now(),'event_id':alert.get('event_id'),'case_id':case['case_id'],'actor':'sentinelforge-policy-engine','decision':status,'action':action,'result':'simulated_success'}
        append_jsonl(self.cfg['storage']['audit_file'],audit)
        return {**alert,'soar_status':status,'case_id':case['case_id'],'playbook':action}

def run_soar(alerts:list[dict[str,Any]],cfg:dict[str,Any],output:str)->list[dict[str,Any]]:
    engine=SOAREngine(cfg); rows=[]
    for alert in alerts:
        row=engine.process(alert); append_jsonl(output,row); rows.append(row)
    return rows
