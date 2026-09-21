from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
import joblib, numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from .utils import append_jsonl, risk_band, utc_now

log=logging.getLogger(__name__)
FEATURES=['bytes','duration_ms','failed_auth','suspicious_action','ti_score']
SUSPICIOUS={'login_failed','port_scan','dns_tunnel','sql_injection_probe','powershell_encoded_command'}

class MLDetector:
    def __init__(self,cfg:dict[str,Any]):
        self.cfg=cfg; self.dir=Path(cfg['ml']['model_dir']); self.dir.mkdir(exist_ok=True)
        self.iso_path=self.dir/'isolation_forest.joblib'; self.clf_path=self.dir/'supervised_classifier.joblib'
        self.iso=None; self.clf=None
        self._load_or_train()
    def _load_or_train(self):
        if self.iso_path.exists() and self.clf_path.exists() and not self.cfg['ml'].get('retrain',False): self.iso=joblib.load(self.iso_path); self.clf=joblib.load(self.clf_path); return
        rng=np.random.default_rng(self.cfg['ml']['random_state']); n=500
        X=np.column_stack([rng.normal(2500,1200,n).clip(0),rng.normal(350,180,n).clip(5),rng.binomial(1,.08,n),rng.binomial(1,.1,n),rng.beta(2,8,n)])
        y=((X[:,2]+X[:,3]+(X[:,4]>.65))>0).astype(int)
        self.iso=IsolationForest(contamination=self.cfg['ml']['contamination'],random_state=self.cfg['ml']['random_state']).fit(X)
        self.clf=RandomForestClassifier(n_estimators=120,random_state=self.cfg['ml']['random_state'],class_weight='balanced').fit(X,y)
        joblib.dump(self.iso,self.iso_path); joblib.dump(self.clf,self.clf_path)
    def vectorize(self,e:dict[str,Any])->list[float]:
        return [float(e.get('bytes',0)),float(e.get('duration_ms',0)),float(e.get('status')=='failure'),float(e.get('action') in SUSPICIOUS),float(e.get('ti_score',0))]
    def score(self,event:dict[str,Any])->dict[str,Any]:
        X=np.array([self.vectorize(event)]); raw=float(-self.iso.decision_function(X)[0]); anomaly=float(max(0,min(1,.5+raw)))
        supervised=float(self.clf.predict_proba(X)[0][1]); confidence=round(min(1, .55*anomaly+.45*supervised),3)
        return {**event,'features':dict(zip(FEATURES,self.vectorize(event))), 'anomaly_score':round(anomaly,3),'supervised_score':round(supervised,3),'confidence':confidence,'prediction':'threat' if confidence>=.55 else 'benign','alert_severity':risk_band(confidence),'detected_at':utc_now()}

def detect_events(events:list[dict[str,Any]],cfg:dict[str,Any],output:str)->list[dict[str,Any]]:
    d=MLDetector(cfg); rows=[]
    for e in events:
        row=d.score(e); append_jsonl(output,row); rows.append(row)
    return rows
