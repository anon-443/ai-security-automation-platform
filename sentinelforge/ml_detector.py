from __future__ import annotations
import logging, warnings
from pathlib import Path
from typing import Any
import joblib, numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.exceptions import InconsistentVersionWarning
from .utils import append_jsonl, risk_band, utc_now

log=logging.getLogger(__name__)
FEATURES=['dur','spkts','dpkts','sbytes','dbytes','rate']
SUSPICIOUS={'login_failed','port_scan','dns_tunnel','sql_injection_probe','powershell_encoded_command'}

class MLDetector:
    def __init__(self,cfg:dict[str,Any]):
        self.cfg=cfg; self.dir=Path(cfg['ml']['model_dir']); self.dir.mkdir(exist_ok=True)
        self.iso_path=self.dir/'isolation_forest.joblib'; self.clf_path=self.dir/'supervised_classifier.joblib'
        self.week5_dir=Path(cfg['ml'].get('week5_model_dir', self.dir/'week5'))
        self.week5_iso_path=self.week5_dir/'isolation_forest_model.pkl'; self.week5_scaler_path=self.week5_dir/'standard_scaler.pkl'
        self.iso=None; self.scaler=None; self.clf=None; self.model_source='synthetic-fallback'
        self._load_or_train()
    def _load_or_train(self):
        if self.week5_iso_path.exists() and self.week5_scaler_path.exists():
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', InconsistentVersionWarning)
                self.iso=joblib.load(self.week5_iso_path); self.scaler=joblib.load(self.week5_scaler_path)
            self.model_source='week5-pretrained-isolation-forest'
        elif self.iso_path.exists() and self.clf_path.exists() and not self.cfg['ml'].get('retrain',False):
            self.iso=joblib.load(self.iso_path); self.clf=joblib.load(self.clf_path)
        else:
            rng=np.random.default_rng(self.cfg['ml']['random_state']); n=500
            X=np.column_stack([rng.lognormal(1.0,1.0,n),rng.normal(55,30,n).clip(1),rng.normal(12,5,n).clip(1),rng.lognormal(12,1.5,n),rng.lognormal(9,1.0,n),rng.lognormal(5,1.2,n)])
            y=((X[:,1]>120)+(X[:,3]>5e6)+(X[:,5]>500))>0
            self.iso=IsolationForest(contamination=self.cfg['ml']['contamination'],random_state=self.cfg['ml']['random_state']).fit(X)
            joblib.dump(self.iso,self.iso_path)
        if self.clf is None:
            rng=np.random.default_rng(self.cfg['ml']['random_state']); n=700
            X=np.column_stack([rng.lognormal(1.0,1.0,n),rng.normal(55,30,n).clip(1),rng.normal(12,5,n).clip(1),rng.lognormal(12,1.5,n),rng.lognormal(9,1.0,n),rng.lognormal(5,1.2,n)])
            y=((X[:,1]>120)+(X[:,3]>5e6)+(X[:,5]>500))>0
            self.clf=RandomForestClassifier(n_estimators=120,random_state=self.cfg['ml']['random_state'],class_weight='balanced').fit(X,y)
            joblib.dump(self.clf,self.clf_path)
    def vectorize(self,e:dict[str,Any])->list[float]:
        duration=max(float(e.get('duration_ms',0))/1000.0, 0.001); total_bytes=max(float(e.get('bytes',0)), 1.0); suspicious=float(e.get('action') in SUSPICIOUS)
        return [duration, max(1.0,total_bytes/1200.0 + suspicious*8), max(1.0,total_bytes/1500.0), total_bytes*(1.0+suspicious), total_bytes*.2, total_bytes/duration]
    def score(self,event:dict[str,Any])->dict[str,Any]:
        raw_X=np.array([self.vectorize(event)])
        if self.scaler is not None and hasattr(self.scaler, 'feature_names_in_'):
            import pandas as pd
            X=self.scaler.transform(pd.DataFrame(raw_X, columns=list(self.scaler.feature_names_in_)))
        else:
            X=self.scaler.transform(raw_X) if self.scaler is not None else raw_X
        raw=float(-self.iso.decision_function(X)[0]); anomaly=float(max(0,min(1,.5+raw)))
        supervised=float(self.clf.predict_proba(X)[0][1]); confidence=round(min(1, .55*anomaly+.45*supervised),3)
        return {**event,'features':dict(zip(FEATURES,self.vectorize(event))), 'model_source':self.model_source, 'anomaly_score':round(anomaly,3),'supervised_score':round(supervised,3),'confidence':confidence,'prediction':'threat' if confidence>=.55 else 'benign','alert_severity':risk_band(confidence),'detected_at':utc_now()}

def detect_events(events:list[dict[str,Any]],cfg:dict[str,Any],output:str)->list[dict[str,Any]]:
    d=MLDetector(cfg); rows=[]
    for e in events:
        row=d.score(e); append_jsonl(output,row); rows.append(row)
    return rows
