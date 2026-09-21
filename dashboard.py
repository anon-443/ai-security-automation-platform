from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import pandas as pd, streamlit as st
import plotly.express as px
from sentinelforge.utils import load_config, read_jsonl

st.set_page_config(page_title='SentinelForge SOC',page_icon='🛡️',layout='wide')
cfg=load_config(); s=cfg['storage']
alerts=pd.DataFrame(read_jsonl(s['alerts_file'])); cases=pd.DataFrame(read_jsonl(s['cases_file'])); events=pd.DataFrame(read_jsonl(s['events_file']))
soar=pd.DataFrame(read_jsonl(s['cases_file'].replace('cases','soar_results')))
if not alerts.empty and not soar.empty:
    response_cols=[c for c in ['event_id','soar_status','case_id','playbook'] if c in soar.columns]
    alerts=alerts.merge(soar[response_cols], on='event_id', how='left')
alerts['soar_status']=alerts.get('soar_status', pd.Series('not_processed', index=alerts.index)).fillna('not_processed')
alerts['case_id']=alerts.get('case_id', pd.Series('', index=alerts.index)).fillna('')
if alerts.empty:
    st.warning('No telemetry found. Run `python platform.py --mode full` first.'); st.stop()
for col in ['confidence','anomaly_score','supervised_score','ti_score']:
    if col in alerts: alerts[col]=pd.to_numeric(alerts[col],errors='coerce').fillna(0)

with st.sidebar:
    st.markdown('# 🛡️ SentinelForge')
    st.caption('AI Security Automation Platform')
    st.divider(); st.metric('Pipeline status','ONLINE'); st.caption('Offline-first demo profile')
    severity=st.multiselect('Severity filter',sorted(alerts['alert_severity'].unique()),default=sorted(alerts['alert_severity'].unique()))
    source=st.multiselect('Source filter',sorted(alerts['source'].unique()),default=sorted(alerts['source'].unique()))
view=alerts[alerts.alert_severity.isin(severity)&alerts.source.isin(source)]
st.title('Security Operations Command Center')
st.caption('Live-style telemetry view · Detection, intelligence, and response in one workflow')
cols=st.columns(5)
for c,label,value in zip(cols,['Events','Threat alerts','High confidence','Analyst queue','TI indicators'],[len(events),len(view),int((view.confidence>=.82).sum()),int((view.soar_status=='analyst_review').sum()),int(view.ti_score.gt(0).sum())]): c.metric(label,value)
left,right=st.columns([1.5,1])
with left:
    st.subheader('Alert timeline')
    timeline=view.copy(); timeline['timestamp']=pd.to_datetime(timeline.timestamp,errors='coerce'); timeline=timeline.sort_values('timestamp')
    fig=px.scatter(timeline,x='timestamp',y='confidence',color='alert_severity',size='ti_score',hover_data=['action','src_ip','soar_status'],color_discrete_map={'critical':'#ef4444','high':'#f97316','medium':'#eab308','low':'#22c55e'})
    fig.update_layout(height=350,margin=dict(l=10,r=10,t=10,b=10),paper_bgcolor='rgba(0,0,0,0)',plot_bgcolor='rgba(0,0,0,0)'); st.plotly_chart(fig,use_container_width=True)
with right:
    st.subheader('Detection mix')
    mix=view.groupby('alert_severity',as_index=False).size(); st.plotly_chart(px.pie(mix,names='alert_severity',values='size',hole=.55,color='alert_severity',color_discrete_map={'critical':'#ef4444','high':'#f97316','medium':'#eab308','low':'#22c55e'}),use_container_width=True)
left,right=st.columns(2)
with left:
    st.subheader('Threat origin / destination')
    geo=view.groupby('country',as_index=False).size().rename(columns={'size':'alerts'}); st.plotly_chart(px.bar(geo,x='country',y='alerts',color='alerts',color_continuous_scale='Reds'),use_container_width=True)
with right:
    st.subheader('SOAR playbook status')
    if 'soar_status' in view: st.plotly_chart(px.bar(view.groupby('soar_status',as_index=False).size(),x='soar_status',y='size',color='soar_status'),use_container_width=True)
st.subheader('Alert drill-down')
st.dataframe(view[['event_id','timestamp','action','src_ip','country','ti_band','ti_score','anomaly_score','supervised_score','confidence','alert_severity','soar_status','case_id']].sort_values('confidence',ascending=False),use_container_width=True,hide_index=True)
with st.expander('Selected alert evidence'):
    selected=st.selectbox('Choose event',view.event_id.tolist()); row=view[view.event_id==selected].iloc[0].to_dict(); st.json(row)
st.subheader('Analyst queue')
queue=view[view.soar_status=='analyst_review']
if queue.empty: st.success('No alerts awaiting analyst approval.')
else: st.dataframe(queue[['case_id','action','src_ip','confidence','alert_severity','playbook']],use_container_width=True,hide_index=True)
