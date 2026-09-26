#!/usr/bin/env python3
"""Generate all paper figures — production version with Type 42 fonts."""
import json, csv, os, sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib as mpl
mpl.rcParams["pdf.fonttype"] = 42  # Type 42 fonts (TrueType)
mpl.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
from scipy.special import expit
from scipy.stats import spearmanr

from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = str(ROOT / "data")
FIG_DIR = str(ROOT / "figures")
os.makedirs(FIG_DIR, exist_ok=True)
np.random.seed(42)

# Figure titles quote the manuscript-run statistics recorded in outputs/results.json
# (read at run time instead of hard-coding them here).
with open(ROOT / "outputs" / "results.json") as f:
    RESULTS = json.load(f)
try:
    RHO_THETA_TEMPORAL = float(RESULTS["temporal"]["rho_theta"])
    RHO_B_TEMPORAL = float(RESULTS["temporal"]["rho_b"])
    RANSOMWARE_MW_P = RESULTS["ransomware"]["mann_whitney_p"]
except KeyError as e:
    sys.exit(f"outputs/results.json is missing key {e}; needed for figure titles.")

def fmt_p(p):
    """Format a results.json p-value (float, '3.2e-10' or '<1e-9') as mathtext."""
    s = str(p).strip()
    bound = s.startswith("<")
    x = float(s.lstrip("<").strip())
    mant, exp = f"{x:.1e}".split("e")
    exp = int(exp)
    body = rf"10^{{{exp}}}" if mant == "1.0" else rf"{mant}\times 10^{{{exp}}}"
    return rf"$p {'<' if bound else '='} {body}$"

plt.rcParams.update({'font.size': 9, 'figure.dpi': 300, 'savefig.bbox': 'tight', 'font.family': 'serif'})

def load_nvd(year):
    with open(f"{DATA_DIR}/CVE-{year}.json") as f:
        raw = json.load(f)
    records = []
    for item in raw["cve_items"]:
        metrics = item.get("metrics", {})
        cvss = None
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics: cvss = metrics[key][0]["cvssData"]; break
        if not cvss: continue
        cwe_list = [d.get("value","") for w in item.get("weaknesses",[]) for d in w.get("description",[])
                    if d.get("value","").startswith("CWE-") and d.get("value","") != "CWE-noinfo"]
        if not cwe_list: continue
        vendors = set()
        for cfg in item.get("configurations",[]):
            for nd in cfg.get("nodes",[]):
                for m in nd.get("cpeMatch",[]):
                    parts = m.get("criteria","").split(":")
                    if len(parts)>=5: vendors.add(parts[3])
        if not vendors: continue
        records.append({"cve_id":item["id"],"vendors":list(vendors),"cwes":cwe_list,
                       "cvss_score":cvss.get("baseScore",0),"year":year,
                       "attack_vector":cvss.get("attackVector",""),
                       "attack_complexity":cvss.get("attackComplexity",""),
                       "privileges_required":cvss.get("privilegesRequired",""),
                       "user_interaction":cvss.get("userInteraction",""),
                       "scope":cvss.get("scope",""),
                       "confidentiality_impact":cvss.get("confidentialityImpact",""),
                       "integrity_impact":cvss.get("integrityImpact",""),
                       "availability_impact":cvss.get("availabilityImpact","")})
    return records

class IRT2PL:
    def __init__(s,N,I): s.N,s.I=N,I; s.theta=np.random.randn(N)*0.3; s.b=np.random.randn(I)*0.3; s.a=np.ones(I)
    def fit(s,data,ne=35,lr=0.005):
        si,ii,r=data; n=len(r)
        for ep in range(ne):
            p=np.random.permutation(n); ss,iii,rr=si[p],ii[p],r[p]; bs=min(4096,n)
            for st in range(0,n,bs):
                e=min(st+bs,n); sb,ib,rb=ss[st:e],iii[st:e],rr[st:e]
                pr=np.clip(expit(s.a[ib]*(s.theta[sb]-s.b[ib])),1e-8,1-1e-8)
                res=rb-pr
                for idx in range(len(sb)):
                    s.theta[sb[idx]]+=lr*s.a[ib[idx]]*res[idx]
                    s.b[ib[idx]]-=lr*s.a[ib[idx]]*res[idx]
                    s.a[ib[idx]]+=lr*0.1*(s.theta[sb[idx]]-s.b[ib[idx]])*res[idx]
                s.a=np.clip(s.a,0.1,5.0)
            s.theta-=s.theta.mean()

def build_matrix(records,mv=20,mc=25):
    vcp=defaultdict(set); vc=Counter(); cc=Counter()
    for r in records:
        for v in r["vendors"]:
            vc[v]+=1
            for c in r["cwes"]: vcp[v].add(c); cc[c]+=1
    vv=sorted([v for v,c in vc.items() if c>=mv],key=lambda v:-vc[v])
    cv=sorted([c for c,n in cc.items() if n>=mc],key=lambda c:-cc[c])
    vi={v:i for i,v in enumerate(vv)}; ci={c:i for i,c in enumerate(cv)}
    m=np.zeros((len(vv),len(cv)))
    for v in vv:
        for c in vcp[v]:
            if c in ci: m[vi[v],ci[c]]=1.0
    return m,vv,cv,vi,ci,vc

print("Loading..."); rec23=load_nvd(2023); rec24=load_nvd(2024); all_rec=rec23+rec24
with open(f"{DATA_DIR}/kev.json") as f: kev={v["cveID"]:v for v in json.load(f)["vulnerabilities"]}
kev_set=set(kev.keys())
exploit_cves=Counter()
with open(f"{DATA_DIR}/exploitdb.csv",encoding='utf-8',errors='ignore') as f:
    for row in csv.DictReader(f):
        for code in row.get('codes','').split(';'):
            code=code.strip()
            if code.startswith('CVE-'): exploit_cves[code]+=1

print("Fitting IRT...")
mat,vendors,cwes,vi,ci,vc=build_matrix(all_rec)
N,I=mat.shape; si,ii=np.where(mat>=0); resp=mat[si,ii]
irt=IRT2PL(N,I); irt.fit((si,ii,resp))
theta,b,a=irt.theta.copy(),irt.b.copy(),irt.a.copy()
naive=mat.mean(axis=1); counts=np.array([vc.get(v,0) for v in vendors])

# ── FIG 1: θ vs Count ──
print("Fig 1...")
fig,ax=plt.subplots(1,1,figsize=(4.5,3.5))
ax.scatter(counts,theta,s=12,alpha=0.5,c='#2563eb',edgecolors='none')
for lv in ['microsoft','linux','ibm','google','apple','cisco','tenda','ivanti']:
    if lv in vi:
        idx=vi[lv]
        offx,offy = (5,3) if lv != 'tenda' else (5,-8)
        ax.annotate(lv,(counts[idx],theta[idx]),fontsize=6,xytext=(offx,offy),textcoords='offset points',fontstyle='italic')
ax.set_xlabel('CVE Count (raw)'); ax.set_ylabel(r'IRT $\theta$ (latent attack surface)')
ax.set_title(f'IRT '+r'$\theta$'+f' vs. CVE Count ('+r'$\rho$'+f' = {spearmanr(theta,counts)[0]:.3f})')
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
fig.savefig(f'{FIG_DIR}/fig1_theta_vs_count.pdf'); plt.close()

# ── FIG 2: b vs Exploitation ──
print("Fig 2...")
cwe_kev_rate={}; cwe_exploit_rate={}
for c,idx in ci.items():
    total,kn,en=0,0,0
    for r in all_rec:
        if c in r["cwes"]: total+=1; kn+=(r["cve_id"] in kev_set); en+=(r["cve_id"] in exploit_cves)
    if total>=10: cwe_kev_rate[c]=kn/total; cwe_exploit_rate[c]=en/total
valid_c=[c for c in ci if c in cwe_kev_rate and c in cwe_exploit_rate]
b_v=np.array([b[ci[c]] for c in valid_c]); kev_v=np.array([cwe_kev_rate[c] for c in valid_c])
exp_v=np.array([cwe_exploit_rate[c] for c in valid_c])
neg_b=-b_v  # CWE commonness = -difficulty
fig,(ax1,ax2)=plt.subplots(1,2,figsize=(7,3.2))
ax1.scatter(neg_b,kev_v*100,s=15,alpha=0.35,c='#dc2626',edgecolors='none',zorder=2)
rho1,p1=spearmanr(neg_b,kev_v)
n_bins=5; bin_edges=np.percentile(neg_b,np.linspace(0,100,n_bins+1))
bc1=[]; bm1=[]
for i in range(n_bins):
    mask=(neg_b>=bin_edges[i])&(neg_b<bin_edges[i+1]) if i<n_bins-1 else (neg_b>=bin_edges[i])
    if mask.sum()>0: bc1.append(neg_b[mask].mean()); bm1.append(kev_v[mask].mean()*100)
ax1.plot(bc1,bm1,'k-o',ms=5,lw=1.5,zorder=3,label='Quintile mean')
ax1.legend(fontsize=7,loc='upper left')
ax1.set_xlabel(r'CWE Commonness ($-b$)'); ax1.set_ylabel('KEV Exploitation Rate (%)')
ax1.set_title(r'Commonness vs. KEV Rate ($\rho$ = '+f'{rho1:.3f})')
ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
ax2.scatter(neg_b,exp_v*100,s=15,alpha=0.35,c='#ea580c',edgecolors='none',zorder=2)
rho2,p2=spearmanr(neg_b,exp_v)
bc2=[]; bm2=[]
for i in range(n_bins):
    mask=(neg_b>=bin_edges[i])&(neg_b<bin_edges[i+1]) if i<n_bins-1 else (neg_b>=bin_edges[i])
    if mask.sum()>0: bc2.append(neg_b[mask].mean()); bm2.append(exp_v[mask].mean()*100)
ax2.plot(bc2,bm2,'k-o',ms=5,lw=1.5,zorder=3,label='Quintile mean')
ax2.legend(fontsize=7,loc='upper left')
ax2.set_xlabel(r'CWE Commonness ($-b$)'); ax2.set_ylabel('ExploitDB Rate (%)')
ax2.set_title(r'Commonness vs. ExploitDB Rate ($\rho$ = '+f'{rho2:.3f})')
ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
fig.tight_layout(pad=1.5); fig.savefig(f'{FIG_DIR}/fig2_difficulty_vs_exploitation.pdf'); plt.close()

# ── FIG 3: Temporal ──
print("Fig 3...")
mat23,v23,c23,vi23,ci23,_=build_matrix(rec23,10,15)
mat24,v24,c24,vi24,ci24,_=build_matrix(rec24,10,15)
common_v=[v for v in v23 if v in set(v24)]; common_c=[c for c in c23 if c in set(c24)]
cvi={v:i for i,v in enumerate(common_v)}; cci={c:i for i,c in enumerate(common_c)}
vcp23=defaultdict(set); vcp24=defaultdict(set)
for r in rec23:
    for v in r["vendors"]:
        for c in r["cwes"]: vcp23[v].add(c)
for r in rec24:
    for v in r["vendors"]:
        for c in r["cwes"]: vcp24[v].add(c)
m23=np.zeros((len(common_v),len(common_c))); m24=np.zeros((len(common_v),len(common_c)))
for v in common_v:
    for c in common_c:
        if c in vcp23.get(v,set()): m23[cvi[v],cci[c]]=1.0
        if c in vcp24.get(v,set()): m24[cvi[v],cci[c]]=1.0
Nc,Ic=len(common_v),len(common_c)
s1,i1=np.where(m23>=0); r1=m23[s1,i1]; irt23=IRT2PL(Nc,Ic); irt23.fit((s1,i1,r1))
s2,i2=np.where(m24>=0); r2=m24[s2,i2]; irt24=IRT2PL(Nc,Ic); irt24.fit((s2,i2,r2))
fig,(ax1,ax2)=plt.subplots(1,2,figsize=(7.5,3.2))
rho_t,_=spearmanr(irt23.theta,irt24.theta)
ax1.scatter(irt23.theta,irt24.theta,s=10,alpha=0.4,c='#2563eb',edgecolors='none')
lims=[min(irt23.theta.min(),irt24.theta.min())-0.3,max(irt23.theta.max(),irt24.theta.max())+0.3]
ax1.plot(lims,lims,'k--',lw=0.8,alpha=0.4)
ax1.set_xlabel(r'Vendor $\theta$ (2023)'); ax1.set_ylabel(r'Vendor $\theta$ (2024)')
# Title value from outputs/results.json (temporal.rho_theta)
ax1.set_title(r'Vendor $\theta$ Stability ($\rho$ = ' + f'{RHO_THETA_TEMPORAL:.3f})')
ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
# Label movers with offset to avoid overlap
delta=irt24.theta-irt23.theta; movers=np.argsort(-np.abs(delta))[:3]
offsets = [(8,-8),(-40,8),(8,6)]  # manual offsets for top 3 movers
for mi,off in zip(movers,offsets):
    ax1.annotate(common_v[mi],(irt23.theta[mi],irt24.theta[mi]),fontsize=5.5,
                xytext=off,textcoords='offset points',fontstyle='italic',
                arrowprops=dict(arrowstyle='-',lw=0.4,color='gray'))
rho_b,_=spearmanr(irt23.b,irt24.b)
ax2.scatter(irt23.b,irt24.b,s=10,alpha=0.4,c='#16a34a',edgecolors='none')
lims2=[min(irt23.b.min(),irt24.b.min())-0.3,max(irt23.b.max(),irt24.b.max())+0.3]
ax2.plot(lims2,lims2,'k--',lw=0.8,alpha=0.4)
ax2.set_xlabel('CWE Difficulty $b$ (2023)'); ax2.set_ylabel('CWE Difficulty $b$ (2024)')
ax2.set_title(r'CWE Difficulty Stability ($\rho$ = ' + f'{RHO_B_TEMPORAL:.3f})')  # temporal.rho_b
ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
fig.tight_layout(pad=1.5); fig.savefig(f'{FIG_DIR}/fig3_temporal_stability.pdf'); plt.close()

# ── FIG 4: LLTM Weights ──
print("Fig 4...")
feat_maps={"AV":["NETWORK","ADJACENT_NETWORK","LOCAL","PHYSICAL"],
           "AC":["LOW","HIGH"],"PR":["NONE","LOW","HIGH"],
           "UI":["NONE","REQUIRED"],"S":["UNCHANGED","CHANGED"],
           "C":["NONE","LOW","HIGH"],"I":["NONE","LOW","HIGH"],
           "A":["NONE","LOW","HIGH"]}
field_map={"AV":"attack_vector","AC":"attack_complexity","PR":"privileges_required",
           "UI":"user_interaction","S":"scope","C":"confidentiality_impact",
           "I":"integrity_impact","A":"availability_impact"}
names=[]; abbrevs=[]
cvss_abbrev={"NETWORK":"N","ADJACENT_NETWORK":"A","LOCAL":"L","PHYSICAL":"P",
             "LOW":"L","HIGH":"H","NONE":"N","REQUIRED":"R","UNCHANGED":"U","CHANGED":"C"}
for short,vals in feat_maps.items():
    for v in vals: names.append(f"{field_map[short]}"); abbrevs.append(f"{short}:{cvss_abbrev[v]}")
abbrevs.append("AvgCVSS")
cwe_fc=defaultdict(lambda:np.zeros(len(abbrevs)-1)); cwe_tot=Counter(); cwe_cvss=defaultdict(list)
for r in all_rec:
    vec=np.zeros(len(abbrevs)-1); idx=0
    for short,vals in feat_maps.items():
        for v in vals:
            if r.get(field_map[short])==v: vec[idx]=1.0
            idx+=1
    for c in r["cwes"]:
        if c in ci: cwe_fc[c]+=vec; cwe_tot[c]+=1; cwe_cvss[c].append(r["cvss_score"])
Q=np.zeros((len(cwes),len(abbrevs)-1)); avg_c=np.zeros(len(cwes))
for c,i in ci.items():
    if cwe_tot[c]>0: Q[i]=cwe_fc[c]/cwe_tot[c]; avg_c[i]=np.mean(cwe_cvss[c])
Q_full=np.column_stack([Q,avg_c/10.0])
Q_aug=np.column_stack([Q_full,np.ones(len(cwes))])
eta,_,_,_=np.linalg.lstsq(Q_aug,b,rcond=None); eta=eta[:-1]
top_idx=np.argsort(-np.abs(eta))[:12]
fig,ax=plt.subplots(figsize=(4.5,3.8))
y_pos=np.arange(len(top_idx))
colors=['#dc2626' if eta[i]>0 else '#2563eb' for i in top_idx]
ax.barh(y_pos,eta[top_idx],color=colors,height=0.6,alpha=0.8)
ax.set_yticks(y_pos); ax.set_yticklabels([abbrevs[i] for i in top_idx],fontsize=7)
ax.set_xlabel(r'LLTM Weight ($\eta$)')
ax.set_title(r'LLTM: CVSS Features $\rightarrow$ CWE Difficulty')
ax.axvline(0,color='black',lw=0.5); ax.invert_yaxis()
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
fig.tight_layout(); fig.savefig(f'{FIG_DIR}/fig4_lltm_weights.pdf'); plt.close()

# ── FIG 5: Ransomware ──
print("Fig 5...")
ransomware_set=set()
for cve_id,info in kev.items():
    if info.get("knownRansomwareCampaignUse")=="Known":
        for r in all_rec:
            if r["cve_id"]==cve_id:
                for c in r["cwes"]:
                    if c in ci: ransomware_set.add(c)
b_ran=[b[ci[c]] for c in ransomware_set if c in ci]
b_noran=[b[ci[c]] for c in ci if c not in ransomware_set]
fig,ax=plt.subplots(figsize=(4.5,3))
bp=ax.boxplot([b_ran,b_noran],tick_labels=[f'Ransomware\nCWEs (n={len(b_ran)})',
              f'Non-ransomware\nCWEs (n={len(b_noran)})'],patch_artist=True,widths=0.5)
bp['boxes'][0].set_facecolor('#fee2e2'); bp['boxes'][0].set_edgecolor('#dc2626')
bp['boxes'][1].set_facecolor('#dbeafe'); bp['boxes'][1].set_edgecolor('#2563eb')
bp['medians'][0].set_color('#dc2626'); bp['medians'][1].set_color('#2563eb')
ax.set_ylabel('IRT Difficulty ($b$)')
ax.set_title(r'Ransomware Targets Low-Difficulty CWEs'+'\n'+'(Mann-Whitney '+fmt_p(RANSOMWARE_MW_P)+')')  # ransomware.mann_whitney_p
ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
fig.tight_layout(); fig.savefig(f'{FIG_DIR}/fig5_ransomware.pdf'); plt.close()

print("All figures generated (Type 42 fonts, no overlap).")
for f in sorted(os.listdir(FIG_DIR)):
    print(f"  {f}")
