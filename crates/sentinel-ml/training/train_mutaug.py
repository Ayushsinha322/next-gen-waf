#!/usr/bin/env python3
"""Mutation-augmented training: apply the SAME evasion transforms attackers use
(multi-encoding, case, SQL comments, whitespace, keyword-splitting) to the attack
corpus so the model covers the evasion space and generalises to out-of-distribution
mutations (GoTestWAF's). Benign trained on real legit code + FWAF + adversarial +
some encoded-benign (so 'encoding' is not learned as an attack signal). Inference
already canonicalises (recursive decode). GoTestWAF NEVER trained on.

Usage: train_mutaug.py [K] [OUT.json]
"""
import csv, glob, re, random, os, sys, urllib.parse
import numpy as np
from sklearn.linear_model import LogisticRegression
from scipy import sparse

K = int(sys.argv[1]) if len(sys.argv) > 1 else 16384
OUT = sys.argv[2] if len(sys.argv) > 2 else "payload_ngram_mutaug.json"
NS = [2, 3, 4]; MAXLEN = 512
OLD = "/tmp/claude-1000/-home-ayush3750-waf-development/24905267-7ca1-4d87-9e75-328eeac4243f/scratchpad/ml-corpus"
EVA = "/tmp/claude-1000/-home-ayush3750-waf-development/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/evasion-corpus"
HARD = "/tmp/claude-1000/-home-ayush3750-waf-development/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/hard-benign"
BEN = "/tmp/claude-1000/-home-ayush3750-waf-development/cbcb63a2-92d2-4e2b-ab24-29bdba5eb6c3/scratchpad/benign-corpus"
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
def lines(f, exclude=None):
    if not os.path.exists(f): return []
    return [l.rstrip("\n").rstrip("\r") for l in open(f,encoding="utf-8",errors="ignore")
            if l.strip() and not l.startswith("#") and not l.lower().startswith("404:")]
def load_dir(d, cap, exclude=None):
    out=[]
    for f in sorted(glob.glob(f"{d}/*.txt")):
        if exclude and exclude in os.path.basename(f): continue
        out+=lines(f)
    out=[a for a in dict.fromkeys(out) if 3<=len(a)<=MAXLEN]; rng.shuffle(out)
    return out[:cap]

# ---- mutation engine (all deterministic; no loops that can run away) ----
def url_enc(s):       return urllib.parse.quote(s, safe='')
def url_enc_part(s):  return ''.join('%%%02X'%ord(c) if c in '<>\'"();&|=/ *' and ord(c)<128 else c for c in s)
def double_url(s):    return url_enc(url_enc(s))
def entity_enc(s):    return ''.join('&#%d;'%ord(c) if c in '<>\'"&/():;=' else c for c in s)
def entity_hex(s):    return ''.join('&#x%x;'%ord(c) if c in '<>\'"&/():;=' else c for c in s)
def rand_case(s):     return ''.join(c.upper() if rng.random()<0.5 else c.lower() for c in s)
def sql_comment(s):   return s.replace(' ', '/**/')
def ws_vary(s):       return s.replace(' ', rng.choice(['\t','\n','\x0b','\x0c','  ','+','%20']))
def kw_split(s):      # SEL/**/ECT style — split long alpha runs once
    m=re.search(r'[A-Za-z]{5,}', s)
    if not m: return s
    i=m.start()+len(m.group())//2
    return s[:i]+'/**/'+s[i:]
MUTATORS=[url_enc, url_enc_part, double_url, entity_enc, entity_hex, rand_case, sql_comment, ws_vary, kw_split]

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

# ---- generated structural attacks (capped) ----
def gen_xss(n):
    tg=["script","img","svg","iframe","body","a","div","details","object","video","input","form","style","math","marquee"]
    ev=["onload","onerror","onclick","onmouseover","ontoggle","onpointerover","onfocus","onanimationstart","onbeforetoggle"]
    js=["alert(1)","alert(document.cookie)","prompt(1)","confirm(1)","eval(name)","fetch('//x')","alert`1`","(alert)(1)"]
    o=set();k=0
    while len(o)<n and k<n*80:
        k+=1;t=rng.choice(tg);e=rng.choice(ev);p=rng.choice(js)
        o.add(rng.choice([f"<{t} {e}={p}>",f"<{t}>{p}</{t}>",f'"><{t} {e}={p}>',f"javascript:{p}",f"<{t} src=x {e}={p}>",f"<svg><script>{p}</script></svg>"]))
    return list(o)
def gen_sqli(n):
    pre=["","'",'"',") ","1' ","admin' ","') ",'" '];bd=["OR 1=1","OR '1'='1","UNION SELECT NULL","UNION SELECT username,password FROM users","AND SLEEP(5)","; DROP TABLE users","AND updatexml(1,concat(0x7e,user()),1)","OR 1=1-- -","UNION ALL SELECT 1,2,3","; WAITFOR DELAY '0:0:5'"];sf=["","-- -"," #","/*","%00"]
    o=set();k=0
    while len(o)<n and k<n*80: k+=1;o.add((rng.choice(pre)+rng.choice(bd)+rng.choice(sf)).strip())
    return list(o)

# ---- assemble ----
base_atk = load_dir(EVA, 14000) + gen_xss(3000) + gen_sqli(3000)
base_atk = list(dict.fromkeys([a for a in base_atk if a]))
atk = augment_attacks(base_atk, per=4)
print(f"attacks: {len(base_atk)} base -> {len(atk)} mutation-augmented")

# benign: real legit code (hard) + FWAF + adversarial + SOME encoded-benign
hard = load_dir(HARD, 14000, exclude="prose_security")
fwaf = load_dir(BEN, 20000)  # good_fwaf lives here
Xtr_hp, _ = [], None
hp_rows = list(csv.DictReader(open(f"{OLD}/HttpParamsDataset/payload_train.csv")))
hp_ben = [r["payload"] for r in hp_rows if r["label"]=="norm"]
def adv_benign(n):
    NOUN=["order","report","table","user","account","product","script","form","menu","update","group","query","filter","comment","profile","file","project","category"]
    VERB=["select","update","insert","delete","join","drop","order","union","alert","print","sort","filter","submit"]
    CONN=["and","or","from","where","by","null","between","having","like"]
    o=set();k=0;w=lambda:rng.choice(NOUN)
    while len(o)<n and k<n*40:
        k+=1;r=rng.random()
        if r<.4: s=f"please {rng.choice(VERB)} the {w()} {rng.choice(CONN)} {w()}"
        elif r<.7: s=f"{rng.choice(VERB)} {w()} {rng.choice(CONN)} {w()} = {w()}"
        else: s=rng.choice([f"x=({rng.randint(0,99)}+{rng.randint(0,99)})*2",f"a && b || c",f"{{{{ {w()}.{w()} }}}}",f"${{{w()}}}"])
        o.add(s)
    return list(o)
adv = adv_benign(6000)
enc_benign = [url_enc_part(b) for b in rng.sample(hard+fwaf, min(4000, len(hard)+len(fwaf)))]  # encoded benign so encoding!=attack
ben = hard + fwaf + hp_ben + adv + enc_benign

allX = atk + ben
allY = np.r_[np.ones(len(atk),np.float32), np.zeros(len(ben),np.float32)]
print(f"train: {len(allX)} ({len(atk)} atk / {len(ben)} benign [{len(hard)} hard-code + {len(fwaf)} fwaf + {len(hp_ben)} hp + {len(adv)} adv + {len(enc_benign)} enc])", flush=True)
print("featurizing...", flush=True)
clf=LogisticRegression(C=0.5,class_weight="balanced",max_iter=4000,solver="liblinear").fit(matrix(allX), allY)

# quick sanity (NOT a GoTestWAF predictor — just confirms the model is sane)
def fpr(g): return (clf.predict_proba(matrix(g))[:,1]>=0.9).mean()*100
print(f"  sanity gen-XSS recall@0.9 = {fpr(gen_xss(400)):.1f}%   gen-SQLi = {fpr(gen_sqli(400)):.1f}%")
print(f"  sanity hard-code benign FP@0.9 = {fpr(rng.sample(hard,2000)):.2f}%   fwaf FP@0.9 = {fpr(rng.sample(fwaf,2000)):.2f}%")

w=clf.coef_.ravel().astype(float).tolist(); b=float(clf.intercept_.ravel()[0])
import json
json.dump({"version":1,"k":K,"ngrams":NS,"hash":"fnv1a32","normalize":"lower_utf8","bias":b,"weights":w}, open(OUT,"w"))
print(f"exported {OUT} (k={K}, bias={b:.4f})", flush=True)
