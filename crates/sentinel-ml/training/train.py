#!/usr/bin/env python3
"""Retrain with ADVERSARIAL-BENIGN augmentation so the model learns injection
STRUCTURE, not attack-keyword presence. Adds: real English prose phrases, legit
SQL queries, benign JSON, and benign paths/params — all label=0. Keeps the
lexical TEST set fully held out."""
import csv, json, glob, re, random
import numpy as np
from sklearn.linear_model import LogisticRegression

K = 4096; NS = [2,3,4]
FNV_OFFSET=2166136261; FNV_PRIME=16777619; MASK=0xFFFFFFFF
random.seed(1337)

def fnv1a(b):
    h=FNV_OFFSET
    for x in b: h^=x; h=(h*FNV_PRIME)&MASK
    return h
def featurize(text):
    v=np.zeros(K,dtype=np.float32); b=text.lower().encode("utf-8","ignore"); n=len(b)
    for ng in NS:
        for i in range(n-ng+1): v[fnv1a(b[i:i+ng])%K]=1.0
    return v
def matrix(ts): return np.vstack([featurize(t) for t in ts]) if ts else np.zeros((0,K),np.float32)

def load(p):
    X,y,t=[],[],[]
    for r in csv.DictReader(open(p)):
        X.append(r["payload"]); y.append(1 if r["label"]=="anom" else 0); t.append(r["attack_type"])
    return X,np.array(y,np.float32),t

# --- adversarial-benign generators -------------------------------------------
def prose_phrases(nmax=5000):
    kw=re.compile(r"\b(or|and|select|union|from|where|script|alert|drop|insert|update|set|by|like|null|true|false|exec|order|group|char|user|admin|and|not)\b",re.I)
    words=[]
    for f in glob.glob("gb_*.txt"):
        txt=open(f,encoding="utf-8",errors="ignore").read()
        words+=re.findall(r"[A-Za-z']+",txt)
    out=[]; i=0
    while i < len(words)-12 and len(out)<nmax:
        ln=random.randint(3,11); ph=" ".join(words[i:i+ln]); i+=ln
        out.append(ph)
        # oversample keyword-containing phrases as hard negatives
        if kw.search(ph): out.append(ph)
    return out[:nmax]

def benign_sql(n=2500):
    cols=["id","name","price","email","created_at","status","title","qty","category","user_id"]
    tabs=["users","products","orders","sessions","invoices","categories","items","logs"]
    vals=["books","active","2023-01-01","alice","pending","electronics","north","new","gold","42"]
    out=[]
    for _ in range(n):
        c=random.sample(cols,random.randint(1,3)); t=random.choice(tabs)
        f=random.choice([
            f"select {', '.join(c)} from {t} where {random.choice(cols)} = '{random.choice(vals)}'",
            f"select {', '.join(c)} from {t} order by {random.choice(cols)}",
            f"select count(*) from {t} where {random.choice(cols)} = {random.randint(1,999)}",
            f"insert into {t} ({', '.join(c)}) values ('{random.choice(vals)}')",
            f"select {c[0]} from {t} join {random.choice(tabs)} on {t}.id = {random.choice(tabs)}.{t}_id",
            f"update {t} set {random.choice(cols)} = '{random.choice(vals)}' where id = {random.randint(1,999)}",
        ])
        out.append(f)
    return out

def benign_json_paths(n=1500):
    keys=["name","role","query","select","filter","order","script","union","search","tag"]
    vals=["alice","admin","select all","union of sets","a and b","or maybe","sort by name","true","new-item"]
    out=[]
    for _ in range(n):
        if random.random()<0.5:
            k=random.sample(keys,random.randint(1,3))
            out.append("{"+", ".join(f'"{x}": "{random.choice(vals)}"' for x in k)+"}")
        else:
            out.append("/api/"+random.choice(["v1","v2"])+"/"+random.choice(keys)+"?"+random.choice(keys)+"="+random.choice(["name","asc","desc","1","true"]))
    return out

Xtr,ytr,_=load("HttpParamsDataset/payload_train.csv")
Xte,yte,tte=load("HttpParamsDataset/payload_test.csv")
Xlex,ylex,_=load("HttpParamsDataset/payload_test_lexical.csv")

aug=prose_phrases()+benign_sql()+benign_json_paths()
print(f"augmenting with {len(aug)} adversarial-benign samples (prose+SQL+JSON+paths)")
Xtr=Xtr+aug; ytr=np.concatenate([ytr,np.zeros(len(aug),np.float32)])

print("featurizing...")
Mtr,Mte,Mlex=matrix(Xtr),matrix(Xte),matrix(Xlex)
clf=LogisticRegression(C=1.0,class_weight="balanced",max_iter=3000,solver="liblinear")
clf.fit(Mtr,ytr)

def rep(name,y,proba,thr):
    pred=(proba>=thr).astype(int)
    tp=int(((pred==1)&(y==1)).sum());fn=int(((pred==0)&(y==1)).sum())
    tn=int(((pred==0)&(y==0)).sum());fp=int(((pred==1)&(y==0)).sum())
    tpr=tp/(tp+fn) if tp+fn else 0; fpr=fp/(fp+tn) if fp+tn else 0
    print(f"  [{name} thr={thr:.2f}] TPR={tpr*100:.2f}% FPR={fpr*100:.2f}% (tp={tp} fn={fn} fp={fp} tn={tn})")
pte=clf.predict_proba(Mte)[:,1]; plex=clf.predict_proba(Mlex)[:,1]
print("=== payload_test ==="); [rep("test",yte,pte,t) for t in (0.5,0.7,0.9)]
print("=== payload_test_lexical (hard benign code) ==="); [rep("lex",ylex,plex,t) for t in (0.5,0.7,0.9)]

w=clf.coef_.ravel().astype(float).tolist(); b=float(clf.intercept_.ravel()[0])
json.dump({"version":1,"k":K,"ngrams":NS,"hash":"fnv1a32","normalize":"lower_utf8","bias":b,"weights":w},
          open("payload_ngram.json","w"))
print(f"exported payload_ngram.json (K={K}, bias={b:.4f})")
