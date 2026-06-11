

sentinel uses a custom rust reverse proxy built on hyper + rustls

the data planes crates/sentinel-proxy/src/lib.rs) is a full standalone http/1.1, HTTP/2, and http/3 reverproxt 

hyper a fast http library for rust like express.js but for rust . ity handles berfore parsing http request at wire level 


rustls a tls library for Rust like Openssl; , but written in rust . it does https encrytpion and decryption cert handling, etc.



sentinel custom proxy components:

listener - binds tcp sockets handles tls via rustls 


HTTP handler - Parser hTTP/1.1 AND Hhttps/ via hyper 

6 phase pipleline - runs waf rules , rate limiting , Ml etc . inline on evert request 

UpstreamPool - Round-robin load balacning to backend servers 


hot-reload : swaps configs atomically without dropping connections 


instead of chaining HAproxy - waf - backend (3hops) sentinel does proxy + waf = bvackend (2 hops) all in one rust process }
less latency , fewer moving parts 


Instead of chaining HAproxy - waf - backend **3hops** 
sentinel does proxy + waf - backend (2hops) all in one rust process. less latency , fewer moving parts.


oUTBOUND dlp 

most waf only inspect inbound traffic 

sentinel also scan response 
ex - 4111 -1 111 --111 
sentinel blocks scans response 
this is enterprise grade 


## Control Plane (go)

go control plane manages 

configs 
nodes 
polciies 
users 
rbac 
cluster 

RAFT CLustering 

Consesus algorithm 

Ensures :
Config consistency 
leader node validates 
replicates to cluster 
Consensus achieved 
all waf nodes updated


Raft 
Imagine 3 control plane servers running Sentinel. One is then leader the boss
two are followers



