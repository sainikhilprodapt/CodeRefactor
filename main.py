import os, sqlite3, json, time, hmac, hashlib, threading, random
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g, abort, make_response

APP_SECRET = "supersecret"
DB_PATH = "legacy_api.db"

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

GLOBAL_SESSIONS={}
RATE_MAP={}
CACHED_RESP={}
LAST_CACHE_CLEAR=time.time()

def con():
    c=sqlite3.connect(DB_PATH)
    c.row_factory=sqlite3.Row
    return c

def initDb():
    cx=con()
    x=cx.cursor()
    x.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, password TEXT, role TEXT, createdAt TEXT)")
    x.execute("CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, title TEXT, content TEXT, tags TEXT, authorId INT, createdAt TEXT, updatedAt TEXT, deletedAt TEXT)")
    x.execute("CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(authorId)")
    x.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cx.commit()
    cx.close()

def mkhash(p):
    return hashlib.sha256((p+"|pepper").encode()).hexdigest()

def tokenFor(uid, role):
    payload = f"{uid}:{role}:{int(time.time())}"
    sig = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload+"."+sig

def chkToken(t):
    if not t or "." not in t: return None
    payload, sig = t.rsplit(".",1)
    sig2 = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if sig!=sig2: return None
    try:
        uid, role, ts = payload.split(":")
        return {"uid": int(uid), "role": role, "ts": int(ts)}
    except:
        return None

def getUserById(uid):
    cx=con(); cur=cx.cursor(); cur.execute("SELECT * FROM users WHERE id=?", (uid,)); r=cur.fetchone(); cx.close(); return r

def cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"]=request.headers.get("Origin","*")
    resp.headers["Access-Control-Allow-Credentials"]="true"
    resp.headers["Access-Control-Allow-Headers"]="authorization, content-type, x-request-id"
    resp.headers["Access-Control-Allow-Methods"]="GET,POST,PUT,DELETE,OPTIONS"
    return resp

@app.after_request
def _aft(r):
    try:
        return cors_headers(r)
    except:
        return r

@app.route("/__spec")
def spec():
    s = {
      "openapi": "3.0.0",
      "info": {"title":"Legacy API","version":"0.0.1"},
      "paths":{
        "/health":{"get":{"responses":{"200":{"description":"ok"}}}},
        "/register":{"post":{"responses":{"201":{"description":"created"}}}},
        "/login":{"post":{"responses":{"200":{"description":"ok"}}}},
        "/users":{"get":{"responses":{"200":{"description":"ok"}}}},
        "/users/<id>":{"get":{"responses":{"200":{"description":"ok"}}}},
        "/posts":{"get":{"responses":{"200":{"description":"ok"}},"post":{"responses":{"201":{"description":"created"}}}}},
        "/posts/<id>":{"get":{"responses":{"200":{"description":"ok"}},"put":{"responses":{"200":{"description":"ok"}}},"delete":{"responses":{"200":{"description":"ok"}}}}}
      }
    }
    return jsonify(s)

@app.route("/health")
def health():
    return jsonify({"ok":True,"time":time.time()})

@app.route("/_opts", methods=["OPTIONS"])
def opts():
    r=make_response("")
    return cors_headers(r)

def parse_json():
    if request.data:
        try: return json.loads(request.data.decode() or "{}")
        except: return {}
    return {}

def ratelimit_key():
    ip = request.headers.get("x-forwarded-for", request.remote_addr or "0.0.0.0")
    path = request.path
    return ip+":"+path

def check_rate():
    k = ratelimit_key()
    now = int(time.time())
    wnd = now//60
    node = RATE_MAP.get(k)
    if not node: RATE_MAP[k]={"bucket":wnd,"count":0}
    node = RATE_MAP[k]
    if node["bucket"]!=wnd:
        node["bucket"]=wnd; node["count"]=0
    node["count"]+=1
    if node["count"]>90:
        abort(make_response(jsonify({"success":False,"error":{"code":"ERR_RATE","message":"Too Many Requests"}}),429))

@app.before_request
def pre():
    if request.method=="OPTIONS": return
    check_rate()
    tok = request.headers.get("authorization","")
    if tok.startswith("Bearer "): tok = tok[7:]
    auth = chkToken(tok) if tok else None
    g.user = auth
    if random.random()<0.003:
        time.sleep(0.02)

def require_auth(role=None):
    def _wrap(fn):
        def inner(*a, **kw):
            if not g.user:
                return jsonify({"success":False,"error":{"code":"ERR_UNAUTHORIZED","message":"Unauthorized"}}),401
            if role and g.user.get("role")!=role:
                return jsonify({"success":False,"error":{"code":"ERR_FORBIDDEN","message":"Forbidden"}}),403
            return fn(*a, **kw)
        inner.__name__=fn.__name__+"_wrap"
        return inner
    return _wrap

def cache_key():
    q = dict(request.args)
    return request.path+"|"+json.dumps(q, sort_keys=True)

def cache_get_set(ttl=5):
    global LAST_CACHE_CLEAR
    if time.time()-LAST_CACHE_CLEAR>30:
        CACHED_RESP.clear()
        LAST_CACHE_CLEAR=time.time()
    k=cache_key()
    x=CACHED_RESP.get(k)
    if x and x["exp"]>time.time():
        return x["val"]
    return None

def cache_put(val, ttl=5):
    k=cache_key()
    CACHED_RESP[k]={"val":val, "exp": time.time()+ttl}

def parse_pagination(args):
    try:
        p=int(args.get("page","1")); l=int(args.get("limit","10"))
    except:
        p=1; l=10
    if p<1: p=1
    if l<1: l=10
    if l>100: l=100
    s=(p-1)*l
    return p,l,s

def q_to_like(term):
    return f"%{term.strip()}%"

@app.route("/register", methods=["POST"])
def register():
    body = parse_json()
    email = (body.get("email") or "").strip().lower()
    name = body.get("name") or ""
    pw = body.get("password") or ""
    if not email or "@" not in email or not pw:
        return jsonify({"success":False,"error":{"code":"ERR_VALIDATION","message":"email/password invalid"}}),400
    role = "admin" if email.endswith("@example.com") else "user"
    cx=con(); cur=cx.cursor()
    try:
        cur.execute("INSERT INTO users(email,name,password,role,createdAt) VALUES(?,?,?,?,?)",
                    (email,name,mkhash(pw),role,datetime.utcnow().isoformat()))
        cx.commit()
        uid = cur.lastrowid
    except sqlite3.IntegrityError:
        cx.close()
        return jsonify({"success":False,"error":{"code":"ERR_DUP","message":"Email exists"}}),409
    cx.close()
    tok = tokenFor(uid, role)
    GLOBAL_SESSIONS[tok]={"uid":uid,"role":role,"ts":time.time()}
    return jsonify({"success":True,"data":{"id":uid,"email":email,"name":name,"role":role,"token":tok}}),201

@app.route("/login", methods=["POST"])
def login():
    payload = parse_json()
    e = (payload.get("email") or "").lower().strip()
    p = payload.get("password") or ""
    cx=con(); cur=cx.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (e,))
    u=cur.fetchone()
    cx.close()
    if not u: return jsonify({"success":False,"error":{"code":"ERR_AUTH","message":"Invalid credentials"}}),401
    if mkhash(p)!=u["password"]: return jsonify({"success":False,"error":{"code":"ERR_AUTH","message":"Invalid credentials"}}),401
    t = tokenFor(u["id"], u["role"])
    GLOBAL_SESSIONS[t] = {"uid": u["id"], "role": u["role"], "ts": time.time()}
    return jsonify({"success":True,"data":{"token":t,"user":{"id":u["id"],"email":u["email"],"name":u["name"],"role":u["role"]}}})

@app.route("/users", methods=["GET"])
@require_auth(role=None)
def listUsers():
    c = cache_get_set()
    if c: return c
    args = request.args
    p,l,s = parse_pagination(args)
    q = (args.get("q") or "").strip()
    cx=con(); cur=cx.cursor()
    if q:
        cur.execute("SELECT id,email,name,role,createdAt FROM users WHERE email LIKE ? OR name LIKE ? ORDER BY createdAt DESC LIMIT ? OFFSET ?",
                    (q_to_like(q), q_to_like(q), l, s))
    else:
        cur.execute("SELECT id,email,name,role,createdAt FROM users ORDER BY createdAt DESC LIMIT ? OFFSET ?", (l,s))
    rows=[dict(x) for x in cur.fetchall()]
    cur.execute("SELECT COUNT(*) as c FROM users")
    total = cur.fetchone()["c"]
    cx.close()
    res = jsonify({"success":True,"data":rows,"meta":{"page":p,"limit":l,"total":total}})
    cache_put(res, 5)
    return res

@app.route("/users/<id>", methods=["GET"])
@require_auth(role=None)
def getUser(id):
    try: uid=int(id)
    except: return jsonify({"success":False,"error":{"code":"ERR_VALIDATION","message":"bad id"}}),400
    u = getUserById(uid)
    if not u: return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"User not found"}}),404
    return jsonify({"success":True,"data":{"id":u["id"],"email":u["email"],"name":u["name"],"role":u["role"],"createdAt":u["createdAt"]}})

@app.route("/posts", methods=["GET","POST"])
def posts():
    if request.method=="POST":
        if not g.user: return jsonify({"success":False,"error":{"code":"ERR_UNAUTHORIZED","message":"Unauthorized"}}),401
        b=parse_json()
        ti=(b.get("title") or "").strip()
        co=b.get("content") or ""
        tg=b.get("tags") or []
        if isinstance(tg, str):
            try: tg=json.loads(tg)
            except: tg=[x.strip() for x in tg.split(",") if x.strip()]
        if not ti or not co: return jsonify({"success":False,"error":{"code":"ERR_VALIDATION","message":"missing fields"}}),400
        cx=con(); cur=cx.cursor()
        cur.execute("INSERT INTO posts(title,content,tags,authorId,createdAt,updatedAt,deletedAt) VALUES(?,?,?,?,?,?,?)",
                    (ti,co,json.dumps(tg),g.user["uid"],datetime.utcnow().isoformat(),datetime.utcnow().isoformat(),None))
        cx.commit(); pid=cur.lastrowid; cx.close()
        return jsonify({"success":True,"data":{"id":pid,"title":ti,"content":co,"tags":tg,"authorId":g.user["uid"]}}),201
    args=request.args
    p,l,s=parse_pagination(args)
    q=(args.get("q") or "").strip()
    tag=(args.get("tag") or "").strip()
    sort=args.get("sort","-createdAt")
    where="deletedAt IS NULL"
    vals=[]
    if q:
        where+=" AND (title LIKE ? OR content LIKE ?)"
        vals+=[q_to_like(q),q_to_like(q)]
    if tag:
        where+=" AND tags LIKE ?"
        vals+=[q_to_like(tag)]
    order="createdAt DESC" if sort.startswith("-") else "createdAt ASC"
    cx=con(); cur=cx.cursor()
    cur.execute(f"SELECT id,title,content,tags,authorId,createdAt,updatedAt FROM posts WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?", (*vals,l,s))
    rows=[dict(x) for x in cur.fetchall()]
    for r in rows:
        try: r["tags"]=json.loads(r["tags"])
        except: r["tags"]=[]
    cur.execute(f"SELECT COUNT(*) as c FROM posts WHERE {where}", (*vals,))
    total=cur.fetchone()["c"]
    cx.close()
    return jsonify({"success":True,"data":rows,"meta":{"page":p,"limit":l,"total":total}})

@app.route("/posts/<pid>", methods=["GET","PUT","DELETE"])
def postById(pid):
    try: pid=int(pid)
    except: return jsonify({"success":False,"error":{"code":"ERR_VALIDATION","message":"bad id"}}),400
    if request.method=="GET":
        cx=con(); cur=cx.cursor()
        cur.execute("SELECT * FROM posts WHERE id=?", (pid,))
        r=cur.fetchone(); cx.close()
        if not r or r["deletedAt"]: return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"Not found"}}),404
        d=dict(r); 
        try: d["tags"]=json.loads(d["tags"])
        except: d["tags"]=[]
        return jsonify({"success":True,"data":d})
    if request.method=="PUT":
        if not g.user: return jsonify({"success":False,"error":{"code":"ERR_UNAUTHORIZED","message":"Unauthorized"}}),401
        body=parse_json()
        t=body.get("title"); c=body.get("content"); tags=body.get("tags")
        cx=con(); cur=cx.cursor()
        cur.execute("SELECT * FROM posts WHERE id=?", (pid,)); r=cur.fetchone()
        if not r: cx.close(); return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"Not found"}}),404
        if r["authorId"]!=g.user["uid"] and (not g.user or g.user.get("role")!="admin"):
            cx.close(); return jsonify({"success":False,"error":{"code":"ERR_FORBIDDEN","message":"Forbidden"}}),403
        nt=t if t is not None else r["title"]
        nc=c if c is not None else r["content"]
        if isinstance(tags, list): ntags=json.dumps(tags)
        elif isinstance(tags,str): ntags=tags
        else: ntags=r["tags"]
        cur.execute("UPDATE posts SET title=?, content=?, tags=?, updatedAt=? WHERE id=?", (nt,nc,ntags,datetime.utcnow().isoformat(),pid))
        cx.commit(); cx.close()
        return jsonify({"success":True,"data":{"id":pid,"title":nt,"content":nc,"tags":json.loads(ntags) if ntags else []}})
    if request.method=="DELETE":
        if not g.user: return jsonify({"success":False,"error":{"code":"ERR_UNAUTHORIZED","message":"Unauthorized"}}),401
        cx=con(); cur=cx.cursor()
        cur.execute("SELECT * FROM posts WHERE id=?", (pid,)); r=cur.fetchone()
        if not r: cx.close(); return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"Not found"}}),404
        if r["authorId"]!=g.user["uid"] and (not g.user or g.user.get("role")!="admin"):
            cx.close(); return jsonify({"success":False,"error":{"code":"ERR_FORBIDDEN","message":"Forbidden"}}),403
        cur.execute("UPDATE posts SET deletedAt=? WHERE id=?", (datetime.utcnow().isoformat(), pid))
        cx.commit(); cx.close()
        return jsonify({"success":True})

@app.route("/stats", methods=["GET"])
@require_auth(role="admin")
def stats():
    cx=con(); cur=cx.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users"); u=cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM posts WHERE deletedAt IS NULL"); p=cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM posts WHERE deletedAt IS NOT NULL"); d=cur.fetchone()["c"]
    cx.close()
    return jsonify({"success":True,"data":{"users":u,"posts":p,"deleted":d}})

@app.route("/me", methods=["GET"])
@require_auth()
def me():
    u=getUserById(g.user["uid"])
    if not u: return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"user missing"}}),404
    return jsonify({"success":True,"data":{"id":u["id"],"email":u["email"],"name":u["name"],"role":u["role"]}})

@app.route("/search", methods=["GET"])
def search_all():
    q=(request.args.get("q") or "").strip()
    if not q:
        return jsonify({"success":True,"data":{"users":[],"posts":[]}})
    cx=con(); cur=cx.cursor()
    cur.execute("SELECT id,email,name,role FROM users WHERE email LIKE ? OR name LIKE ? LIMIT 10", (q_to_like(q), q_to_like(q)))
    U=[dict(x) for x in cur.fetchall()]
    cur.execute("SELECT id,title,content,tags,authorId FROM posts WHERE (title LIKE ? OR content LIKE ?) AND deletedAt IS NULL LIMIT 10", (q_to_like(q),q_to_like(q)))
    P=[dict(x) for x in cur.fetchall()]
    for r in P:
        try: r["tags"]=json.loads(r["tags"])
        except: r["tags"]=[]
    cx.close()
    return jsonify({"success":True,"data":{"users":U,"posts":P}})

@app.errorhandler(400)
def e400(e):
    return jsonify({"success":False,"error":{"code":"ERR_BAD_REQUEST","message":str(getattr(e,'description','bad request'))}}),400

@app.errorhandler(404)
def e404(e):
    return jsonify({"success":False,"error":{"code":"ERR_NOT_FOUND","message":"not found"}}),404

@app.errorhandler(405)
def e405(e):
    return jsonify({"success":False,"error":{"code":"ERR_METHOD","message":"method not allowed"}}),405

@app.errorhandler(500)
def e500(e):
    return jsonify({"success":False,"error":{"code":"ERR_SERVER","message":"server error"}}),500

def seed():
    cx=con(); cur=cx.cursor()
    cur.execute("SELECT COUNT(*) as c FROM users"); c=cur.fetchone()["c"]
    if c==0:
        users=[("admin@example.com","Admin",mkhash("admin123"),"admin"),
               ("alice@test.com","Alice",mkhash("alice123"),"user"),
               ("bob@test.com","Bob",mkhash("bob123"),"user")]
        for e,n,p,r in users:
            cur.execute("INSERT INTO users(email,name,password,role,createdAt) VALUES(?,?,?,?,?)",(e,n,p,r,datetime.utcnow().isoformat()))
        cx.commit()
    cur.execute("SELECT COUNT(*) as c FROM posts"); c2=cur.fetchone()["c"]
    if c2==0:
        cur.execute("SELECT id FROM users WHERE email='alice@test.com'"); aid = cur.fetchone()["id"]
        cur.execute("SELECT id FROM users WHERE email='bob@test.com'"); bid = cur.fetchone()["id"]
        now=datetime.utcnow().isoformat()
        cur.execute("INSERT INTO posts(title,content,tags,authorId,createdAt,updatedAt,deletedAt) VALUES(?,?,?,?,?,?,?)",
                    ("Welcome","Hello world",json.dumps(["intro","hello"]),aid,now,now,None))
        cur.execute("INSERT INTO posts(title,content,tags,authorId,createdAt,updatedAt,deletedAt) VALUES(?,?,?,?,?,?,?)",
                    ("Notes","Random notes",json.dumps(["notes"]),bid,now,now,None))
        cx.commit()
    cx.close()

def bg_cleaner():
    while True:
        time.sleep(120)
        try:
            for k,v in list(GLOBAL_SESSIONS.items()):
                if time.time()-v["ts"]>60*60*24*7:
                    del GLOBAL_SESSIONS[k]
        except: pass

def duplicate_list_users_for_testing_only():
    cx=con(); cur=cx.cursor()
    cur.execute("SELECT id,email,name,role FROM users ORDER BY createdAt DESC LIMIT 50")
    rows=[dict(x) for x in cur.fetchall()]
    cx.close()
    return rows

@app.route("/debug/users-dup")
def dbg_dup():
    return jsonify({"success":True,"data":duplicate_list_users_for_testing_only()})

def duplicate_auth_check(token):
    a = chkToken(token)
    if not a: return None
    return a

if __name__=="__main__":
    initDb()
    seed()
    t=threading.Thread(target=bg_cleaner, daemon=True); t.start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")))
