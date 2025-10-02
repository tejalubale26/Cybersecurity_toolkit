// ---------------- Session ----------------
const user = localStorage.getItem('currentUser') || '—';
document.getElementById('userDisplay').innerText = `Signed in as ${user}`;
document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('currentUser');
    window.location.href = 'logout.html';
});

// ---------------- Local signatures helpers ----------------
const SIG_KEY = 'cyber_sigs_v1';
function loadSigs() {
    try { return JSON.parse(localStorage.getItem(SIG_KEY) || '{}'); } 
    catch(e) { return {}; }
}
function saveSigs(obj) { localStorage.setItem(SIG_KEY, JSON.stringify(obj)); }

// ---------------- Pyodide bootstrap & helpers ----------------
let pyodideReady = null;
async function ensurePyodide() {
    if(pyodideReady) return pyodideReady;
    pyodideReady = (async ()=>{
        const p = await loadPyodide({indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.24.1/full/'});
        await p.runPythonAsync(`
import hashlib, re
def md5_bytes(b):
    m = hashlib.md5()
    m.update(b)
    return m.hexdigest()
def sha256_text(text):
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()
def check_password(p):
    if len(p)>=8 and re.search(r"[a-z]",p) and re.search(r"[A-Z]",p) and re.search(r"[0-9]",p) and re.search(r"[\\W_]"):
        return "Strong"
    elif len(p)>=6:
        return "Medium"
    return "Weak"
def crack_md5(md5hash, wordlist_text):
    for w in wordlist_text.splitlines():
        if hashlib.md5(w.strip().encode()).hexdigest() == md5hash:
            return "[+] Match found: " + w.strip()
    return "[-] No match found."
`);
        return p;
    })();
    return pyodideReady;
}
async function runPyAndGetString(expr){
    const p = await ensurePyodide();
    const res = await p.runPythonAsync(expr);
    try{ 
        const s = res.toString();
        if(typeof res.destroy==='function') try{res.destroy();}catch(_){} 
        return s;
    }catch(e){ return String(res); }
}

// ---------------- Malware Scanner ----------------
const fileInput = document.getElementById('fileInput');
const scanOut = document.getElementById('scanOut');

document.getElementById('scanBtn').addEventListener('click', async ()=>{
    const f = fileInput.files[0];
    if(!f){ alert('Please upload a file to scan'); return; }
    const buffer = await f.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const py = await ensurePyodide();
    py.globals.set('js_bytes', bytes);
    const md5 = await runPyAndGetString(`md5_bytes(js_bytes.to_py())`);
    try{ py.globals.delete('js_bytes'); }catch(e){}
    const sigs = loadSigs();
    const found = Object.entries(sigs).find(([name,h]) => h===md5);
    if(found){
        const q = JSON.parse(localStorage.getItem('cyber_quarantine_v1') || '[]');
        q.push({name: f.name, md5, when: new Date().toISOString()});
        localStorage.setItem('cyber_quarantine_v1', JSON.stringify(q));
        scanOut.innerText = `[!] Malware detected and quarantined: ${found[0]}\nMD5: ${md5}`;
    } else {
        scanOut.innerText = `[-] File is clean.\nMD5: ${md5}`;
    }
});

document.getElementById('sigBtn').addEventListener('click', async ()=>{
    const f = fileInput.files[0];
    if(!f){ alert('Please upload a file to add as signature'); return; }
    const buffer = await f.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const py = await ensurePyodide();
    py.globals.set('js_bytes', bytes);
    const md5 = await runPyAndGetString(`md5_bytes(js_bytes.to_py())`);
    try{ py.globals.delete('js_bytes'); }catch(e){}
    const sigs = loadSigs();
    sigs[f.name] = md5;
    saveSigs(sigs);
    scanOut.innerText = `[+] Signature added for ${f.name}\nMD5: ${md5}`;
});

document.getElementById('exportSigs').addEventListener('click', ()=>{
    const data = JSON.stringify(loadSigs(), null, 2);
    const blob = new Blob([data], {type: 'application/json'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'signatures.json'; a.click();
    URL.revokeObjectURL(a.href);
});

document.getElementById('clearSigs').addEventListener('click', ()=>{
    if(confirm('Clear all saved signatures?')){
        localStorage.removeItem(SIG_KEY); 
        document.getElementById('scanOut').innerText = 'Signatures cleared.';
    }
});

// ---------------- Password Strength ----------------
document.getElementById('pwdBtn').addEventListener('click', async ()=>{
    const pwd = document.getElementById('pwdInput').value || '';
    const safe = JSON.stringify(pwd);
    const res = await runPyAndGetString(`check_password(${safe})`);
    document.getElementById('pwdOut').innerText = `Strength: ${res}`;
});

// ---------------- MD5 Hash Cracker ----------------
document.getElementById('crackBtn').addEventListener('click', async ()=>{
    const target = document.getElementById('md5Input').value.trim();
    const f = document.getElementById('wordlistInput').files[0];
    const out = document.getElementById('hashOut');
    if(!target){ alert('Provide an MD5 hash to crack'); return; }
    if(!f){ alert('Upload a wordlist file'); return; }
    const text = await f.text();
    const res = await runPyAndGetString(`crack_md5(${JSON.stringify(target)}, ${JSON.stringify(text)})`);
    out.innerText = res;
});

// ---------------- SHA256 Hash Generator ----------------
document.getElementById('shaBtn').addEventListener('click', async ()=>{
    const txt = document.getElementById('shaInput').value;
    if(!txt){ alert('Enter text'); return; }
    const res = await runPyAndGetString(`sha256_text(${JSON.stringify(txt)})`);
    document.getElementById('shaOut').innerText = res;
});

// ---------------- Port Scanner ----------------
const commonPorts = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",3306:"MySQL",3389:"RDP",8080:"HTTP-Alt"};
document.getElementById('portBtn').addEventListener('click', async ()=>{
    const target = document.getElementById('targetInput').value.trim();
    const outEl = document.getElementById('portOut');
    if(!target){ alert('Enter a domain or IP to probe'); return; }
    outEl.innerText = 'Scanning common ports (browser probes, CORS-limited)...\n';
    for(const p of Object.keys(commonPorts)){
        const port = Number(p);
        const service = commonPorts[port];
        const scheme = (port===443) ? 'https' : 'http';
        const url = `${scheme}://${target}${(port===80||port===443)?'':':'+port}/`;
        try{
            const controller = new AbortController();
            const id = setTimeout(()=>controller.abort(), 2500);
            await fetch(url, {method:'HEAD', mode:'no-cors', signal: controller.signal});
            clearTimeout(id);
            outEl.innerText += `[+] ${service} (${port}): Possibly OPEN\n`;
        } catch (e) {
            outEl.innerText += `[-] ${service} (${port}): Closed / Filtered\n`;
        }
    }
});

// ---------------- Network Sniffer (simulated) ----------------
let sniffInterval = null;
function randomPacket(){
    const src = `192.168.${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*255)}`;
    const dst = `93.184.${Math.floor(Math.random()*10)}.${Math.floor(Math.random()*255)}`;
    const proto = ["TCP","UDP","ICMP"][Math.floor(Math.random()*3)];
    const sport = Math.floor(Math.random()*65535);
    const dport = Math.floor(Math.random()*65535);
    return `${new Date().toLocaleTimeString()} | ${proto} | ${src}:${sport} -> ${dst}:${dport}`;
}
document.getElementById('sniffStart').addEventListener('click', ()=>{
    const out = document.getElementById('sniffOut');
    if(sniffInterval) return;
    if(out.innerText==='—') out.innerText='';
    sniffInterval = setInterval(()=>{
        out.innerText += randomPacket()+'\n';
        out.scrollTop = out.scrollHeight;
    },700);
});
document.getElementById('sniffStop').addEventListener('click', ()=>{ clearInterval(sniffInterval); sniffInterval=null; });
document.getElementById('sniffClear').addEventListener('click', ()=>{ document.getElementById('sniffOut').innerText='—'; });

// ---------------- Subnet / CIDR Calculator ----------------
document.getElementById('calcSubnetBtn').addEventListener('click', ()=>{
    const input = document.getElementById('cidrInput').value.trim();
    if(!input){ alert('Enter IP/CIDR'); return; }
    let ip='', mask='';
    if(input.includes('/')) [ip, mask] = input.split('/');
    else [ip, mask] = input.split(' ');
    if(!ip || !mask){ alert('Invalid input'); return; }
    const octets = ip.split('.').map(Number);
    if(octets.length!==4){ alert('Invalid IP'); return; }
    let cidr = mask.includes('.') ? maskToCidr(mask) : Number(mask);
    if(isNaN(cidr)){ alert('Invalid mask'); return; }
    const hostBits = 32-cidr;
    const hosts = Math.pow(2, hostBits)-2;
    document.getElementById('cidrOut').innerText = `Network: ${ip}/${cidr}\nHosts: ${hosts}`;
});
document.getElementById('clearSubnetBtn').addEventListener('click', ()=>{
    document.getElementById('cidrInput').value=''; document.getElementById('cidrOut').innerText='—';
});
function maskToCidr(mask){
    const bits = mask.split('.').map(x=>parseInt(x,10).toString(2).padStart(8,'0')).join('');
    return bits.split('1').length-1;
}

// ---------------- DNS Lookup ----------------
document.getElementById('dnsLookupBtn').addEventListener('click', async ()=>{
    const domain = document.getElementById('domainInput').value.trim();
    const type = document.getElementById('dnsType').value;
    const out = document.getElementById('dnsOut');
    if(!domain){ alert('Enter a domain'); return; }
    try{
        const res = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const json = await res.json();
        out.innerText = JSON.stringify(json, null, 2);
    }catch(e){
        out.innerText = 'Error fetching DNS info: '+e;
    }
});
