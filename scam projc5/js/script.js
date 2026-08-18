/* ============================================================
   CYBER SCAM & PHISHING DETECTOR - JAVASCRIPT ENGINE
   Complete rule-based detection engine (same logic as C program)
   ============================================================ */
'use strict';

const STORAGE_KEY = 'phishDetect_reports';

const KEYWORDS = [
    {w:'otp',s:30},{w:'password',s:30},{w:'verify',s:10},{w:'verification',s:10},{w:'urgent',s:15},{w:'immediately',s:10},
    {w:'click here',s:20},{w:'login',s:15},{w:'bank',s:10},{w:'kyc',s:20},{w:'payment',s:15},{w:'refund',s:20},
    {w:'winner',s:20},{w:'lottery',s:25},{w:'gift',s:10},{w:'free',s:10},{w:'claim',s:15},{w:'upi',s:15},
    {w:'qr code',s:20},{w:'scan',s:20},{w:'account blocked',s:30},{w:'account suspended',s:30},{w:'credit card',s:25},{w:'debit card',s:25},
    {w:'pin',s:15},{w:'limited offer',s:15},{w:'limited time',s:15},{w:'congratulations',s:20},{w:'cash prize',s:25},{w:'reward',s:20},
    {w:'security alert',s:25},{w:'suspicious activity',s:25},{w:'confirm',s:10},{w:'update',s:10},{w:'selected',s:15},{w:'won',s:15},
    {w:'prize',s:15},{w:'cashback',s:15},{w:'discount',s:10},{w:'hurry',s:10},{w:'last chance',s:15},{w:'exclusive',s:10},
    {w:'guaranteed',s:15},{w:'risk free',s:15},{w:'no cost',s:10},{w:'act now',s:15},{w:"dont miss",s:10},{w:'apply now',s:10},
    {w:'expires today',s:20},{w:'double your',s:20},{w:'earn money',s:20},{w:'dear customer',s:15},{w:'dear user',s:10},{w:'valued customer',s:10},{w:'account holder',s:10}
];

const SAFE = {
    h:['This message appears to be a SCAM. Do not respond.','Do not click any links or download attachments.','Never share personal or financial information.','Report this message to the authorities immediately.'],
    m:['This message may be suspicious. Exercise caution.','Verify the sender through official channels.','Do not make any payments based on this message alone.'],
    l:['This message appears to be safe.','Always stay vigilant against potential scams.']
};

function getTS() {
    var d = new Date();
    return String(d.getDate()).padStart(2,'0')+'/'+String(d.getMonth()+1).padStart(2,'0')+'/'+d.getFullYear()+' '+String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')+':'+String(d.getSeconds()).padStart(2,'0');
}

function analyze(t) {
    if (!t || !t.trim()) return null;
    var lc = t.toLowerCase(), r = {s:0,k:[],re:[],a:[],p:[],txt:t,ts:getTS()}, fw = [];
    for (var i = 0; i < KEYWORDS.length; i++) {
        var kw = KEYWORDS[i];
        if (lc.indexOf(kw.w) !== -1 && fw.indexOf(kw.w) === -1) {
            fw.push(kw.w); r.k.push(kw.w); r.s += kw.s;
            r.re.push('Keyword: "'+kw.w+'" (+'+kw.s+')');
        }
    }
    if (lc.indexOf('http://') !== -1) { r.s += 20; r.p.push('HTTP Link'); r.re.push('HTTP URL (+20)'); if (r.k.indexOf('http://')===-1) r.k.push('http://'); }
    if (lc.indexOf('https://') !== -1) { r.s += 15; r.p.push('HTTPS Link'); r.re.push('HTTPS URL (+15)'); if (r.k.indexOf('https://')===-1) r.k.push('https://'); }
    if (lc.indexOf('www.') !== -1) { r.s += 10; r.p.push('www'); r.re.push('www. found (+10)'); if (r.k.indexOf('www.')===-1) r.k.push('www.'); }
    var em = t.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    if (em) { r.s += 15; r.p.push('Email'); r.re.push('Email: '+em[0]+' (+15)'); if (r.k.indexOf('Email')===-1) r.k.push('Email'); }
    var dc = 0, pf = false;
    for (var i = 0; i < t.length; i++) {
        var c = t.charAt(i);
        if (c >= '0' && c <= '9') dc++;
        else if (c === '-' || c === '+' || c === ' ' || c === '(' || c === ')') continue;
        else { if (dc >= 10) pf = true; dc = 0; }
    }
    if (dc >= 10) pf = true;
    if (pf) { r.s += 15; r.p.push('Phone'); r.re.push('Phone detected (+15)'); if (r.k.indexOf('Phone')===-1) r.k.push('Phone'); }
    var ex = t.match(/!{3,}/g);
    if (ex) { var mx = 0; for (var i = 0; i < ex.length; i++) if (ex[i].length > mx) mx = ex[i].length; var es = mx * 3; if (es > 20) es = 20; r.s += es; r.p.push('Excessive !!!'); r.re.push(mx+' exclamation marks (+'+es+')'); if (r.k.indexOf('!!!')===-1) r.k.push('!!!'); }
    var cw = t.match(/\b[A-Z]{3,}\b/g);
    if (cw && cw.length >= 2) { var cs = cw.length * 5; if (cs > 25) cs = 25; r.s += cs; r.p.push('ALL CAPS'); r.re.push(cw.length+' CAPS words (+'+cs+')'); if (r.k.indexOf('ALL CAPS')===-1) r.k.push('ALL CAPS'); }
    var syms = ['$','\u20AC','\u00A3','\u20B9','\u00A5']; var sc = 0;
    for (var i = 0; i < t.length; i++) { for (var s = 0; s < syms.length; s++) { if (t.charAt(i) === syms[s]) sc++; } }
    if (sc > 0) { var cs2 = sc * 8; if (cs2 > 20) cs2 = 20; r.s += cs2; r.p.push('Currency'); r.re.push(sc+' currency symbols (+'+cs2+')'); if (r.k.indexOf('Currency')===-1) r.k.push('Currency'); }
    var urls = t.match(/https?:\/\/[^\s]+/g) || [];
    var sd = ['free','win','lucky','prize','claim','reward','bonus','cash','money','gift','secure','verify','update','confirm','login','account'];
    for (var u = 0; u < urls.length; u++) { for (var d = 0; d < sd.length; d++) { if (urls[u].indexOf(sd[d]) !== -1) { r.s += 10; r.p.push('Suspicious URL'); r.re.push('Suspicious URL with "'+sd[d]+'" (+10)'); if (r.k.indexOf('Suspicious URL')===-1) r.k.push('Suspicious URL'); d = sd.length; } } }
    var gr = ['dear customer','dear user','dear account holder','valued customer'];
    for (var g = 0; g < gr.length; g++) { if (lc.indexOf(gr[g]) !== -1) { r.s += 10; r.p.push('Phishing Greeting'); r.re.push('Greeting "'+gr[g]+'" (+10)'); if (r.k.indexOf('Phishing greeting')===-1) r.k.push('Phishing greeting'); break; } }
    if (r.s < 0) r.s = 0; if (r.s > 100) r.s = 100;
    if (r.s <= 30) { r.l = 'LOW RISK'; r.lc = 'l'; } else if (r.s <= 60) { r.l = 'MEDIUM RISK'; r.lc = 'm'; } else { r.l = 'HIGH RISK'; r.lc = 'h'; }
    var ga = SAFE[r.lc]; for (var i = 0; i < ga.length; i++) r.a.push(ga[i]);
    var ak = r.k.join(' ').toLowerCase();
    if (ak.indexOf('otp')!==-1) r.a.push('Never share OTP with anyone.');
    if (ak.indexOf('password')!==-1) r.a.push('Never share passwords. Legitimate companies never ask.');
    if (ak.indexOf('kyc')!==-1) r.a.push('Verify KYC through official website.');
    if (ak.indexOf('lottery')!==-1||ak.indexOf('winner')!==-1||ak.indexOf('prize')!==-1) r.a.push('You cannot win a lottery you did not enter.');
    if (ak.indexOf('urgent')!==-1||ak.indexOf('immediately')!==-1) r.a.push('Scammers create false urgency to rush you.');
    if (ak.indexOf('account blocked')!==-1||ak.indexOf('account suspended')!==-1) r.a.push('Contact your bank directly.');
    if (ak.indexOf('payment')!==-1||ak.indexOf('refund')!==-1) r.a.push('Be cautious of money-related messages.');
    if (r.p.indexOf('HTTP Link')!==-1||r.p.indexOf('HTTPS Link')!==-1) r.a.push('Always verify URLs before clicking.');
    var ua = []; for (var i = 0; i < r.a.length; i++) { if (ua.indexOf(r.a[i])===-1) ua.push(r.a[i]); } r.a = ua;
    if (r.lc === 'h') r.rec = 'DANGER: Multiple scam indicators. DO NOT respond or click links.';
    else if (r.lc === 'm') r.rec = 'CAUTION: Suspicious patterns. Verify before acting.';
    else r.rec = 'SAFE: No significant scam indicators. Stay vigilant.';
    return r;
}

function save(r) {
    try { var rs = getR(); rs.unshift({id:Date.now(),ts:r.ts,s:r.s,l:r.l,lc:r.lc,k:r.k,re:r.re,a:r.a,p:r.p,rec:r.rec,txt:r.txt.substring(0,500)}); localStorage.setItem(STORAGE_KEY, JSON.stringify(rs)); return true; } catch(e) { return false; }
}
function getR() { try { var d = localStorage.getItem(STORAGE_KEY); return d ? JSON.parse(d) : []; } catch(e) { return []; } }
function clearR() { localStorage.removeItem(STORAGE_KEY); }
function getStats() { var r = getR(), s = {t:r.length,h:0,m:0,l:0}; for (var i = 0; i < r.length; i++) { if (r[i].lc==='h') s.h++; else if (r[i].lc==='m') s.m++; else s.l++; } return s; }

function showRes(r) {
    document.getElementById('scoreValue').textContent = r.s;
    var ring = document.getElementById('scoreRingProgress'), circ = 339.292;
    ring.style.strokeDashoffset = circ - (r.s/100)*circ;
    var col = r.lc==='h'?'#ef4444':r.lc==='m'?'#f59e0b':'#10b981';
    ring.style.stroke = col;
    document.getElementById('resultLevel').textContent = r.l;
    document.getElementById('resultLevel').style.color = col;
    var b = document.getElementById('resultBadge');
    if (r.lc === 'h') { b.innerHTML = '<i class="fas fa-circle-exclamation"></i> Likely Scam'; b.style.cssText = 'background:rgba(239,68,68,0.15);color:#ef4444;border:1px solid rgba(239,68,68,0.3)'; }
    else if (r.lc === 'm') { b.innerHTML = '<i class="fas fa-triangle-exclamation"></i> Suspicious'; b.style.cssText = 'background:rgba(245,158,11,0.15);color:#f59e0b;border:1px solid rgba(245,158,11,0.3)'; }
    else { b.innerHTML = '<i class="fas fa-shield"></i> Safe'; b.style.cssText = 'background:rgba(16,185,129,0.15);color:#10b981;border:1px solid rgba(16,185,129,0.3)'; }
    var kw = document.getElementById('detectedKeywords'); kw.innerHTML = '';
    if (r.k.length === 0) kw.innerHTML = '<span class="no-data">No suspicious keywords detected.</span>';
    else { for (var i = 0; i < r.k.length; i++) { var t = document.createElement('span'); t.className = 'keyword-tag'; t.textContent = r.k[i]; kw.appendChild(t); } }
    var re = document.getElementById('detectedReasons'); re.innerHTML = '';
    if (r.re.length === 0) re.innerHTML = '<span class="no-data">No suspicious patterns detected.</span>';
    else { for (var i = 0; i < r.re.length; i++) { var it = document.createElement('div'); it.className = 'reason-item'; it.textContent = '* '+r.re[i]; re.appendChild(it); } }
    var ad = document.getElementById('safetyAdvice'); ad.innerHTML = '';
    for (var i = 0; i < r.a.length; i++) { var a = document.createElement('div'); a.className = 'advice-item'; a.innerHTML = '<i class="fas fa-check-circle"></i> '+r.a[i]; ad.appendChild(a); }
    var icon = r.lc==='h'?'ban':r.lc==='m'?'exclamation-triangle':'check-circle';
    var cls = r.lc==='h'?'danger':r.lc==='m'?'warning':'safe';
    document.getElementById('finalRecommendation').innerHTML = '<div class="recommendation '+cls+'"><i class="fas fa-'+icon+'"></i> '+r.rec+'</div>';
    document.getElementById('resultPanel').style.display = 'block';
    document.getElementById('copyResultBtn').disabled = false;
    document.getElementById('analyzer').classList.add('allows-scroll');
    window._lr = r;
}

function showReps() {
    var list = document.getElementById('reportsList'), rs = getR();
    document.getElementById('reportsCount').textContent = rs.length+' report'+(rs.length!==1?'s':'');
    if (rs.length === 0) { list.innerHTML = '<div class="no-reports"><i class="fas fa-folder-open"></i><h3>No Reports Yet</h3><p>Analyze a message to see reports.</p><a href="#analyzer" class="btn btn-primary"><i class="fas fa-microscope"></i> Analyze Now</a></div>'; return; }
    var h = '';
    for (var i = 0; i < rs.length; i++) {
        var r = rs[i];
        h += '<div class="report-card"><div class="report-card-header"><div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;"><span class="report-date"><i class="fas fa-clock"></i> '+r.ts+'</span><span class="report-level '+(r.lc==='h'?'high':r.lc==='m'?'medium':'low')+'">'+r.l+'</span></div><span class="report-score">'+r.s+'/100</span></div><div class="report-message">'+r.txt+'</div>';
    }
    list.innerHTML = h;
}

function showStats() {
    var s = getStats();
    document.querySelector('#statTotal .stat-card-value').textContent = s.t;
    document.querySelector('#statHigh .stat-card-value').textContent = s.h;
    document.querySelector('#statMedium .stat-card-value').textContent = s.m;
    document.querySelector('#statLow .stat-card-value').textContent = s.l;
    var mv = Math.max(s.h, s.m, s.l, 1);
    document.getElementById('chartHigh').style.width = (s.h/mv*100)+'%';
    document.getElementById('chartMedium').style.width = (s.m/mv*100)+'%';
    document.getElementById('chartLow').style.width = (s.l/mv*100)+'%';
    document.getElementById('chartHighVal').textContent = s.h;
    document.getElementById('chartMediumVal').textContent = s.m;
    document.getElementById('chartLowVal').textContent = s.l;
}

function toast(msg, type, dur) {
    type = type || 'info'; dur = dur || 3000;
    var c = document.getElementById('toastContainer');
    var t = document.createElement('div'); t.className = 'toast '+type;
    var icons = {success:'fa-check-circle',error:'fa-circle-exclamation',info:'fa-info-circle',warning:'fa-triangle-exclamation'};
    t.innerHTML = '<span class="toast-icon"><i class="fas '+(icons[type]||icons.info)+'"></i></span><span class="toast-message">'+msg+'</span><span class="toast-close"><i class="fas fa-xmark"></i></span>';
    c.appendChild(t);
    t.querySelector('.toast-close').addEventListener('click', function() { t.classList.add('removing'); setTimeout(function(){ t.remove(); }, 300); });
    setTimeout(function() { if (t.parentNode) { t.classList.add('removing'); setTimeout(function(){ t.remove(); }, 300); } }, dur);
}

function copyRes(r) {
    if (!r) { toast('No result to copy!','warning'); return; }
    var txt = '=== PHISHING DETECTOR REPORT ===\nDate: '+r.ts+'\nScore: '+r.s+'/100\nLevel: '+r.l+'\n\nKeywords:\n';
    for (var i = 0; i < r.k.length; i++) txt += '- '+r.k[i]+'\n';
    txt += '\nReasons:\n'; for (var i = 0; i < r.re.length; i++) txt += '- '+r.re[i]+'\n';
    txt += '\nAdvice:\n'; for (var i = 0; i < r.a.length; i++) txt += '- '+r.a[i]+'\n';
    txt += '\n--- '+r.rec+' ---\n';
    navigator.clipboard.writeText(txt).then(function(){ toast('Copied!','success'); }).catch(function(){ toast('Copy failed!','error'); });
}

function dlPDF(r) {
    if (!r) { toast('No result!','warning'); return; }
    var h = '<html><head><title>Phishing Report</title><style>body{font-family:Arial;padding:20px}h1{color:#0d1117;border-bottom:3px solid #00d4ff}.box{background:#f5f5f5;padding:10px;margin:10px 0}li{margin:5px 0}</style></head><body>';
    h += '<h1>Phishing Detector Report</h1><p><b>Date:</b> '+r.ts+'</p><p><b>Score:</b> '+r.s+'/100</p><p><b>Level:</b> '+r.l+'</p>';
    h += '<hr><h3>Keywords</h3><p>'+(r.k.length?r.k.join(', '):'None')+'</p>';
    h += '<hr><h3>Reasons</h3><ul>'; for (var i = 0; i < r.re.length; i++) h += '<li>'+r.re[i]+'</li>'; h += '</ul>';
    h += '<hr><h3>Advice</h3><ul>'; for (var i = 0; i < r.a.length; i++) h += '<li>'+r.a[i]+'</li>'; h += '</ul>';
    h += '<hr><h3>Message</h3><div class="box">'+r.txt+'</div>';
    h += '<hr><small>Generated by Cyber Scam & Phishing Detector</small></body></html>';
    var w = window.open('','_blank'); w.document.write(h); w.document.close();
    setTimeout(function(){ w.print(); }, 500);
}

// Initialize everything
document.addEventListener('DOMContentLoaded', function() {
    // Loading screen
    setTimeout(function() {
var ls = document.getElementById('loading-screen');
        if (ls) { ls.classList.add('hidden'); setTimeout(function() { ls.style.display = 'none'; }, 500); }
    }, 1500);

    // Matrix rain
    var cnv = document.createElement('canvas');
    var ct = document.getElementById('matrixRain');
    if (ct) {
        ct.appendChild(cnv);
        cnv.width = ct.offsetWidth; cnv.height = ct.offsetHeight;
        var ctx = cnv.getContext('2d');
        var ch = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789';
        var fs = 14, cols = Math.floor(cnv.width/fs), drops = [];
        for (var i = 0; i < cols; i++) drops[i] = Math.floor(Math.random()*cnv.height/fs);
        setInterval(function() {
            ctx.fillStyle = 'rgba(10,14,26,0.05)'; ctx.fillRect(0,0,cnv.width,cnv.height);
            ctx.fillStyle = '#00d4ff'; ctx.font = fs+'px monospace';
            for (var i = 0; i < drops.length; i++) {
                ctx.fillText(ch.charAt(Math.floor(Math.random()*ch.length)), i*fs, drops[i]*fs);
                if (drops[i]*fs > cnv.height && Math.random() > 0.975) drops[i] = 0;
                drops[i]++;
            }
        }, 50);
        window.addEventListener('resize', function() { cnv.width = ct.offsetWidth; cnv.height = ct.offsetHeight; });
    }

    // Typewriter
    var tw = document.getElementById('typewriter');
    if (tw) {
        var phrases = ['Phishing Attempts','Lottery Scams','KYC Frauds','QR Code Scams','Banking Frauds','OTP Phishing'];
        var pi = 0, ci = 0, del = false, speed = 100;
        setTimeout(function type() {
            var cur = phrases[pi];
            tw.textContent = del ? cur.substring(0, ci-1) : cur.substring(0, ci+1);
            del ? ci-- : ci++;
            if (!del && ci === cur.length) { del = true; setTimeout(type, 2000); return; }
            if (del && ci === 0) { del = false; pi = (pi+1)%phrases.length; setTimeout(type, 500); return; }
            setTimeout(type, del ? 50 : speed);
        }, 3000);
    }

    // Navbar
    var nt = document.getElementById('navToggle'), nm = document.getElementById('navMenu');
    if (nt) { nt.addEventListener('click', function() { nt.classList.toggle('active'); nm.classList.toggle('active'); }); }
    document.querySelectorAll('.nav-link').forEach(function(l) {
        l.addEventListener('click', function() { if (nt) nt.classList.remove('active'); if (nm) nm.classList.remove('active'); });
    });

    // Horizontal slide navigation
    var st = document.getElementById('slidesTrack');
    var sl = st ? Array.prototype.slice.call(st.querySelectorAll('.slide')) : [];
    if (st && sl.length) {
        var si = 0;
        var ps = document.getElementById('prevSlide');
        var ns = document.getElementById('nextSlide');
        var ss = document.getElementById('slideStatus');
        var touchStartX = null;

        function slideIndexForId(id) {
            for (var i = 0; i < sl.length; i++) if (sl[i].id === id) return i;
            return -1;
        }

        function goToSlide(index, updateUrl) {
            if (index < 0) index = 0;
            if (index >= sl.length) index = sl.length - 1;
            si = index;
            st.style.transform = 'translateX(-' + (si * 100) + '%)';

            for (var i = 0; i < sl.length; i++) {
                var isActive = i === si;
                sl[i].setAttribute('aria-hidden', isActive ? 'false' : 'true');
                sl[i].inert = !isActive;
            }

            sl[si].scrollTop = 0;
            if (ps) ps.disabled = si === 0;
            if (ns) ns.disabled = si === sl.length - 1;
            if (ss) ss.textContent = (si + 1) + ' / ' + sl.length;

            document.querySelectorAll('.nav-link').forEach(function(link) {
                link.classList.toggle('active', link.getAttribute('href') === '#' + sl[si].id);
            });

            if (updateUrl && window.location.hash !== '#' + sl[si].id) {
                history.pushState(null, '', '#' + sl[si].id);
            }
        }

        function goToHash() {
            var id = window.location.hash.slice(1);
            var index = slideIndexForId(id);
            goToSlide(index === -1 ? 0 : index, false);
        }

        if (ps) ps.addEventListener('click', function() { goToSlide(si - 1, true); });
        if (ns) ns.addEventListener('click', function() { goToSlide(si + 1, true); });

        document.querySelectorAll('a[href^="#"]').forEach(function(link) {
            link.addEventListener('click', function(e) {
                var index = slideIndexForId(link.getAttribute('href').slice(1));
                if (index !== -1) { e.preventDefault(); goToSlide(index, true); }
            });
        });

        document.addEventListener('keydown', function(e) {
            var tag = e.target.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || e.target.isContentEditable) return;
            if (e.key === 'ArrowLeft') { e.preventDefault(); goToSlide(si - 1, true); }
            if (e.key === 'ArrowRight') { e.preventDefault(); goToSlide(si + 1, true); }
        });

        st.addEventListener('touchstart', function(e) { touchStartX = e.changedTouches[0].clientX; }, {passive:true});
        st.addEventListener('touchend', function(e) {
            if (touchStartX === null) return;
            var distance = e.changedTouches[0].clientX - touchStartX;
            touchStartX = null;
            if (Math.abs(distance) < 50) return;
            goToSlide(si + (distance < 0 ? 1 : -1), true);
        }, {passive:true});

        window.addEventListener('hashchange', goToHash);
        window.addEventListener('popstate', goToHash);
        goToHash();
    }

    // Theme
    var tt = document.getElementById('themeToggle');
    if (tt) {
        var ti = tt.querySelector('i');
        if (localStorage.getItem('phishDetect_theme') === 'light') { document.documentElement.setAttribute('data-theme','light'); ti.className = 'fas fa-sun'; }
        tt.addEventListener('click', function() {
            if (document.documentElement.getAttribute('data-theme') === 'light') {
                document.documentElement.removeAttribute('data-theme'); ti.className = 'fas fa-moon';
                localStorage.setItem('phishDetect_theme','dark');
            } else {
                document.documentElement.setAttribute('data-theme','light'); ti.className = 'fas fa-sun';
                localStorage.setItem('phishDetect_theme','light');
            }
        });
    }

    // Scroll to top
    var sb = document.getElementById('scrollTopBtn');
    if (sb) {
        window.addEventListener('scroll', function() { sb.classList.toggle('visible', window.scrollY > 500); });
        sb.addEventListener('click', function() { window.scrollTo({top:0, behavior:'smooth'}); });
    }

    // Char counter
    var ip = document.getElementById('messageInput'), cc = document.getElementById('charCount');
    if (ip && cc) { ip.addEventListener('input', function() { cc.textContent = this.value.length; }); }

    // Analyze button
    var ab = document.getElementById('analyzeBtn');
    if (ab) {
        ab.addEventListener('click', function() {
            var txt = ip.value.trim();
            if (!txt) { toast('Please enter a message!','warning'); return; }
            ab.disabled = true; ab.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
            setTimeout(function() {
                var r = analyze(txt);
                if (r) { showRes(r); toast('Analysis complete!','success'); }
                ab.disabled = false; ab.innerHTML = '<i class="fas fa-microscope"></i> Analyze Message';
            }, 600);
        });
    }

    // Clear button
    var cb = document.getElementById('clearBtn');
    if (cb) {
        cb.addEventListener('click', function() {
            ip.value = ''; cc.textContent = '0';
            document.getElementById('resultPanel').style.display = 'none';
            document.getElementById('copyResultBtn').disabled = true;
            document.getElementById('analyzer').classList.remove('allows-scroll');
            window._lr = null;
        });
    }

    // Example buttons - use hardcoded examples
    var EX = [
        {t:'Bank Phishing',x:'Dear Customer, your bank account has been blocked due to suspicious activity. Click here to verify your KYC immediately. http://fake-bank-verify.com'},
        {t:'Lottery Scam',x:'CONGRATULATIONS! You have WON $1,000,000 in our international lottery!!! Claim your prize now! LIMITED TIME! ACT NOW!'},
        {t:'KYC Update',x:'URGENT: Your account will be suspended in 24 hours. Update your KYC immediately. Click here: https://bit.ly/kyc-update'},
        {t:'Normal Message',x:'Hi, how are you doing? Are we still meeting for lunch tomorrow at 1pm? Let me know!'}
    ];
    var lb = document.getElementById('loadExampleBtn');
    if (lb) {
        lb.addEventListener('click', function() {
            var ri = Math.floor(Math.random()*EX.length);
            ip.value = EX[ri].x; cc.textContent = ip.value.length;
            toast('Loaded: '+EX[ri].t, 'info');
        });
    }

    // Copy buttons
    var cp = document.getElementById('copyResultBtn'), cp2 = document.getElementById('copyResultBtn2');
    if (cp) cp.addEventListener('click', function() { copyRes(window._lr); });
    if (cp2) cp2.addEventListener('click', function() { copyRes(window._lr); });

    // Save report
    var sv = document.getElementById('saveReportBtn');
    if (sv) sv.addEventListener('click', function() { if (window._lr && save(window._lr)) toast('Report saved!','success'); else toast('No result!','warning'); });

    // PDF download
    var pdf = document.getElementById('downloadPdfBtn');
    if (pdf) pdf.addEventListener('click', function() { dlPDF(window._lr); });

    // Reports
    var rf = document.getElementById('refreshReportsBtn');
    if (rf) rf.addEventListener('click', function() { showReps(); toast('Refreshed!','info'); });
    var ch = document.getElementById('clearHistoryBtn');
    if (ch) ch.addEventListener('click', function() { if (confirm('Clear all history?')) { clearR(); showReps(); showStats(); toast('Cleared!','success'); } });

    // Initial display
    showReps(); showStats();
});
