/* ═══════════════════════════════════════════════════════════
   PhishGuard AI — Frontend Logic
   • Real-time URL scanning
   • Audio alerts via Web Audio API
   • Visual overlay alerts (safe / phishing)
   • Risk gauge + ring animations
   ═══════════════════════════════════════════════════════════ */

// ── Audio Engine ──────────────────────────────────────────────────────────────
const Audio = (function(){
  let ctx = null;
  function getCtx(){
    if(!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
    return ctx;
  }

  function tone(freq, type, duration, gain, delay=0){
    const c    = getCtx();
    const osc  = c.createOscillator();
    const gn   = c.createGain();
    osc.connect(gn); gn.connect(c.destination);
    osc.type        = type;
    osc.frequency.setValueAtTime(freq, c.currentTime + delay);
    gn.gain.setValueAtTime(0, c.currentTime + delay);
    gn.gain.linearRampToValueAtTime(gain, c.currentTime + delay + 0.02);
    gn.gain.exponentialRampToValueAtTime(0.0001, c.currentTime + delay + duration);
    osc.start(c.currentTime + delay);
    osc.stop(c.currentTime + delay + duration + 0.05);
  }

  return {
    safe(){
      // Ascending bright chord — "all clear"
      tone(523.25, 'sine', .25, .18, 0);
      tone(659.25, 'sine', .25, .14, .12);
      tone(783.99, 'sine', .35, .18, .24);
      tone(1046.5, 'sine', .40, .14, .36);
    },
    phishing(){
      // Descending minor alarm
      tone(880,  'sawtooth', .15, .12, 0);
      tone(784,  'sawtooth', .15, .12, .16);
      tone(698,  'sawtooth', .15, .12, .32);
      tone(523,  'sawtooth', .30, .16, .48);
      // Pulse
      tone(220, 'square', .08, .08, .85);
      tone(220, 'square', .08, .08, 1.00);
      tone(220, 'square', .08, .08, 1.15);
    },
    scanning(){
      tone(400, 'sine', .08, .06, 0);
      tone(600, 'sine', .08, .06, .1);
      tone(400, 'sine', .08, .06, .2);
    }
  };
})();


// ── Alert Overlay ─────────────────────────────────────────────────────────────
const Overlay = (function(){
  const overlay      = document.getElementById('alertOverlay');
  const iconEl       = document.getElementById('alertIcon');
  const titleEl      = document.getElementById('alertTitle');
  const urlEl        = document.getElementById('alertUrl');
  const riskNumEl    = document.getElementById('riskNumber');
  const ringFill     = document.getElementById('ringFill');
  const featuresEl   = document.getElementById('alertFeatures');
  const dismissBtn   = document.getElementById('dismissBtn');

  if(dismissBtn){
    dismissBtn.addEventListener('click', hide);
    document.addEventListener('keydown', e => { if(e.key==='Escape') hide(); });
  }

  function show(data){
    if(!overlay) return;
    const isPhish = data.label === 'phishing';
    const risk    = data.risk_percentage;

    overlay.className = 'alert-overlay ' + (isPhish ? 'phish-overlay' : 'safe-overlay');

    iconEl.textContent  = isPhish ? '🚨' : '✅';
    titleEl.textContent = isPhish ? 'PHISHING DETECTED' : 'WEBSITE IS SAFE';
    titleEl.style.color = isPhish ? 'var(--red)' : 'var(--green)';
    urlEl.textContent   = data.url;

    // Animate risk ring
    riskNumEl.textContent = 0;
    const circum = 314; // 2π*50
    ringFill.style.stroke = isPhish ? 'var(--red)' : 'var(--green)';
    ringFill.style.strokeDashoffset = circum;

    let current = 0;
    const target = risk;
    const step   = target / 50;
    const timer  = setInterval(()=>{
      current = Math.min(current + step, target);
      riskNumEl.textContent = Math.round(current);
      ringFill.style.strokeDashoffset = circum - (current/100)*circum;
      if(current >= target) clearInterval(timer);
    }, 16);

    // Feature chips
    featuresEl.innerHTML = '';
    const features = data.features || {};
    const badKeys  = ['Has IP Address','Has @ Symbol','Hex Encoding'];
    const goodKeys = ['Uses HTTPS','Trusted TLD'];
    Object.entries(features).forEach(([k,v])=>{
      const chip = document.createElement('span');
      chip.className = 'af-chip';
      if(badKeys.includes(k) && v===true)   chip.className += ' bad';
      if(goodKeys.includes(k) && v===true)  chip.className += ' good';
      if(k==='Suspicious Keywords' && v>0)  chip.className += ' bad';
      chip.textContent = `${k}: ${typeof v==='boolean'?(v?'Yes':'No'):v}`;
      featuresEl.appendChild(chip);
    });

    overlay.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  function hide(){
    if(!overlay) return;
    overlay.classList.add('hidden');
    document.body.style.overflow = '';
  }

  return { show, hide };
})();


// ── Scanner UI ────────────────────────────────────────────────────────────────
(function(){
  const urlInput     = document.getElementById('urlInput');
  const scanBtn      = document.getElementById('scanBtn');
  const scanBtnText  = document.getElementById('scanBtnText');
  const resultPanel  = document.getElementById('resultPanel');
  const scanningAnim = document.getElementById('scanningAnim');
  const resultBadge  = document.getElementById('resultBadge');
  const resultUrlEl  = document.getElementById('resultUrl');
  const resultTimeEl = document.getElementById('resultTime');
  const gaugeBar     = document.getElementById('gaugeBar');
  const gaugeNum     = document.getElementById('gaugeNumber');
  const featureGrid  = document.getElementById('featureGrid');

  if(!urlInput) return; // not on checker page

  // Enter key
  urlInput.addEventListener('keydown', e => { if(e.key==='Enter') doScan(); });
  scanBtn.addEventListener('click', doScan);

  async function doScan(){
    const raw = urlInput.value.trim();
    if(!raw){ shake(urlInput); return; }

    let url = raw;
    if(!url.startsWith('http://') && !url.startsWith('https://'))
      url = 'https://' + url;

    setLoading(true);
    Audio.scanning();

    try{
      const res  = await fetch('/api/scan', {
        method:  'POST',
        headers: { 'Content-Type':'application/json' },
        body:    JSON.stringify({ url })
      });
      const data = await res.json();
      if(!res.ok) throw new Error(data.error || 'Scan failed');

      renderResult(data);

      // Flash background
      flashBackground(data.label);

      // Sound
      if(data.label === 'phishing') Audio.phishing();
      else                          Audio.safe();

      // Show overlay after tiny delay for drama
      setTimeout(()=> Overlay.show(data), 300);

    } catch(err){
      showError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function renderResult(data){
    const isPhish = data.label === 'phishing';
    const risk    = data.risk_percentage;

    // Panel
    resultPanel.classList.remove('hidden');
    scanningAnim.classList.add('hidden');

    resultBadge.className = 'result-badge ' + (isPhish ? 'phish-badge' : 'safe-badge');
    resultBadge.textContent = isPhish ? '⚠ PHISHING' : '✓ SAFE';

    resultUrlEl.textContent  = data.url;
    resultTimeEl.textContent = new Date(data.timestamp).toLocaleString();

    // Gauge
    const gaugeColor = risk > 60 ? 'var(--red)' : risk > 30 ? 'var(--amber)' : 'var(--green)';
    gaugeBar.style.width      = '0%';
    gaugeBar.style.background = gaugeColor;
    gaugeNum.textContent      = '0%';
    gaugeNum.style.color      = gaugeColor;

    setTimeout(()=>{
      gaugeBar.style.width  = risk + '%';
      gaugeNum.textContent  = risk + '%';
      animateCount(gaugeNum, 0, risk, '%');
    }, 50);

    // Feature grid
    featureGrid.innerHTML = '';
    const features = data.features || {};
    Object.entries(features).forEach(([k,v])=>{
      const item = document.createElement('div');
      item.className = 'feature-item';

      let cls = 'fv-neutral';
      if(typeof v === 'boolean'){
        const isBad  = ['Has IP Address','Has @ Symbol','Hex Encoding'].includes(k);
        const isGood = ['Uses HTTPS','Trusted TLD'].includes(k);
        if(isBad)  cls = v ? 'fv-bad' : 'fv-good';
        if(isGood) cls = v ? 'fv-good': 'fv-bad';
      } else if(typeof v === 'number'){
        if(k === 'Suspicious Keywords') cls = v > 0 ? 'fv-bad' : 'fv-good';
        else if(k === 'Subdomains')     cls = v > 2 ? 'fv-bad' : v > 0 ? 'fv-warn' : 'fv-good';
        else if(k === 'URL Length')     cls = v > 75 ? 'fv-bad' : v > 54 ? 'fv-warn' : 'fv-good';
      }

      item.innerHTML = `
        <div class="feature-name">${k}</div>
        <div class="feature-value ${cls}">${typeof v==='boolean'?(v?'Yes':'No'):v}</div>`;
      featureGrid.appendChild(item);
    });
  }

  function flashBackground(label){
    const body = document.body;
    const color = label === 'phishing'
      ? 'rgba(255,23,68,.07)'
      : 'rgba(0,230,118,.06)';
    body.style.transition    = 'background-color .3s ease';
    body.style.backgroundColor = color;
    setTimeout(()=>{ body.style.backgroundColor = ''; }, 1200);
  }

  function setLoading(on){
    if(on){
      resultPanel.classList.add('hidden');
      scanningAnim.classList.remove('hidden');
      scanBtnText.textContent = '…';
      scanBtn.disabled = true;
    } else {
      scanningAnim.classList.add('hidden');
      scanBtnText.textContent = 'SCAN';
      scanBtn.disabled = false;
    }
  }

  function showError(msg){
    resultPanel.classList.remove('hidden');
    resultBadge.className   = 'result-badge phish-badge';
    resultBadge.textContent = '⚠ ERROR';
    resultUrlEl.textContent = msg;
    resultTimeEl.textContent = '';
    if(gaugeBar) gaugeBar.style.width = '0%';
    if(featureGrid) featureGrid.innerHTML = '';
  }

  function shake(el){
    el.style.animation = 'none';
    void el.offsetWidth;
    el.style.animation = 'shake .4s ease';
  }

  function animateCount(el, from, to, suffix=''){
    const dur  = 600;
    const start= performance.now();
    function frame(now){
      const t = Math.min((now-start)/dur, 1);
      el.textContent = Math.round(from + (to-from)*easeOut(t)) + suffix;
      if(t<1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }
  function easeOut(t){ return 1 - Math.pow(1-t, 3); }

})();


// ── Keyframe for shake ─────────────────────────────────────────────────────────
(function(){
  const style = document.createElement('style');
  style.textContent = `
    @keyframes shake {
      0%,100%{ transform:translateX(0) }
      20%{ transform:translateX(-8px) }
      40%{ transform:translateX(8px) }
      60%{ transform:translateX(-5px) }
      80%{ transform:translateX(5px) }
    }`;
  document.head.appendChild(style);
})();
