// Story generator for «پنجشنبه‌های مهرورزی» — مهر جاوید
// usage: node gen.js <variantNumber> <out.jpg>
// variantNumber picks palette, illustration, decoration and text, so every week differs.
const path = require('path');
const fs = require('fs');
const { chromium } = require('playwright');

const KIT = __dirname;
const CARD = '۶۰۳۷ ۹۹۷۹ ۵۰۲۹ ۵۲۳۹';

const PALETTES = [
  { name: 'olive',      bg: '#3F4F1E', bg2: '#4D5F27', acc: '#E3CC3C', accInk: '#2E3A12', light: '#F6F3E2', leaf1: '#9DB548', leaf2: '#C9D44A' },
  { name: 'teal-gold',  bg: '#0E3B33', bg2: '#15493F', acc: '#E3BF73', accInk: '#0E3B33', light: '#F6F1E7', leaf1: '#3F7D5C', leaf2: '#7FAF7E' },
  { name: 'burgundy',   bg: '#4A1F2A', bg2: '#5A2834', acc: '#F0C27B', accInk: '#4A1F2A', light: '#FBF1E6', leaf1: '#8E4D5B', leaf2: '#C98A93' },
  { name: 'navy-sand',  bg: '#1D2E4A', bg2: '#25395A', acc: '#E9C88B', accInk: '#1D2E4A', light: '#F4EFE6', leaf1: '#5C7AA6', leaf2: '#9DB3D3' },
  { name: 'forest',     bg: '#24432F', bg2: '#2D5139', acc: '#F2D06B', accInk: '#24432F', light: '#F3F5EC', leaf1: '#5E9A62', leaf2: '#A5C97A' },
  { name: 'plum',       bg: '#3B2A4A', bg2: '#47355A', acc: '#EBC97F', accInk: '#3B2A4A', light: '#F6F0F7', leaf1: '#7E6A9E', leaf2: '#B7A6D1' },
];

const TEXTS = [
  { kicker: 'به نیت عزیزان آسمانی', head: ['مهرِ شما، ', 'درمانِ آن‌ها'] , body: 'خیرات این پنجشنبه را به نیت شادی روح عزیزانتان، هرچقدر که دلتان خواست، به صندوق مهر جاوید بسپارید تا صرف درمان مددجویان نیازمند شود.' },
  { kicker: 'پنجشنبه است؛ یادشان کنیم', head: ['خیراتی که ', 'درمان می‌شود'], body: 'به یاد پدر و مادر و عزیزانی که دیگر کنارمان نیستند، هر مبلغی که از دلتان برآمد، دارو و درمانی می‌شود برای یک بیمار نیازمند.' },
  { kicker: 'یادشان سبز، روحشان شاد', head: ['به یاد رفتگان، ', 'برای ماندگان'], body: 'کمک کوچک شما در صندوق مهر جاوید، باری از دوش یک بیمار برمی‌دارد و ثوابش هدیه‌ای است به روح عزیزانتان.' },
  { kicker: 'خیرات پنجشنبه', head: ['ثوابش برای آن‌ها، ', 'شفایش برای اینان'], body: 'برای دل خودتان و به نیت اموات‌تان، هر مبلغی که خواستید به ما بسپارید تا هزینه درمان مددجویان نیازمند تأمین شود.' },
  { kicker: 'با یک فاتحه و یک خیر', head: ['دعای بیمار، ', 'هدیه به روح عزیزتان'], body: 'وقتی هزینه درمان یک بیمار را سبک می‌کنید، دعای خیرش بدرقه راه عزیزان آسمانی‌تان می‌شود.' },
  { kicker: 'پنجشنبه‌ها، وقت یاد عزیزان', head: ['هر مبلغ، ', 'یک امید تازه'], body: 'لازم نیست زیاد باشد؛ همان که از دلتان برمی‌آید، به نیت رفتگانتان، صرف درمان نیازمندان می‌شود.' },
  { kicker: 'به نیت شادی روح', head: ['مهرتان را ', 'ماندگار کنید'], body: 'یاد عزیزان رفته را با کمک به بیماران نیازمند زنده نگه دارید؛ صندوق مهر جاوید امانت‌دار خیرات شماست.' },
  { kicker: 'یادی از عزیزان آسمانی', head: ['خیر شما، ', 'لبخند یک بیمار'], body: 'این پنجشنبه هم به نیت عزیزانتان سهمی در درمان مددجویان مهر جاوید داشته باشید؛ هر مبلغی، هرچقدر کم.' },
];

const CTA = ['شما هم در این کار خیر شریک شوید', 'سهم شما هرچقدر باشد، ارزشمند است', 'به نیت عزیزانتان همراه ما باشید', 'این پنجشنبه هم یادشان کنیم'];

// ---------- illustrations (inline SVG, colors from palette) ----------
function illCare(p) { // caregiver helping an elder, heart with plus
  return `<svg width="420" height="300" viewBox="0 0 420 300" aria-hidden="true">
  <circle cx="230" cy="150" r="125" fill="${p.bg2}"/>
  <rect x="40" y="262" width="340" height="9" rx="4.5" fill="${p.leaf1}"/>
  <circle cx="190" cy="100" r="34" fill="${p.acc}"/>
  <path d="M150 262 V185 q0-42 40-42 q40 0 40 42 V262Z" fill="${p.acc}"/>
  <path d="M232 160 L232 262" stroke="${p.light}" stroke-width="7" stroke-linecap="round"/>
  <circle cx="275" cy="80" r="38" fill="${p.light}"/>
  <path d="M232 262 V170 q0-48 43-48 q45 0 45 48 V262Z" fill="${p.light}"/>
  <path d="M245 170 q-30 8 -62 4" stroke="${p.light}" stroke-width="22" stroke-linecap="round" fill="none"/>
  <path d="M84 92 c-16-22 -50-8 -38 18 c6 14 38 34 38 34 s32-20 38-34 c12-26 -22-40 -38-18z" fill="${p.acc}"/>
  <path d="M84 104 v26 M71 117 h26" stroke="${p.accInk}" stroke-width="6" stroke-linecap="round"/>
  </svg>`;
}
function illCandle(p) { // three candles with glow
  const c = (x, h, w) => `<rect x="${x - w / 2}" y="${250 - h}" width="${w}" height="${h}" rx="6" fill="${p.light}"/>
  <path d="M${x} ${250 - h - 58} c20 26 18 52 0 52 c-18 0 -20-26 0-52z" fill="${p.acc}"/>
  <path d="M${x} ${250 - h - 34} c9 12 9 26 0 26 c-9 0 -9-14 0-26z" fill="${p.light}"/>`;
  return `<svg width="420" height="300" viewBox="0 0 420 300" aria-hidden="true">
  <circle cx="210" cy="130" r="130" fill="${p.bg2}"/>
  <circle cx="210" cy="90" r="80" fill="${p.acc}" opacity="0.13"/>
  ${c(130, 110, 50)}${c(290, 90, 46)}${c(210, 160, 60)}
  <rect x="70" y="250" width="280" height="14" rx="7" fill="${p.acc}"/>
  <path d="M60 262 c20-30 50-30 60-6 M360 262 c-20-30 -50-30 -60-6" stroke="${p.leaf1}" stroke-width="10" fill="none" stroke-linecap="round"/>
  </svg>`;
}
function illHands(p) { // two hands holding a heart
  return `<svg width="420" height="300" viewBox="0 0 420 300" aria-hidden="true">
  <circle cx="210" cy="150" r="128" fill="${p.bg2}"/>
  <path d="M210 150 c-30-42 -98-22 -76 30 c12 28 76 66 76 66 s64-38 76-66 c22-52 -46-72 -76-30z" fill="${p.acc}"/>
  <path d="M210 168 v46 M187 191 h46" stroke="${p.accInk}" stroke-width="10" stroke-linecap="round"/>
  <path d="M60 230 q40-10 80 10 q30 16 70 16 v24 q-50 0 -86 -14 q-34 -12 -64 -8z" fill="${p.light}"/>
  <path d="M360 230 q-40-10 -80 10 q-30 16 -70 16 v24 q50 0 86 -14 q34 -12 64 -8z" fill="${p.light}"/>
  </svg>`;
}
const ILLS = [illCare, illCandle, illHands];

// ---------- decorations ----------
const leaf = (x, y, r, s, c1, c2) => `<g transform="translate(${x} ${y}) rotate(${r}) scale(${s})"><path d="M0 0 C60 -70 190 -70 250 0 C190 70 60 70 0 0Z" fill="${c1}"/><path d="M10 0 C90 -6 170 -6 240 0" stroke="${c2}" stroke-width="6" fill="none"/></g>`;
function decoLeaves(p) {
  return leaf(720, 120, -35, 1.25, p.leaf1, p.bg) + leaf(860, 20, 10, 1.1, p.leaf2, p.bg) + leaf(820, 230, -70, 0.9, p.acc, p.bg) +
    leaf(-120, 1820, -20, 1.3, p.leaf1, p.bg) + leaf(-40, 1930, -45, 1.1, p.leaf2, p.bg) + leaf(10, 1760, 30, 0.9, p.acc, p.bg) +
    leaf(70, 690, -60, 0.45, p.leaf1, p.bg) + leaf(960, 1190, 50, 0.45, p.acc, p.bg);
}
function decoDots(p) {
  let s = '';
  for (let i = 0; i < 40; i++) { const x = (i * 197) % 1080, y = (i * 331) % 1920; s += `<circle cx="${x}" cy="${y}" r="${4 + (i % 4) * 3}" fill="${i % 3 ? p.leaf2 : p.acc}" opacity="0.35"/>`; }
  return s + `<circle cx="1000" cy="80" r="260" fill="${p.bg2}"/><circle cx="60" cy="1850" r="300" fill="${p.bg2}"/>`;
}
function decoGirih(p) {
  let s = '';
  for (let y = 0; y < 1920; y += 120) for (let x = 0; x < 1080; x += 120)
    s += `<g transform="translate(${x + 60} ${y + 60})" opacity="0.13" stroke="${p.acc}" fill="none" stroke-width="2"><rect x="-25" y="-25" width="50" height="50"/><rect x="-25" y="-25" width="50" height="50" transform="rotate(45)"/></g>`;
  return s + `<rect x="34" y="34" width="1012" height="1852" fill="none" stroke="${p.acc}" stroke-width="3"/><rect x="48" y="48" width="984" height="1824" fill="none" stroke="${p.acc}" stroke-width="1.5" opacity="0.6"/>`;
}
const DECOS = [decoLeaves, decoDots, decoGirih];

function html(v) {
  const p = PALETTES[v % PALETTES.length];
  const ill = ILLS[Math.floor(v / PALETTES.length) % ILLS.length];
  const deco = DECOS[(v + Math.floor(v / 2)) % DECOS.length];
  const t = TEXTS[v % TEXTS.length];
  const cta = CTA[v % CTA.length];
  const f = (w) => 'file://' + path.join(KIT, `vazirmatn-arabic-${w}-normal.woff2`);
  const logo = 'file://' + path.join(KIT, 'logo.png');
  return `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><style>
@font-face{font-family:V;src:url(${f(400)});font-weight:400}
@font-face{font-family:V;src:url(${f(700)});font-weight:700}
@font-face{font-family:V;src:url(${f(900)});font-weight:900}
body{margin:0;width:1080px;height:1920px;overflow:hidden;background:${p.bg};font-family:V,sans-serif;color:${p.light};position:relative}
.c{position:absolute;left:0;width:1080px;display:flex;flex-direction:column;align-items:center;text-align:center}
</style></head><body>
<svg width="1080" height="1920" style="position:absolute;inset:0" aria-hidden="true">${deco(p)}</svg>
<div class="c" style="top:150px">
  <div style="width:230px;height:230px;border-radius:50%;background:#fff;border:10px solid ${p.acc};display:flex;align-items:center;justify-content:center;overflow:hidden"><img src="${logo}" style="width:226px;height:226px"></div>
  <div style="font-size:66px;font-weight:900;margin-top:26px">مهر جاوید</div>
  <div style="margin-top:26px;background:${p.acc};color:${p.accInk};font-size:52px;font-weight:900;border-radius:999px;padding:14px 64px">پنجشنبه‌های مهرورزی</div>
  <div style="margin-top:56px">${ill(p)}</div>
  <div style="font-size:40px;font-weight:700;color:${p.acc};margin-top:30px">${t.kicker}</div>
  <div style="font-size:84px;font-weight:900;line-height:1.35;margin-top:6px;padding:0 70px">${t.head[0]}<span style="color:${p.acc}">${t.head[1]}</span></div>
  <div style="font-size:38px;line-height:1.75;margin-top:22px;padding:0 120px;opacity:0.92">${t.body}</div>
  <div style="font-size:44px;font-weight:900;margin-top:40px;display:flex;align-items:center;gap:16px"><svg width="44" height="40" viewBox="0 0 24 22" aria-hidden="true"><path d="M12 21s-9-5.6-10.7-11C.2 6.2 2.6 2 6.8 2 9.3 2 10.8 3.4 12 5c1.2-1.6 2.7-3 5.2-3 4.2 0 6.6 4.2 5.5 8C21 15.4 12 21 12 21z" fill="${p.acc}"/></svg>${cta}</div>
  <div style="margin-top:36px;width:900px;box-sizing:border-box;background:#fff;border:8px solid ${p.acc};border-radius:44px;padding:30px 40px;color:${p.accInk}">
    <div style="display:flex;align-items:center;justify-content:center;gap:16px;font-size:40px;font-weight:700"><svg width="62" height="44" viewBox="0 0 62 44" aria-hidden="true"><rect width="62" height="44" rx="8" fill="${p.accInk}"/><rect y="10" width="62" height="8" fill="${p.acc}"/><rect x="8" y="28" width="18" height="6" rx="3" fill="${p.acc}"/></svg>شماره کارت موسسه</div>
    <div style="font-size:84px;font-weight:900;margin-top:10px;direction:ltr;letter-spacing:4px;white-space:nowrap">${CARD}</div>
  </div>
</div>
</body></html>`;
}

(async () => {
  const v = parseInt(process.argv[2] || '0', 10);
  const out = path.resolve(process.argv[3] || 'story.jpg');
  const tmp = path.join(KIT, `_story_${v}.html`);
  fs.writeFileSync(tmp, html(v));
  const b = await chromium.launch();
  const pg = await b.newPage({ viewport: { width: 1080, height: 1920 } });
  await pg.goto('file://' + tmp);
  await pg.evaluate(() => document.fonts.ready);
  await pg.waitForTimeout(300);
  await pg.screenshot({ path: out, type: 'jpeg', quality: 85 });
  await b.close();
  fs.unlinkSync(tmp);
  const p = PALETTES[v % PALETTES.length];
  console.log(JSON.stringify({ variant: v, palette: p.name, text: v % TEXTS.length, out }));
})();
