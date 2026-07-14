// Branded PDF report generation for Sentinelware CTEM Platform
// 2× pixel-density canvas → high-quality JPEG → hand-written PDF-1.4 binary

// ── Resolution & page geometry ──────────────────────────────────────────
const SCALE = 2;           // physical pixels = logical × SCALE (2× for crisp output)
const PW    = 794;         // A4 logical width  at 96 dpi
const PH    = 1123;        // A4 logical height
const M     = 52;          // horizontal margin
const CW    = PW - M * 2;  // usable content width = 690

// ── Colour palette ──────────────────────────────────────────────────────
const NAVY    = "#0f172a";
const BLUE    = "#3b82f6";
const AMBER   = "#f59e0b";
const WHITE   = "#ffffff";
const GR50    = "#f8fafc";
const GR100   = "#f1f5f9";
const GR200   = "#e2e8f0";
const GR300   = "#cbd5e1";
const GR400   = "#94a3b8";
const TEXT    = "#0f172a";
const TEXT2   = "#64748b";
const CRIT    = "#dc2626"; const CRIT_BG = "#fef2f2"; const CRIT_BD = "#fca5a5";
const HIGH    = "#ea580c"; const HIGH_BG = "#fff7ed"; const HIGH_BD = "#fdba74";
const MED     = "#ca8a04"; const MED_BG  = "#fefce8"; const MED_BD  = "#fde047";
const LOW     = "#16a34a"; const LOW_BG  = "#f0fdf4"; const LOW_BD  = "#86efac";
const INFO_C  = "#2563eb"; const INFO_BG = "#eff6ff"; const INFO_BD = "#93c5fd";
const PURPLE  = "#7c3aed";

// ── Severity helpers ────────────────────────────────────────────────────
function sevColor(s: string): string {
  switch (s.toLowerCase()) {
    case "critical": return CRIT;
    case "high":     return HIGH;
    case "medium":   return MED;
    case "low":      return LOW;
    default:         return INFO_C;
  }
}
function sevBg(s: string): string {
  switch (s.toLowerCase()) {
    case "critical": return CRIT_BG;
    case "high":     return HIGH_BG;
    case "medium":   return MED_BG;
    case "low":      return LOW_BG;
    default:         return INFO_BG;
  }
}
function sevBd(s: string): string {
  switch (s.toLowerCase()) {
    case "critical": return CRIT_BD;
    case "high":     return HIGH_BD;
    case "medium":   return MED_BD;
    case "low":      return LOW_BD;
    default:         return INFO_BD;
  }
}
function riskLabel(s: string): string {
  return s.toUpperCase().replace(/_/g, " ");
}

// ── Font constants ──────────────────────────────────────────────────────
const FONT = "'Segoe UI', 'Inter', system-ui, -apple-system, sans-serif";
const MONO = "'Cascadia Code', 'Consolas', 'Courier New', monospace";

// ── Canvas utilities ────────────────────────────────────────────────────
function createScaledCanvas(): HTMLCanvasElement {
  const cv = document.createElement("canvas");
  cv.width  = PW * SCALE;
  cv.height = PH * SCALE;
  return cv;
}

function getScaledCtx(cv: HTMLCanvasElement): CanvasRenderingContext2D {
  const ctx = cv.getContext("2d")!;
  ctx.scale(SCALE, SCALE);
  return ctx;
}

// ── Drawing primitives ──────────────────────────────────────────────────
function rr(
  c: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number,
  r: number,
  fill = WHITE,
  stroke = "",
  strokeWidth = 1,
) {
  c.beginPath();
  c.moveTo(x + r, y);
  c.lineTo(x + w - r, y);
  c.quadraticCurveTo(x + w, y, x + w, y + r);
  c.lineTo(x + w, y + h - r);
  c.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  c.lineTo(x + r, y + h);
  c.quadraticCurveTo(x, y + h, x, y + h - r);
  c.lineTo(x, y + r);
  c.quadraticCurveTo(x, y, x + r, y);
  c.closePath();
  if (fill) { c.fillStyle = fill; c.fill(); }
  if (stroke) { c.strokeStyle = stroke; c.lineWidth = strokeWidth; c.stroke(); }
}

function tx(
  c: CanvasRenderingContext2D,
  text: string,
  x: number, y: number,
  size: number,
  color = TEXT,
  weight = "normal",
  align: CanvasTextAlign = "left",
  maxW?: number,
) {
  c.save();
  c.font = `${weight} ${size}px ${FONT}`;
  c.fillStyle = color;
  c.textAlign = align;
  if (maxW) c.fillText(text, x, y, maxW);
  else       c.fillText(text, x, y);
  c.restore();
}

function monoTx(
  c: CanvasRenderingContext2D,
  text: string,
  x: number, y: number,
  size: number,
  color = TEXT2,
  maxW?: number,
) {
  c.save();
  c.font = `${size}px ${MONO}`;
  c.fillStyle = color;
  if (maxW) c.fillText(text, x, y, maxW);
  else       c.fillText(text, x, y);
  c.restore();
}

function mw(c: CanvasRenderingContext2D, text: string, size: number, weight = "normal"): number {
  c.save();
  c.font = `${weight} ${size}px ${FONT}`;
  const w = c.measureText(text).width;
  c.restore();
  return w;
}

function wrapText(
  c: CanvasRenderingContext2D,
  text: string,
  size: number,
  weight: string,
  maxWidth: number,
): string[] {
  c.save();
  c.font = `${weight} ${size}px ${FONT}`;
  const words = text.split(" ");
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    const test = cur ? `${cur} ${w}` : w;
    if (c.measureText(test).width <= maxWidth) {
      cur = test;
    } else {
      if (cur) lines.push(cur);
      cur = w;
    }
  }
  if (cur) lines.push(cur);
  c.restore();
  return lines;
}

function truncStr(c: CanvasRenderingContext2D, text: string, size: number, maxW: number): string {
  c.save();
  c.font = `${size}px ${FONT}`;
  if (c.measureText(text).width <= maxW) { c.restore(); return text; }
  let s = text;
  while (s.length > 0 && c.measureText(s + "…").width > maxW) s = s.slice(0, -1);
  c.restore();
  return s + "…";
}

// ── Logo / branding helpers ─────────────────────────────────────────────
async function getLogo(): Promise<HTMLImageElement | null> {
  return new Promise(resolve => {
    const img = new Image();
    img.crossOrigin = "anonymous";
    img.onload  = () => resolve(img);
    img.onerror = () => {
      // fallback to sidebar logo or null
      const imgs = document.querySelectorAll<HTMLImageElement>("img[alt='Sentinelware logo'], img[alt='logo']");
      for (const i of imgs) {
        if (i.complete && i.naturalWidth > 0) { resolve(i); return; }
      }
      resolve(null);
    };
    img.src = "/sentinelware-logo.png";
  });
}

function drawShield(
  c: CanvasRenderingContext2D,
  cx: number, cy: number, size: number, color: string,
) {
  const h = size; const hw = size * 0.72;
  c.save();
  c.fillStyle = color;
  c.beginPath();
  c.moveTo(cx, cy - h / 2);
  c.lineTo(cx + hw / 2, cy - h * 0.3);
  c.lineTo(cx + hw / 2, cy + h * 0.15);
  c.quadraticCurveTo(cx + hw / 2, cy + h / 2, cx, cy + h / 2);
  c.quadraticCurveTo(cx - hw / 2, cy + h / 2, cx - hw / 2, cy + h * 0.15);
  c.lineTo(cx - hw / 2, cy - h * 0.3);
  c.closePath();
  c.fill();
  c.fillStyle = WHITE;
  c.font = `bold ${h * 0.5}px ${FONT}`;
  c.textAlign = "center";
  c.textBaseline = "middle";
  c.fillText("S", cx, cy + 1);
  c.restore();
}

function drawLogo(
  c: CanvasRenderingContext2D,
  img: HTMLImageElement,
  cx: number, cy: number,
  maxW: number,
) {
  const ar  = img.naturalWidth / img.naturalHeight;
  const ww  = Math.min(maxW, img.naturalWidth);
  const hh  = ww / ar;
  c.save();
  c.globalCompositeOperation = "screen";
  c.drawImage(img, cx - ww / 2, cy - hh / 2, ww, hh);
  c.restore();
}

// ── Cover page ──────────────────────────────────────────────────────────
interface CoverOptions {
  title:      string;
  reportKind: string;
  metaPairs:  [string, string][];
  riskLabel:  string;
  riskColor:  string;
  logo:       HTMLImageElement | null;
}

function makeCover(o: CoverOptions): HTMLCanvasElement {
  const cv  = createScaledCanvas();
  const ctx = getScaledCtx(cv);

  // ── Background: rich dark gradient ──────────────────────────────────────
  const bgGrad = ctx.createLinearGradient(0, 0, 0, PH);
  bgGrad.addColorStop(0.0, "#060c18");
  bgGrad.addColorStop(0.45, "#0b1220");
  bgGrad.addColorStop(1.0,  "#0f172a");
  ctx.fillStyle = bgGrad;
  ctx.fillRect(0, 0, PW, PH);

  // ── Subtle dot-grid texture ─────────────────────────────────────────────
  ctx.fillStyle = "rgba(255,255,255,0.035)";
  for (let gx = 36; gx < PW; gx += 36) {
    for (let gy = 36; gy < PH; gy += 36) {
      ctx.beginPath(); ctx.arc(gx, gy, 1, 0, Math.PI * 2); ctx.fill();
    }
  }

  // ── Top accent bar: amber gradient ──────────────────────────────────────
  const topGrad = ctx.createLinearGradient(0, 0, PW, 0);
  topGrad.addColorStop(0, "#d97706");
  topGrad.addColorStop(0.5, "#f59e0b");
  topGrad.addColorStop(1, "#d97706");
  ctx.fillStyle = topGrad;
  ctx.fillRect(0, 0, PW, 5);

  // ── Bottom confidential strip ────────────────────────────────────────────
  ctx.fillStyle = "#160505";
  ctx.fillRect(0, PH - 46, PW, 46);
  ctx.fillStyle = "#7f1d1d";
  ctx.fillRect(0, PH - 46, PW, 1.5);
  tx(ctx, "⚠  CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY  ⚠", PW / 2, PH - 14, 9, "#fca5a5", "bold", "center");

  // ── Logo zone: centered vertically at ~35% of page height ──────────────
  const logoZoneCY = Math.round(PH * 0.28);
  const logoW = 300;

  if (o.logo) {
    drawLogo(ctx, o.logo, PW / 2, logoZoneCY, logoW);
  } else {
    // Fallback text logo
    drawShield(ctx, PW / 2 - 90, logoZoneCY, 44, AMBER);
    tx(ctx, "SENTINELWARES", PW / 2 + 20, logoZoneCY + 10, 26, WHITE, "bold", "center");
  }

  // ── Tagline ──────────────────────────────────────────────────────────────
  const tagY = logoZoneCY + 52;
  tx(ctx, "CONTINUOUS THREAT EXPOSURE MANAGEMENT", PW / 2, tagY, 9.5, GR400, "bold", "center");

  // ── Horizontal rule with amber accent ────────────────────────────────────
  const divY = tagY + 26;
  ctx.fillStyle = "rgba(245,158,11,0.25)";
  ctx.fillRect(M + 30, divY, CW - 60, 1);
  ctx.fillStyle = AMBER;
  ctx.fillRect(PW / 2 - 28, divY - 1, 56, 3);

  // ── Report kind badge ─────────────────────────────────────────────────────
  const bKind = o.reportKind.toUpperCase();
  const bkW   = mw(ctx, bKind, 8.5, "bold") + 30;
  const bkY   = divY + 20;
  rr(ctx, PW / 2 - bkW / 2, bkY, bkW, 24, 12, "rgba(59,130,246,0.15)", BLUE, 1);
  tx(ctx, bKind, PW / 2, bkY + 16.5, 8.5, BLUE, "bold", "center");

  // ── Report title ──────────────────────────────────────────────────────────
  const titleY0 = bkY + 40;
  const titleLines = wrapText(ctx, o.title, 21, "bold", PW - 100);
  let titleY = titleY0;
  for (const line of titleLines.slice(0, 2)) {
    tx(ctx, line, PW / 2, titleY, 21, WHITE, "bold", "center");
    titleY += 29;
  }

  // ── Generated date (prominent) ────────────────────────────────────────────
  const gen = new Date().toLocaleString("en-US", {
    weekday: "long", year: "numeric", month: "long", day: "numeric",
  });
  tx(ctx, gen, PW / 2, titleY + 20, 10, GR300, "500", "center");

  // ── Meta grid ────────────────────────────────────────────────────────────
  const metaY    = titleY + 46;
  const metaCols = 2;
  const colW     = (CW - 14) / metaCols;
  const rowH     = 54;
  o.metaPairs.forEach(([k, v], i) => {
    const col = i % metaCols;
    const row = Math.floor(i / metaCols);
    const x   = M + col * (colW + 14);
    const y   = metaY + row * rowH;
    rr(ctx, x, y, colW, rowH - 8, 7, "rgba(255,255,255,0.05)", "rgba(255,255,255,0.12)", 1);
    // Left micro-accent
    ctx.fillStyle = AMBER;
    ctx.fillRect(x, y, 3, rowH - 8);
    rr(ctx, x, y, 3, 6, 2, AMBER, "");
    rr(ctx, x, y + rowH - 8 - 6, 3, 6, 2, AMBER, "");
    tx(ctx, k.toUpperCase(), x + 12, y + 17, 7.5, GR400, "bold");
    tx(ctx, String(v || "—"), x + 12, y + 36, 10.5, WHITE, "500", "left", colW - 22);
  });

  // ── Risk level badge ──────────────────────────────────────────────────────
  const metaRows = Math.ceil(o.metaPairs.length / metaCols);
  const rBadgeY  = metaY + metaRows * rowH + 18;
  const bLabel   = o.riskLabel.toUpperCase();
  const bBW      = mw(ctx, bLabel, 11, "bold") + 48;
  ctx.save();
  ctx.shadowColor = o.riskColor;
  ctx.shadowBlur  = 18;
  rr(ctx, PW / 2 - bBW / 2, rBadgeY, bBW, 36, 18, o.riskColor);
  ctx.shadowBlur  = 0;
  ctx.restore();
  tx(ctx, bLabel, PW / 2, rBadgeY + 24, 11, WHITE, "bold", "center");

  return cv;
}

// ── PdfDoc — paginated content builder ──────────────────────────────────
class PdfDoc {
  private pages_: HTMLCanvasElement[] = [];
  private cur_!: HTMLCanvasElement;
  _ctx!: CanvasRenderingContext2D;
  y = 0;
  private pn_ = 0;
  private title_: string;
  private genDate_: string;
  private logo_: HTMLImageElement | null;

  constructor(title: string, logo?: HTMLImageElement | null) {
    this.title_   = title;
    this.logo_    = logo ?? null;
    this.genDate_ = new Date().toLocaleString("en-US", {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  }

  newPage() {
    if (this.pn_ > 0) this._endPage();
    this.pn_++;
    this.cur_ = createScaledCanvas();
    this._ctx = getScaledCtx(this.cur_);
    this._drawFrame();
    this.y = 70;
  }

  private _drawFrame() {
    const c = this._ctx;
    c.fillStyle = WHITE;
    c.fillRect(0, 0, PW, PH);

    // Top accent
    c.fillStyle = BLUE;
    c.fillRect(0, 0, PW, 4);

    // Header strip
    const grad = c.createLinearGradient(0, 4, 0, 50);
    grad.addColorStop(0, "#1e293b");
    grad.addColorStop(1, "#0f172a");
    c.fillStyle = grad;
    c.fillRect(0, 4, PW, 46);

    // Header bottom separator
    c.fillStyle = "rgba(59,130,246,0.3)";
    c.fillRect(0, 50, PW, 1);

    if (this.logo_) {
      drawLogo(c, this.logo_, M + 70, 27, 130);
    } else {
      drawShield(c, M + 14, 27, 20, BLUE);
      tx(c, "SENTINELWARE", M + 28, 32, 9.5, WHITE, "bold");
    }

    const short = this.title_.length > 60 ? this.title_.slice(0, 57) + "…" : this.title_;
    tx(c, short, PW / 2, 32, 8, GR400, "normal", "center");
    tx(c, `Page ${this.pn_}`, PW - M, 32, 8, GR400, "normal", "right");
  }

  private _endPage() {
    const c = this._ctx;
    c.fillStyle = GR200;
    c.fillRect(M, PH - 42, CW, 1);
    tx(c, "CONFIDENTIAL — Sentinelware CTEM Platform", M, PH - 24, 7.5, TEXT2);
    tx(c, this.genDate_, PW - M, PH - 24, 7.5, TEXT2, "normal", "right");
    this.pages_.push(this.cur_);
  }

  ensureSpace(h: number) {
    if (this.y + h > PH - 54) this.newPage();
  }

  gap(h: number) { this.y += h; }

  sectionHeader(title: string, color = BLUE) {
    this.ensureSpace(38);
    const c = this._ctx;
    c.fillStyle = color;
    c.fillRect(M, this.y, 4, 24);
    tx(c, title.toUpperCase(), M + 12, this.y + 16.5, 10.5, TEXT, "bold");
    c.fillStyle = GR200;
    c.fillRect(M + 12, this.y + 25, CW - 12, 1);
    this.y += 36;
  }

  cardHeader(num: number, title: string, color = BLUE, subtitle?: string) {
    const hgt = subtitle ? 56 : 42;
    this.ensureSpace(hgt + 12);
    const c = this._ctx;
    const y0 = this.y;
    // Card header background
    const hgrad = c.createLinearGradient(M, y0, M, y0 + hgt);
    hgrad.addColorStop(0, "#f8fafc");
    hgrad.addColorStop(1, "#f1f5f9");
    rr(c, M, y0, CW, hgt, 8, "#f8fafc", GR200, 1);
    // Left color accent bar
    c.fillStyle = color;
    c.fillRect(M, y0, 5, hgt);
    rr(c, M, y0, 5, 8, 3, color, "");
    rr(c, M, y0 + hgt - 8, 5, 8, 3, color, "");
    // Number badge (circle)
    const cx = M + 26;
    const cy = y0 + hgt / 2;
    c.fillStyle = color;
    c.beginPath();
    c.arc(cx, cy, 13, 0, Math.PI * 2);
    c.fill();
    c.fillStyle = WHITE;
    c.font = `bold 9px ${FONT}`;
    c.textAlign = "center";
    c.textBaseline = "middle";
    c.fillText(String(num).padStart(2, "0"), cx, cy + 0.5);
    c.textAlign = "left";
    c.textBaseline = "alphabetic";
    // Title & optional subtitle
    if (subtitle) {
      tx(c, title, M + 48, y0 + 22, 10.5, TEXT, "bold");
      tx(c, subtitle, M + 48, y0 + 40, 8.5, TEXT2, "normal");
    } else {
      tx(c, title, M + 48, y0 + hgt / 2 + 5, 10.5, TEXT, "bold");
    }
    this.y += hgt + 10;
  }

  subsectionHeader(title: string, color = TEXT2) {
    this.ensureSpace(26);
    tx(this._ctx, title, M, this.y + 12, 9, color, "bold");
    this.y += 20;
  }

  text(str: string, opts: { size?: number; color?: string; weight?: string; indent?: number } = {}) {
    const { size = 9.5, color = TEXT, weight = "normal", indent = 0 } = opts;
    const lines = wrapText(this._ctx, str, size, weight, CW - indent - 4);
    for (const line of lines) {
      this.ensureSpace(size + 9);
      tx(this._ctx, line, M + indent, this.y + size, size, color, weight);
      this.y += size + 6;
    }
  }

  keyValue(pairs: [string, string][], columns = 2) {
    const cardH = 46;
    const gapX  = 10;
    const colW  = (CW - gapX * (columns - 1)) / columns;
    const rows  = Math.ceil(pairs.length / columns);
    this.ensureSpace(rows * (cardH + 8) + 8);
    const c = this._ctx;
    pairs.forEach(([k, v], i) => {
      const col = i % columns;
      const row = Math.floor(i / columns);
      const x   = M + col * (colW + gapX);
      const y   = this.y + row * (cardH + 8);
      rr(c, x, y, colW, cardH, 6, GR50, GR200);
      tx(c, k, x + 10, y + 15, 8, TEXT2, "bold");
      tx(c, String(v || "—"), x + 10, y + 33, 10, TEXT, "500", "left", colW - 20);
    });
    this.y += rows * (cardH + 8) + 6;
  }

  statCards(stats: { label: string; value: string | number; color: string }[]) {
    const cardH = 72;
    const gap   = 10;
    const colW  = (CW - gap * (stats.length - 1)) / stats.length;
    this.ensureSpace(cardH + 14);
    const c = this._ctx;
    stats.forEach((s, i) => {
      const x = M + i * (colW + gap);
      const y = this.y;
      rr(c, x, y, colW, cardH, 7, WHITE, GR200);
      c.fillStyle = s.color;
      c.fillRect(x, y, 4, cardH);
      rr(c, x, y, 4, 7, 0, s.color, "");
      rr(c, x, y + cardH - 7, 4, 7, 0, s.color, "");
      const valStr = String(s.value);
      const valSize = valStr.length <= 4 ? 28 : valStr.length <= 6 ? 22 : 18;
      tx(c, valStr, x + 16, y + 44, valSize, s.color, "bold");
      tx(c, s.label.toUpperCase(), x + 16, y + 62, 7.5, TEXT2, "bold");
    });
    this.y += cardH + 14;
  }

  table(
    headers: string[],
    colWidths: number[],
    rows: (string | null)[][],
    opts: { rowH?: number; severityCol?: number; monoCol?: number[]; statusCol?: number } = {},
  ) {
    const { rowH = 30, severityCol, monoCol = [], statusCol } = opts;
    const totalW  = colWidths.reduce((a, b) => a + b, 0) + (headers.length - 1) * 8;
    const headerH = 28;

    this.ensureSpace(headerH + Math.min(rows.length, 2) * rowH);
    const c = this._ctx;

    // Header row with gradient
    const hgrad = c.createLinearGradient(M, this.y, M, this.y + headerH);
    hgrad.addColorStop(0, "#1e293b");
    hgrad.addColorStop(1, NAVY);
    c.fillStyle = hgrad;
    c.fillRect(M, this.y, totalW, headerH);
    let hx = M;
    for (let ci = 0; ci < headers.length; ci++) {
      tx(c, headers[ci].toUpperCase(), hx + 10, this.y + 19, 7.5, WHITE, "bold");
      hx += colWidths[ci] + 8;
    }
    this.y += headerH;

    for (let ri = 0; ri < rows.length; ri++) {
      this.ensureSpace(rowH);
      const bg = ri % 2 === 0 ? WHITE : GR50;
      c.fillStyle = bg;
      c.fillRect(M, this.y, totalW, rowH);
      c.strokeStyle = GR200;
      c.lineWidth   = 0.75;
      c.beginPath();
      c.moveTo(M, this.y + rowH);
      c.lineTo(M + totalW, this.y + rowH);
      c.stroke();

      let cx2 = M;
      for (let ci = 0; ci < headers.length; ci++) {
        const cell = rows[ri][ci] ?? "";
        const cw   = colWidths[ci];
        const midY = this.y + rowH / 2 + 4.5;

        if (ci === severityCol) {
          const sev  = cell.toLowerCase();
          const bw3  = 68; const bh = 18;
          rr(c, cx2 + 8, this.y + (rowH - bh) / 2, bw3, bh, 9, sevBg(sev), sevBd(sev));
          tx(c, cell.toUpperCase(), cx2 + 8 + bw3 / 2, this.y + (rowH - bh) / 2 + 12.5, 7.5, sevColor(sev), "bold", "center");
        } else if (ci === statusCol) {
          const clean = cell.replace(/_/g, " ");
          const sw    = mw(c, clean, 8, "500") + 16;
          rr(c, cx2 + 6, this.y + (rowH - 18) / 2, sw, 18, 9, GR100, GR300);
          tx(c, clean, cx2 + 6 + sw / 2, this.y + (rowH - 18) / 2 + 12, 8, TEXT2, "500", "center");
        } else if (monoCol.includes(ci)) {
          monoTx(c, truncStr(c, cell, 8.5, cw - 14), cx2 + 10, midY, 8.5, TEXT2);
        } else {
          tx(c, truncStr(c, cell, 9, cw - 14), cx2 + 10, midY, 9, TEXT);
        }
        cx2 += cw + 8;
      }
      this.y += rowH;
    }
    this.y += 10;
  }

  // Enhanced finding card with multi-line title, description, and remediation
  findingCard(f: {
    title:        string;
    severity:     string;
    cve?:         string | null;
    cvss?:        number | null;
    cwe?:         string | null;
    status?:      string | null;
    description?: string | null;
    remediation?: string | null;
  }) {
    const c    = this._ctx;
    const sc   = sevColor(f.severity);
    const sbg  = sevBg(f.severity);
    const sbd  = sevBd(f.severity);

    const INNER_W   = CW - 28;     // content width inside card
    const PAD_X     = 14;
    const BADGE_W   = 74;
    const BADGE_H   = 20;
    const title_max = INNER_W - BADGE_W - 80;

    const titleLines = wrapText(c, f.title, 9.5, "bold", title_max).slice(0, 2);
    const descLines  = f.description
      ? wrapText(c, f.description,               8.5, "normal", INNER_W).slice(0, 3)
      : [];
    const remLines   = f.remediation
      ? wrapText(c, `Fix: ${f.remediation}`,     8.5, "normal", INNER_W).slice(0, 2)
      : [];

    const headerH  = 12 + titleLines.length * 15 + 8;
    const metaH    = 18;
    const descH    = descLines.length  > 0 ? descLines.length  * 14 + 8 : 0;
    const remH     = remLines.length   > 0 ? remLines.length   * 14 + 4 : 0;
    const cardH    = headerH + metaH + descH + remH + 10;

    this.ensureSpace(cardH + 10);
    const y0 = this.y;

    // Card background + border
    rr(c, M, y0, CW, cardH, 7, sbg, sbd, 1);
    // Left severity accent bar
    c.fillStyle = sc;
    c.fillRect(M, y0, 5, cardH);
    // Round left bar corners
    rr(c, M, y0, 5, 7, 2, sc, "");
    rr(c, M, y0 + cardH - 7, 5, 7, 2, sc, "");

    let y = y0 + 12;

    // Severity badge
    rr(c, M + PAD_X, y, BADGE_W, BADGE_H, 10, sc);
    tx(c, f.severity.toUpperCase(), M + PAD_X + BADGE_W / 2, y + 13.5, 7.5, WHITE, "bold", "center");

    // Title (multi-line)
    let titleX = M + PAD_X + BADGE_W + 10;
    for (let li = 0; li < titleLines.length; li++) {
      tx(c, titleLines[li], titleX, y + 14 + li * 15, 9.5, NAVY, "bold");
    }

    // CVSS score (right side)
    if (f.cvss != null) {
      const cvssStr = `CVSS ${f.cvss.toFixed(1)}`;
      const cvssW   = mw(c, cvssStr, 8.5, "bold");
      tx(c, cvssStr, PW - M - 12, y + 14, 8.5, sc, "bold", "right");
      if (f.cve) {
        monoTx(c, f.cve, PW - M - 14 - cvssW - 12, y + 14, 8, TEXT2, cvssW + 12);
      }
    } else if (f.cve) {
      monoTx(c, f.cve, PW - M - 12, y + 14, 8, TEXT2, undefined);
    }

    y += headerH - 12;

    // Meta row: CVE · CWE · Status
    const metaParts: string[] = [];
    if (f.cwe)    metaParts.push(`CWE-${f.cwe.replace(/^CWE-/i, "")}`);
    if (f.status) metaParts.push(`Status: ${f.status.replace(/_/g, " ")}`);
    if (metaParts.length > 0) {
      tx(c, metaParts.join("  ·  "), M + PAD_X + BADGE_W + 10, y + 12, 8, TEXT2);
    }
    y += metaH;

    // Description block
    if (descLines.length > 0) {
      tx(c, "Description", M + PAD_X, y + 11, 8, TEXT2, "bold");
      y += 14;
      for (const line of descLines) {
        tx(c, line, M + PAD_X, y + 11, 8.5, TEXT, "normal");
        y += 14;
      }
    }

    // Remediation block
    if (remLines.length > 0) {
      y += 4;
      for (const line of remLines) {
        tx(c, line, M + PAD_X, y + 11, 8.5, LOW, "normal");
        y += 14;
      }
    }

    this.y += cardH + 10;
  }

  finalize(): HTMLCanvasElement[] {
    if (this.pn_ > 0) this._endPage();
    return this.pages_;
  }
}

// ── PDF binary assembly ──────────────────────────────────────────────────
function buildPdf(canvases: HTMLCanvasElement[]): Blob {
  // A4 in points (72dpi) — page size unchanged, image is higher-res
  const ptW = Math.round(PW * 72 / 96);  // 595pt
  const ptH = Math.round(PH * 72 / 96);  // 842pt
  // Physical pixel dimensions of each canvas (2× scale)
  const imgW = PW * SCALE;
  const imgH = PH * SCALE;

  const images: Uint8Array[] = canvases.map(cv => {
    const b64 = cv.toDataURL("image/jpeg", 0.97).split(",")[1];
    const bin  = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  });

  const enc   = new TextEncoder();
  const parts: Uint8Array[] = [];
  const offsets: number[]   = [];
  let offset = 0;

  function push(s: string)    { const b = enc.encode(s); parts.push(b); offset += b.length; }
  function pushB(b: Uint8Array){ parts.push(b); offset += b.length; }

  push("%PDF-1.4\n%\xFF\xFF\xFF\xFF\n");

  const nPages = images.length;
  offsets[1] = offset; push(`1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n`);
  const pageRefs = Array.from({ length: nPages }, (_, i) => `${3 + i * 2} 0 R`).join(" ");
  offsets[2] = offset; push(`2 0 obj\n<< /Type /Pages /Kids [${pageRefs}] /Count ${nPages} >>\nendobj\n`);

  for (let i = 0; i < nPages; i++) {
    const pageObj = 3 + i * 2;
    const imgObj  = 4 + i * 2;
    const csObj   = 3 + nPages * 2 + 10 + i;
    const imgName = `Im${i}`;
    const cs      = enc.encode(`q ${ptW} 0 0 ${ptH} 0 0 cm /${imgName} Do Q`);

    offsets[csObj] = offset;
    push(`${csObj} 0 obj\n<< /Length ${cs.length} >>\nstream\n`);
    pushB(cs);
    push(`\nendstream\nendobj\n`);

    offsets[pageObj] = offset;
    push(
      `${pageObj} 0 obj\n<< /Type /Page /Parent 2 0 R ` +
      `/MediaBox [0 0 ${ptW} ${ptH}] ` +
      `/Resources << /XObject << /${imgName} ${imgObj} 0 R >> >> ` +
      `/Contents ${csObj} 0 R >>\nendobj\n`,
    );

    offsets[imgObj] = offset;
    push(
      `${imgObj} 0 obj\n<< /Type /XObject /Subtype /Image ` +
      `/Width ${imgW} /Height ${imgH} /ColorSpace /DeviceRGB /BitsPerComponent 8 ` +
      `/Filter /DCTDecode /Length ${images[i].length} >>\nstream\n`,
    );
    pushB(images[i]);
    push(`\nendstream\nendobj\n`);
  }

  const xrefOff = offset;
  const allIds  = Object.keys(offsets).map(Number).sort((a, b) => a - b);
  const maxId   = Math.max(...allIds);
  push(`xref\n0 ${maxId + 1}\n0000000000 65535 f \n`);
  for (let id = 1; id <= maxId; id++) {
    if (offsets[id] !== undefined) push(`${String(offsets[id]).padStart(10, "0")} 00000 n \n`);
    else push(`0000000000 65535 f \n`);
  }
  push(`trailer\n<< /Size ${maxId + 1} /Root 1 0 R >>\nstartxref\n${xrefOff}\n%%EOF\n`);

  const totalLen = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of parts) { out.set(p, pos); pos += p.length; }
  return new Blob([out], { type: "application/pdf" });
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement("a");
  a.href     = url;
  a.download = filename.endsWith(".pdf") ? filename : filename + ".pdf";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 8000);
}

// ── Asset PDF ───────────────────────────────────────────────────────────
export async function downloadAssetPdf(assetId: number, token: string | null): Promise<void> {
  const [logo, res] = await Promise.all([
    getLogo(),
    fetch(`/api/reports/pdf-data/asset/${assetId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
  ]);
  if (!res.ok) throw new Error("Failed to fetch asset PDF data");

  const d = await res.json() as {
    asset: {
      name: string; value: string; type: string;
      ipAddress?: string; port?: number;
      riskLevel: string; verificationStatus: string; lastScannedAt?: string;
    };
    riskScore?: { score: number; level: string };
    findings: {
      title: string; severity: string; status: string;
      cve?: string; cvss?: number; cwe?: string;
      description?: string; remediation?: string;
    }[];
    technologies: {
      technology: string; category?: string;
      version?: string; confidence?: number;
    }[];
    findingCounts: {
      total: number; open: number; critical: number;
      high: number; medium: number; low: number;
    };
  };

  const rLevel = d.riskScore?.level ?? d.asset.riskLevel ?? "low";
  const rc     = sevColor(rLevel);

  const cover = makeCover({
    title:      `${d.asset.name} — Security Assessment Report`,
    reportKind: "Asset Vulnerability Report",
    metaPairs:  [
      ["Asset Name",    d.asset.name],
      ["Target",        d.asset.value],
      ["Asset Type",    d.asset.type.toUpperCase()],
      ["Risk Level",    rLevel.toUpperCase()],
      ["IP Address",    d.asset.ipAddress ?? "—"],
      ["Last Scanned",  d.asset.lastScannedAt ? new Date(d.asset.lastScannedAt).toLocaleDateString() : "Never"],
    ],
    riskLabel:  `Risk Level: ${rLevel.toUpperCase()}`,
    riskColor:  rc,
    logo,
  });

  const doc = new PdfDoc(`${d.asset.name} — Security Assessment`, logo);
  doc.newPage();

  // Executive Summary
  doc.sectionHeader("Executive Summary");
  doc.gap(6);
  doc.statCards([
    { label: "Risk Score",     value: Math.round(d.riskScore?.score ?? 0), color: rc },
    { label: "Total Findings", value: d.findingCounts.total,               color: NAVY },
    { label: "Critical",       value: d.findingCounts.critical,            color: CRIT },
    { label: "High",           value: d.findingCounts.high,                color: HIGH },
  ]);
  doc.statCards([
    { label: "Medium",        value: d.findingCounts.medium, color: MED },
    { label: "Low",           value: d.findingCounts.low,    color: LOW },
    { label: "Open",          value: d.findingCounts.open,   color: HIGH },
    { label: "Technologies",  value: d.technologies.length,  color: INFO_C },
  ]);
  doc.gap(12);

  // Asset Details
  doc.sectionHeader("Asset Details");
  doc.gap(6);
  doc.keyValue([
    ["Asset Name",      d.asset.name],
    ["Target / Value",  d.asset.value],
    ["Asset Type",      d.asset.type],
    ["IP Address",      d.asset.ipAddress ?? "—"],
    ["Port",            d.asset.port != null ? String(d.asset.port) : "—"],
    ["Verification",    d.asset.verificationStatus],
    ["Risk Level",      rLevel.toUpperCase()],
    ["Last Scanned",    d.asset.lastScannedAt ? new Date(d.asset.lastScannedAt).toLocaleString() : "Never"],
  ], 4);
  doc.gap(12);

  // Findings
  if (d.findings.length > 0) {
    doc.sectionHeader("Vulnerability Findings");
    doc.gap(6);

    // Summary table first
    doc.table(
      ["Severity", "Title", "CVE / ID", "CVSS", "Status"],
      [74, 248, 118, 56, 80],
      d.findings.map(f => [
        f.severity, f.title,
        f.cve ?? "—",
        f.cvss != null ? String(f.cvss) : "—",
        f.status,
      ]),
      { severityCol: 0, monoCol: [2], statusCol: 4 },
    );
    doc.gap(12);

    // Detailed finding cards (all findings, critical + high first)
    const critical = d.findings.filter(f => f.severity === "critical");
    const high     = d.findings.filter(f => f.severity === "high");
    const others   = d.findings.filter(f => f.severity !== "critical" && f.severity !== "high");

    const toDetail = [...critical, ...high, ...others.slice(0, Math.max(0, 30 - critical.length - high.length))];

    if (toDetail.length > 0) {
      doc.sectionHeader("Finding Details — Critical & High Priority", CRIT);
      doc.gap(6);
      for (const f of toDetail) {
        doc.findingCard(f);
      }
    }

    if (others.length > toDetail.length - critical.length - high.length) {
      const rem = others.length - Math.max(0, 30 - critical.length - high.length);
      if (rem > 0) {
        doc.gap(4);
        doc.text(`…and ${rem} additional medium/low findings are captured in the vulnerability table above.`, { size: 8.5, color: TEXT2 });
      }
    }
  } else {
    doc.gap(8);
    doc.text("No vulnerability findings recorded for this asset. The asset appears clean.", { size: 10, color: LOW });
    doc.gap(8);
  }

  // Technology Stack
  if (d.technologies.length > 0) {
    doc.gap(6);
    doc.sectionHeader("Technology Stack");
    doc.gap(6);
    doc.table(
      ["Technology", "Category", "Version", "Confidence"],
      [200, 190, 130, 110],
      d.technologies.map(t => [
        t.technology,
        t.category ?? "—",
        t.version ?? "—",
        t.confidence != null ? `${t.confidence}%` : "—",
      ]),
    );
  }

  const filename = `${d.asset.name.replace(/[^a-z0-9]/gi, "_")}_security_report.pdf`;
  triggerDownload(buildPdf([cover, ...doc.finalize()]), filename);
}

// ── Brand Threat CSV ─────────────────────────────────────────────────────
function csvEscapeCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function toCsvRows(headers: string[], rows: unknown[][]): string {
  const lines = [headers.map(csvEscapeCell).join(",")];
  for (const row of rows) lines.push(row.map(csvEscapeCell).join(","));
  return lines.join("\n");
}

export async function downloadBrandThreatCsv(scanId: number, token: string | null): Promise<void> {
  const res = await fetch(`/api/reports/pdf-data/brand-threat/${scanId}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error("Failed to fetch brand threat data");
  const d = await res.json() as {
    scan: {
      id: number; domain: string; status: string;
      totalPermutations: number; liveCount: number; registeredCount: number;
      phishingRisk: string; dataLeakCount: number; phishingCount: number;
      brandAbuseCount: number; darkWebCount: number; createdAt: string; completedAt?: string;
    };
    topResults:  {
      permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[];
      mxSpf?: string; riskScore: number; isSuspicious: boolean; geoCountry?: string;
      vtMalicious?: number; whoisRegistrar?: string; whoisCreated?: string;
      whoisAgeDays?: number; isPhishing?: boolean; phishingSource?: string; registrationStatus?: string;
    }[];
    liveResults: {
      permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[];
      mxSpf?: string; riskScore: number; isSuspicious: boolean; geoCountry?: string;
      vtMalicious?: number; whoisRegistrar?: string; whoisCreated?: string; whoisAgeDays?: number;
    }[];
    phishingDetections: {
      id: number; url: string; source: string; threatType?: string | null;
      verified: boolean; targetBrand?: string | null; submittedAt?: string | null;
    }[];
    dataLeaks: {
      id: number; source: string; title: string; breachDate?: string | null;
      description?: string | null; exposedData?: string[] | null;
      domainMatch?: string | null; emailMatch?: string | null; severity: string; url?: string | null;
    }[];
    brandAbuse: {
      id: number; type: string; platform?: string | null; url?: string | null;
      title?: string | null; description?: string | null; evidenceSnippet?: string | null; risk: string;
    }[];
    adMonitoringResults: {
      id: number; platform: string; adId?: string | null; adType?: string | null;
      title?: string | null; body?: string | null; advertiserName?: string | null;
      advertiserPage?: string | null; impressions?: string | null; spend?: string | null;
      currency?: string | null; startDate?: string | null; endDate?: string | null;
      sourceUrl?: string | null; risk: string;
    }[];
  };

  const sections: string[] = [];

  const typoHeaders = [
    "pillar","permutation","fuzzer_type","dns_a","has_mx","spf_policy",
    "risk_score","is_suspicious","geo_country","vt_malicious",
    "registrar","registered_date","domain_age_days",
    "is_phishing","phishing_source","registration_status",
  ];
  const typoRows = d.topResults.map(r => [
    "typosquatting", r.permutation, r.fuzzer,
    (r.dnsA ?? []).join("; "),
    r.dnsMx && r.dnsMx.length > 0 ? "yes" : "no",
    r.mxSpf ?? "",
    r.riskScore, r.isSuspicious ? "yes" : "no",
    r.geoCountry ?? "", r.vtMalicious ?? "",
    r.whoisRegistrar ?? "", r.whoisCreated ?? "",
    r.whoisAgeDays ?? "",
    r.isPhishing ? "yes" : "no", r.phishingSource ?? "", r.registrationStatus ?? "",
  ]);
  sections.push("# TYPOSQUATTING PERMUTATIONS\n" + toCsvRows(typoHeaders, typoRows));

  const phishHeaders = ["pillar","url","source","threat_type","verified","target_brand","submitted_at"];
  const phishRows = d.phishingDetections.map(p => [
    "phishing", p.url, p.source, p.threatType ?? "",
    p.verified ? "yes" : "no", p.targetBrand ?? "", p.submittedAt ?? "",
  ]);
  sections.push("# PHISHING DETECTIONS\n" + toCsvRows(phishHeaders, phishRows));

  const leakHeaders = [
    "pillar","title","source","severity","breach_date",
    "domain_match","email_match","exposed_data","url","description",
  ];
  const leakRows = d.dataLeaks.map(l => [
    "data_leak", l.title, l.source, l.severity, l.breachDate ?? "",
    l.domainMatch ?? "", l.emailMatch ?? "",
    (l.exposedData ?? []).join("; "), l.url ?? "", l.description ?? "",
  ]);
  sections.push("# DATA LEAKS\n" + toCsvRows(leakHeaders, leakRows));

  const abuseHeaders = ["pillar","type","platform","risk","url","title","description","evidence_snippet"];
  const abuseRows = d.brandAbuse.map(a => [
    "brand_abuse", a.type, a.platform ?? "", a.risk,
    a.url ?? "", a.title ?? "", a.description ?? "", a.evidenceSnippet ?? "",
  ]);
  sections.push("# BRAND ABUSE\n" + toCsvRows(abuseHeaders, abuseRows));

  const adHeaders = [
    "pillar","platform","ad_type","advertiser","title","impressions",
    "spend","currency","start_date","end_date","risk","source_url","body",
  ];
  const adRows = (d.adMonitoringResults ?? []).map(a => [
    "malicious_ads", a.platform, a.adType ?? "", a.advertiserName ?? "",
    a.title ?? "", a.impressions ?? "", a.spend ?? "", a.currency ?? "",
    a.startDate ?? "", a.endDate ?? "", a.risk, a.sourceUrl ?? "", a.body ?? "",
  ]);
  sections.push("# MALICIOUS ADS\n" + toCsvRows(adHeaders, adRows));

  const csvContent = sections.join("\n\n");
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `brand-threat-${d.scan.domain}-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 8000);
}

// ── Brand Threat PDF ─────────────────────────────────────────────────────
export async function downloadBrandThreatPdf(scanId: number, token: string | null): Promise<void> {
  const [logo, res] = await Promise.all([
    getLogo(),
    fetch(`/api/reports/pdf-data/brand-threat/${scanId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
  ]);
  if (!res.ok) throw new Error("Failed to fetch brand threat PDF data");

  const d = await res.json() as {
    scan: {
      id: number; domain: string; status: string;
      totalPermutations: number; liveCount: number; registeredCount: number;
      phishingRisk: string; dataLeakCount: number; phishingCount: number;
      brandAbuseCount: number; darkWebCount: number;
      fuzzerBreakdown?: Record<string, number>;
      faviconUrl?: string; faviconMmh3?: number; faviconMd5?: string; faviconSha256?: string;
      faviconSearchUrls?: Record<string, { url: string; hash_type: string }>;
      favihunterStatus?: string; createdAt: string; completedAt?: string;
    };
    topResults:  {
      permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[];
      mxSpf?: string; riskScore: number; isSuspicious: boolean; geoCountry?: string;
      vtMalicious?: number; whoisRegistrar?: string; whoisCreated?: string;
      whoisAgeDays?: number; isPhishing?: boolean; phishingSource?: string; registrationStatus?: string;
    }[];
    liveResults: {
      permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[];
      mxSpf?: string; riskScore: number; isSuspicious: boolean; geoCountry?: string;
      vtMalicious?: number; whoisRegistrar?: string; whoisCreated?: string; whoisAgeDays?: number;
    }[];
    phishingDetections: {
      id: number; url: string; source: string; threatType?: string | null;
      verified: boolean; targetBrand?: string | null; submittedAt?: string | null;
    }[];
    dataLeaks: {
      id: number; source: string; title: string; breachDate?: string | null;
      description?: string | null; exposedData?: string[] | null;
      domainMatch?: string | null; emailMatch?: string | null; severity: string; url?: string | null;
    }[];
    brandAbuse: {
      id: number; type: string; platform?: string | null; url?: string | null;
      title?: string | null; description?: string | null; evidenceSnippet?: string | null; risk: string;
    }[];
    adMonitoringResults: {
      id: number; platform: string; adId?: string | null; adType?: string | null;
      title?: string | null; body?: string | null; advertiserName?: string | null;
      advertiserPage?: string | null; impressions?: string | null; spend?: string | null;
      currency?: string | null; startDate?: string | null; endDate?: string | null;
      sourceUrl?: string | null; risk: string;
    }[];
  };

  const phishRisk  = d.scan.phishingRisk ?? "low";
  const rc         = sevColor(phishRisk);
  const phishCount = d.scan.phishingCount   ?? d.phishingDetections.length;
  const leakCount  = d.scan.dataLeakCount   ?? d.dataLeaks.length;
  const abuseCount = d.scan.brandAbuseCount ?? d.brandAbuse.length;
  const suspCount  = d.topResults.filter(r => r.isSuspicious).length;

  const cover = makeCover({
    title:      `${d.scan.domain} — Brand Threat Intelligence Report`,
    reportKind: "Domain & Phishing Threat Analysis",
    metaPairs:  [
      ["Target Domain",       d.scan.domain],
      ["Phishing Risk",       phishRisk.toUpperCase()],
      ["Permutations Tested", String(d.scan.totalPermutations)],
      ["Live Domains",        String(d.scan.liveCount)],
      ["Phishing Detections", String(phishCount)],
      ["Data Leaks",          String(leakCount)],
      ["Brand Abuse Cases",   String(abuseCount)],
      ["Scan Date",           new Date(d.scan.createdAt).toLocaleDateString()],
    ],
    riskLabel:  `Phishing Risk: ${phishRisk.toUpperCase()}`,
    riskColor:  rc,
    logo,
  });

  const doc = new PdfDoc(`${d.scan.domain} — Brand Threat Report`, logo);
  doc.newPage();

  // Scan Summary
  doc.sectionHeader("Scan Summary");
  doc.gap(6);
  doc.statCards([
    { label: "Total Permutations", value: d.scan.totalPermutations, color: NAVY },
    { label: "Live Domains",       value: d.scan.liveCount,         color: CRIT },
    { label: "Registered",         value: d.scan.registeredCount,   color: HIGH },
    { label: "Suspicious",         value: suspCount,                color: MED  },
  ]);
  doc.statCards([
    { label: "Phishing Detections", value: phishCount,               color: CRIT },
    { label: "Data Leaks",          value: leakCount,                color: HIGH },
    { label: "Brand Abuse Cases",   value: abuseCount,               color: MED  },
    { label: "Dark Web Mentions",   value: d.scan.darkWebCount ?? 0, color: NAVY },
  ]);
  doc.gap(12);

  // Domain Intelligence metadata
  doc.sectionHeader("Domain Intelligence");
  doc.gap(6);
  doc.keyValue([
    ["Target Domain",      d.scan.domain],
    ["Phishing Risk",      phishRisk.toUpperCase()],
    ["Scan Started",       new Date(d.scan.createdAt).toLocaleString()],
    ["Scan Completed",     d.scan.completedAt ? new Date(d.scan.completedAt).toLocaleString() : "In Progress"],
    ["Total Permutations", String(d.scan.totalPermutations)],
    ["Live / Resolving",   String(d.scan.liveCount)],
  ], 3);
  doc.gap(12);

  // Favicon Intelligence
  if (d.scan.favihunterStatus === "done" && d.scan.faviconMd5) {
    doc.sectionHeader("Favicon Intelligence", PURPLE);
    doc.gap(6);
    doc.keyValue([
      ["Favicon URL", d.scan.faviconUrl ?? "—"],
      ["MMH3 Hash",   String(d.scan.faviconMmh3 ?? "—")],
      ["MD5 Hash",    d.scan.faviconMd5 ?? "—"],
      ["SHA256",      d.scan.faviconSha256 ? d.scan.faviconSha256.slice(0, 44) + "…" : "—"],
    ], 2);
    if (d.scan.faviconSearchUrls) {
      doc.gap(8);
      doc.text("Search Engine Pivot URLs (find infrastructure sharing this favicon):", { size: 9, color: TEXT2, weight: "bold" });
      for (const [name, info] of Object.entries(d.scan.faviconSearchUrls)) {
        doc.gap(3);
        doc.text(`• ${name}  [${info.hash_type}]`, { size: 9, color: NAVY, indent: 10 });
        doc.text(info.url, { size: 8, color: TEXT2, indent: 22 });
      }
    }
    doc.gap(12);
  }

  // Fuzzer Breakdown
  if (d.scan.fuzzerBreakdown) {
    doc.sectionHeader("Permutation Type Breakdown");
    doc.gap(6);
    const fuzzers = Object.entries(d.scan.fuzzerBreakdown)
      .filter(([k]) => !k.startsWith("*"))
      .sort(([, a], [, b]) => (b as number) - (a as number));
    doc.table(
      ["Fuzzer Type", "Count", "% of Total"],
      [320, 130, 120],
      fuzzers.map(([k, v]) => [
        k.charAt(0).toUpperCase() + k.slice(1),
        String(v),
        `${(((v as number) / Math.max(d.scan.totalPermutations, 1)) * 100).toFixed(1)}%`,
      ]),
    );
    doc.gap(12);
  }

  // Notable Domains
  const live    = d.liveResults;
  const susp    = d.topResults.filter(r => r.isSuspicious);
  const notable = [
    ...live,
    ...susp.filter(r => !live.find(lr => lr.permutation === r.permutation)),
  ].slice(0, 80);

  if (notable.length > 0) {
    doc.sectionHeader("Notable Domains — Live & Suspicious", CRIT);
    doc.gap(6);
    doc.table(
      ["Domain", "Type", "IP Addresses", "Risk", "MX / SPF"],
      [198, 88, 166, 56, 128],
      notable.map(r => [
        r.permutation,
        r.fuzzer,
        r.dnsA?.join(", ") ?? "—",
        String(r.riskScore),
        r.mxSpf ?? (r.dnsMx?.length ? "Has MX" : "—"),
      ]),
      { monoCol: [0, 2] },
    );
    doc.gap(6);
    if (notable.length < (live.length + susp.length)) {
      doc.text(`…and ${live.length + susp.length - notable.length} more live/suspicious domains not shown.`, { size: 8.5, color: TEXT2 });
    }
  } else {
    doc.gap(8);
    doc.text(
      "No live or suspicious domains detected. The brand appears well-protected from active typosquatting at the time of this scan.",
      { size: 10, color: LOW },
    );
  }
  doc.gap(12);

  // Pillar 2: Phishing Detections
  if (d.phishingDetections.length > 0) {
    doc.sectionHeader("Phishing Detections", CRIT);
    doc.gap(6);
    doc.text(
      `${d.phishingDetections.length} active phishing URL${d.phishingDetections.length !== 1 ? "s" : ""} detected targeting the "${d.scan.domain}" brand.`,
      { size: 9, color: TEXT2 },
    );
    doc.gap(8);

    const verified   = d.phishingDetections.filter(p => p.verified);
    const unverified = d.phishingDetections.filter(p => !p.verified);

    if (verified.length > 0) {
      doc.subsectionHeader(`Confirmed Phishing (${verified.length})`, CRIT);
      doc.gap(3);
      doc.table(
        ["URL", "Source Feed", "Threat Type", "Target Brand", "Submitted"],
        [212, 92, 90, 102, 110],
        verified.slice(0, 30).map(p => [
          p.url, p.source, p.threatType ?? "Phishing",
          p.targetBrand ?? "—",
          p.submittedAt ? new Date(p.submittedAt).toLocaleDateString() : "—",
        ]),
        { monoCol: [0] },
      );
      doc.gap(8);
    }

    if (unverified.length > 0) {
      doc.subsectionHeader(`Reported / Unconfirmed (${unverified.length})`, HIGH);
      doc.gap(3);
      doc.table(
        ["URL", "Source Feed", "Threat Type", "Submitted"],
        [242, 120, 110, 134],
        unverified.slice(0, 20).map(p => [
          p.url, p.source, p.threatType ?? "Phishing",
          p.submittedAt ? new Date(p.submittedAt).toLocaleDateString() : "—",
        ]),
        { monoCol: [0] },
      );
      doc.gap(8);
    }

    if (d.phishingDetections.length > 50) {
      doc.text(`…and ${d.phishingDetections.length - 50} more phishing URLs not shown in this report.`, { size: 8.5, color: TEXT2 });
    }
    doc.gap(8);
  }

  // Pillar 3: Data Leaks
  if (d.dataLeaks.length > 0) {
    doc.sectionHeader("Data Leak Intelligence", HIGH);
    doc.gap(6);
    doc.text(
      `${d.dataLeaks.length} breach record${d.dataLeaks.length !== 1 ? "s" : ""} found associated with "${d.scan.domain}". Review each entry and notify affected users.`,
      { size: 9, color: TEXT2 },
    );
    doc.gap(8);

    const critLeaks  = d.dataLeaks.filter(l => l.severity === "critical" || l.severity === "high");
    const otherLeaks = d.dataLeaks.filter(l => l.severity !== "critical" && l.severity !== "high");

    if (critLeaks.length > 0) {
      doc.subsectionHeader(`Critical / High-Severity Breaches (${critLeaks.length})`, CRIT);
      doc.gap(4);
      for (const leak of critLeaks.slice(0, 10)) {
        doc.findingCard({
          title:       leak.title,
          severity:    leak.severity,
          description: [
            leak.source   ? `Source: ${leak.source}` : null,
            leak.breachDate ? `Breach Date: ${new Date(leak.breachDate).toLocaleDateString()}` : null,
            leak.domainMatch ? `Domain: ${leak.domainMatch}` : null,
            leak.exposedData?.length ? `Exposed: ${leak.exposedData.slice(0, 6).join(", ")}` : null,
            leak.description?.slice(0, 160) ?? null,
          ].filter(Boolean).join(" · ") || null,
        });
      }
      doc.gap(8);
    }

    if (otherLeaks.length > 0) {
      doc.subsectionHeader(`Other Breaches (${otherLeaks.length})`, TEXT2);
      doc.gap(4);
      doc.table(
        ["Title", "Source", "Breach Date", "Severity", "Exposed Data"],
        [162, 94, 82, 72, 196],
        otherLeaks.slice(0, 25).map(l => [
          l.title, l.source,
          l.breachDate ? new Date(l.breachDate).toLocaleDateString() : "—",
          l.severity,
          l.exposedData ? l.exposedData.slice(0, 4).join(", ") : "—",
        ]),
        { severityCol: 3 },
      );
      doc.gap(8);
    }

    if (d.dataLeaks.length > 35) {
      doc.text(`…and ${d.dataLeaks.length - 35} additional breach records not shown.`, { size: 8.5, color: TEXT2 });
    }
    doc.gap(8);
  }

  // Pillar 4: Brand Abuse
  if (d.brandAbuse.length > 0) {
    doc.sectionHeader("Brand Abuse Findings", AMBER);
    doc.gap(6);
    doc.text(
      `${d.brandAbuse.length} brand abuse case${d.brandAbuse.length !== 1 ? "s" : ""} identified across social media, certificate transparency, app stores, and lookalike infrastructure.`,
      { size: 9, color: TEXT2 },
    );
    doc.gap(8);

    const byType: Record<string, typeof d.brandAbuse> = {};
    for (const b of d.brandAbuse) {
      (byType[b.type] ??= []).push(b);
    }

    for (const [type, items] of Object.entries(byType)) {
      const label = type.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
      doc.subsectionHeader(`${label} (${items.length})`, TEXT);
      doc.gap(3);
      doc.table(
        ["Title / Description", "Platform", "Risk", "URL / Evidence"],
        [192, 82, 62, 270],
        items.slice(0, 15).map(b => [
          b.title ?? b.description ?? "—",
          b.platform ?? "—",
          b.risk,
          b.url ?? b.evidenceSnippet ?? "—",
        ]),
        { severityCol: 2, monoCol: [3] },
      );
      doc.gap(8);
    }

    if (d.brandAbuse.length > 45) {
      doc.text(`…and ${d.brandAbuse.length - 45} more brand abuse cases not shown.`, { size: 8.5, color: TEXT2 });
    }
    doc.gap(8);
  }

  // Pillar 5: Malicious Ads
  const adResults = d.adMonitoringResults ?? [];
  if (adResults.length > 0) {
    doc.sectionHeader("Malicious Ad Monitoring", HIGH);
    doc.gap(6);
    doc.text(
      `${adResults.length} suspicious ad${adResults.length !== 1 ? "s" : ""} detected impersonating or abusing the "${d.scan.domain}" brand across ad platforms.`,
      { size: 9, color: TEXT2 },
    );
    doc.gap(8);

    const byPlatform: Record<string, typeof adResults> = {};
    for (const a of adResults) {
      (byPlatform[a.platform] ??= []).push(a);
    }

    for (const [platform, items] of Object.entries(byPlatform)) {
      doc.subsectionHeader(`${platform} (${items.length})`, TEXT);
      doc.gap(3);
      doc.table(
        ["Title / Body", "Advertiser", "Risk", "Impressions", "Period"],
        [208, 120, 62, 88, 128],
        items.slice(0, 20).map(a => {
          const period = a.startDate && a.endDate
            ? `${a.startDate} – ${a.endDate}`
            : a.startDate ?? a.endDate ?? "—";
          return [
            a.title ?? a.body ?? "—",
            a.advertiserName ?? "—",
            a.risk,
            a.impressions ?? "—",
            period,
          ];
        }),
        { severityCol: 2 },
      );
      doc.gap(8);
    }

    if (adResults.length > 60) {
      doc.text(`…and ${adResults.length - 60} more malicious ad records not shown.`, { size: 8.5, color: TEXT2 });
    }
    doc.gap(8);
  }

  const filename = `${d.scan.domain.replace(/\./g, "_")}_brand_threat_report.pdf`;
  triggerDownload(buildPdf([cover, ...doc.finalize()]), filename);
}

// ── Scan Report PDF ──────────────────────────────────────────────────────
function computeAsmScore(asset: any): number {
  let score = 100;
  score -= Math.min((asset.summary?.criticalVulns ?? 0) * 15, 40);
  score -= Math.min((asset.summary?.highVulns ?? 0) * 6, 20);
  score -= Math.min((asset.secrets ?? []).length * 8, 20);
  score -= Math.min((asset.vulnScan?.stats?.critical ?? 0) * 12, 30);
  score -= Math.min((asset.vulnScan?.stats?.high ?? 0) * 4, 15);
  score -= Math.min((asset.secretsHunt?.stats?.secretsFound ?? 0) * 5, 15);
  if ((asset.secretsHunt?.stats?.gitDirsExposed ?? 0) > 0) score -= 10;
  const waf = asset.httpInfo?.waf;
  if (!waf || waf === "none" || waf === "None") score -= 5;
  if ((asset.summary?.openPorts ?? 0) > 20) score -= 5;
  return Math.max(0, Math.min(100, Math.round(score)));
}

export async function downloadScanReportPdf(scan: any, assetReports: any[], token?: string | null): Promise<void> {
  // Load logo + optionally fetch brand threat data for primary domain
  const primaryDomain = assetReports[0]?.assetValue ?? "";
  const [logo, brandThreatDetail] = await Promise.all([
    getLogo(),
    (async () => {
      if (!primaryDomain || !token) return null;
      try {
        const r = await fetch(`/api/brand-threats?limit=5`, { headers: { Authorization: `Bearer ${token}` } });
        if (!r.ok) return null;
        const list: any[] = await r.json();
        const match = list.find((s: any) =>
          (s.domain ?? "").toLowerCase().includes(primaryDomain.replace(/^https?:\/\//,"").replace(/\/.*$/,"").toLowerCase().split(".").slice(-2).join("."))
        );
        if (!match) return null;
        const dr = await fetch(`/api/brand-threats/${match.id}`, { headers: { Authorization: `Bearer ${token}` } });
        return dr.ok ? dr.json() : null;
      } catch { return null; }
    })(),
  ]);

  // ── Aggregate stats across all assets ──────────────────────────────────
  const totalCritical  = assetReports.reduce((a, r) => a + (r.summary?.criticalVulns ?? 0) + (r.vulnScan?.stats?.critical ?? 0), 0);
  const totalHigh      = assetReports.reduce((a, r) => a + (r.summary?.highVulns ?? 0) + (r.vulnScan?.stats?.high ?? 0), 0);
  const totalMedium    = assetReports.reduce((a, r) => a + (r.cves ?? []).filter((c: any) => c.severity === "medium").length, 0);
  const totalCves      = assetReports.reduce((a, r) => a + (r.cves ?? []).length, 0);
  const totalPorts     = assetReports.reduce((a, r) => a + (r.summary?.openPorts ?? 0), 0);
  const totalSubs      = assetReports.reduce((a, r) => a + (r.summary?.subdomains ?? 0), 0);
  const totalDns       = assetReports.reduce((a, r) => a + (r.summary?.dnsRecords ?? 0), 0);
  const totalEndpoints = assetReports.reduce((a, r) => a + (r.summary?.endpoints ?? 0), 0);
  const totalSecrets   = assetReports.reduce((a, r) => a + (r.secrets ?? []).length + (r.secretsHunt?.stats?.secretsFound ?? 0), 0);
  const avgAsm         = assetReports.length > 0
    ? Math.round(assetReports.map(computeAsmScore).reduce((a, b) => a + b, 0) / assetReports.length)
    : 100;
  const ws  = totalCritical > 0 ? "critical" : totalHigh > 0 ? "high" : "medium";
  const rc  = sevColor(ws);
  const ts  = scan?.completedAt ? new Date(scan.completedAt).toLocaleString() : new Date().toLocaleString();
  const scanName        = scan?.name ?? `Scan #${scan?.id}`;
  const primaryAssetName = assetReports[0]?.assetName ?? scanName;
  const asmColor        = avgAsm >= 70 ? LOW : avgAsm >= 40 ? MED : CRIT;

  // ── Cover page ───────────────────────────────────────────────────────────
  const cover = makeCover({
    title:      scanName,
    reportKind: "Pipeline Vulnerability Scan Report",
    metaPairs:  [
      ["Scan Name",       scanName],
      ["Completed",       ts],
      ["Assets Scanned",  String(assetReports.length)],
      ["Total CVEs",      String(totalCves)],
      ["Critical / High", `${totalCritical} / ${totalHigh}`],
      ["Secrets Found",   String(totalSecrets)],
    ],
    riskLabel:  `Threat Level: ${ws.toUpperCase()}`,
    riskColor:  rc,
    logo,
  });

  const doc = new PdfDoc(scanName, logo);
  doc.newPage();

  // ════════════════════════════════════════════════════════════════════════
  // CARD 01 — Total Risk Score / Asset Name / Timestamp
  // ════════════════════════════════════════════════════════════════════════
  doc.cardHeader(1, "Total Risk Score & Scan Overview", BLUE);
  doc.gap(6);
  doc.statCards([
    { label: "ASM Risk Score",   value: `${avgAsm}/100`,          color: asmColor },
    { label: "Assets Scanned",   value: assetReports.length,      color: NAVY     },
    { label: "Scan Status",      value: (scan?.status ?? "DONE").toUpperCase(), color: INFO_C },
  ]);
  doc.gap(6);
  doc.keyValue([
    ["Primary Asset",  primaryAssetName],
    ["Scan Name",      scanName],
    ["Completed At",   ts],
    ["Scan Type",      scan?.type ?? "Full Pipeline"],
    ["Scan ID",        String(scan?.id ?? "—")],
    ["Report Date",    new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" })],
  ], 3);
  if (assetReports.length > 1) {
    doc.gap(6);
    doc.subsectionHeader("Asset List", NAVY);
    doc.gap(3);
    doc.table(
      ["Asset Name", "Target", "ASM Score", "Open Ports", "CVEs", "Secrets"],
      [170, 200, 76, 74, 66, 66],
      assetReports.map(r => [
        r.assetName ?? "—",
        r.assetValue ?? "—",
        `${computeAsmScore(r)}/100`,
        String(r.summary?.openPorts ?? 0),
        String((r.cves ?? []).length),
        String((r.secrets ?? []).length + (r.secretsHunt?.stats?.secretsFound ?? 0)),
      ]),
    );
  }
  doc.gap(16);

  // ════════════════════════════════════════════════════════════════════════
  // CARD 02 — Critical / High Findings / Risk Level / Assets Scanned
  // ════════════════════════════════════════════════════════════════════════
  doc.cardHeader(2, "Findings Summary", CRIT,
    `${totalCritical} Critical · ${totalHigh} High · ${totalMedium} Medium · ${totalCves} Total CVEs`);
  doc.gap(6);
  doc.statCards([
    { label: "Critical Findings", value: totalCritical,           color: CRIT   },
    { label: "High Findings",     value: totalHigh,               color: HIGH   },
    { label: "Threat Level",      value: ws.toUpperCase(),        color: rc     },
    { label: "Assets Scanned",    value: assetReports.length,     color: NAVY   },
  ]);
  doc.gap(6);
  doc.statCards([
    { label: "Medium Findings",   value: totalMedium,             color: MED    },
    { label: "Total CVEs",        value: totalCves,               color: HIGH   },
    { label: "Secrets Found",     value: totalSecrets,            color: MED    },
    { label: "Scan Duration",     value: scan?.startedAt && scan?.completedAt
        ? formatScanDuration(scan.startedAt, scan.completedAt) : "—",           color: INFO_C },
  ]);
  doc.gap(16);

  // ════════════════════════════════════════════════════════════════════════
  // CARD 03 — Attack Surface Summary Stats
  // ════════════════════════════════════════════════════════════════════════
  doc.cardHeader(3, "Attack Surface Summary", PURPLE,
    "Aggregated statistics across all scanned assets");
  doc.gap(6);
  doc.statCards([
    { label: "Open Ports",   value: totalPorts,     color: INFO_C },
    { label: "CVEs Found",   value: totalCves,      color: CRIT   },
    { label: "Subdomains",   value: totalSubs,      color: BLUE   },
  ]);
  doc.gap(6);
  doc.statCards([
    { label: "DNS Records",  value: totalDns,       color: MED    },
    { label: "Endpoints",    value: totalEndpoints, color: INFO_C },
    { label: "Secrets",      value: totalSecrets,   color: HIGH   },
  ]);
  doc.gap(16);

  // ════════════════════════════════════════════════════════════════════════
  // CARDS 04-15: Per-asset detail sections
  // ════════════════════════════════════════════════════════════════════════
  for (const asset of assetReports) {
    const assetSuffix = assetReports.length > 1 ? ` — ${asset.assetName ?? "Unknown"}` : "";
    const ports: any[]      = (asset.ports ?? []).filter((p: any) => p.state === "open" || !p.state);
    const cves: any[]       = asset.cves ?? [];
    const secrets: any[]    = asset.secrets ?? [];
    const techList: any[]   = asset.technologies ?? [];
    const dnsRecords: any[] = asset.dnsRecords ?? [];
    const subdomains: any[] = asset.subdomains ?? [];
    const endpoints: any[]  = asset.endpoints ?? [];
    const intelItems: any[] = asset.intelligence ?? [];
    const httpInfo: any     = asset.httpInfo ?? {};
    const httpHeaders: any  = asset.httpHeaders ?? {};
    const cloudRecon: any   = asset.cloudRecon ?? null;
    const secretsHunt: any  = asset.secretsHunt ?? null;
    const dirFuzz: any      = asset.dirFuzz ?? null;

    // ── CARD 04: Open Ports ─────────────────────────────────────────────
    if (ports.length > 0) {
      doc.cardHeader(4, `Open Ports${assetSuffix}`, INFO_C,
        `${ports.length} open port${ports.length !== 1 ? "s" : ""} detected`);
      doc.gap(4);
      doc.table(
        ["Port", "Protocol", "Service", "Version / Banner", "State"],
        [52, 60, 100, 390, 56],
        ports.slice(0, 35).map((p: any) => [
          String(p.port ?? "—"), p.protocol ?? "tcp",
          p.service ?? "unknown", p.version ?? p.banner ?? "—",
          p.state ?? "open",
        ]),
        { monoCol: [0, 1, 4] },
      );
      if (ports.length > 35) {
        doc.gap(3); doc.text(`…and ${ports.length - 35} more ports not shown`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 05: CVEs ──────────────────────────────────────────────────
    if (cves.length > 0) {
      const crit5 = cves.filter((c: any) => c.severity === "critical").length;
      const high5 = cves.filter((c: any) => c.severity === "high").length;
      const med5  = cves.filter((c: any) => c.severity === "medium").length;
      doc.cardHeader(5, `CVEs & Vulnerabilities${assetSuffix}`, CRIT,
        `${crit5} Critical · ${high5} High · ${med5} Medium · ${cves.length} Total`);
      doc.gap(4);
      doc.table(
        ["CVE / ID", "Title", "Severity", "CVSS", "CWE"],
        [116, 298, 76, 54, 56],
        cves.slice(0, 35).map((c: any) => [
          c.cve ?? c.cveId ?? c.id ?? "—",
          c.title ?? c.description ?? "—",
          c.severity ?? "—",
          c.cvss != null ? Number(c.cvss).toFixed(1) : "—",
          c.cwe ?? "—",
        ]),
        { severityCol: 2, monoCol: [0, 4] },
      );
      if (cves.length > 35) {
        doc.gap(3); doc.text(`…and ${cves.length - 35} more CVEs not shown`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 06: Secrets & Credentials ─────────────────────────────────
    if (secrets.length > 0) {
      doc.cardHeader(6, `Secrets & Credentials${assetSuffix}`, MED,
        `${secrets.length} exposed secret${secrets.length !== 1 ? "s" : ""} detected`);
      doc.gap(4);
      doc.table(
        ["Type", "File / Location", "Value (truncated)"],
        [130, 228, 316],
        secrets.slice(0, 25).map((s: any) => [
          s.type ?? "Secret",
          s.file ?? "—",
          s.value ? String(s.value).slice(0, 55) : "—",
        ]),
        { monoCol: [2] },
      );
      if (secrets.length > 25) {
        doc.gap(3); doc.text(`…and ${secrets.length - 25} more secrets not shown`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 07: Technologies ─────────────────────────────────────────
    const vs = asset.vulnScan;
    const hasTech = techList.length > 0;
    const hasVulnStats = vs?.stats && (vs.stats.critical + vs.stats.high + vs.stats.medium + vs.stats.low) > 0;
    if (hasTech || hasVulnStats) {
      doc.cardHeader(7, `Technologies${assetSuffix}`, BLUE,
        hasTech ? `${techList.length} technologies detected` : "Vulnerability template scan results");
      doc.gap(4);
      if (hasTech) {
        doc.table(
          ["Technology", "Category", "Version", "Confidence"],
          [220, 204, 130, 92],
          techList.slice(0, 30).map((t: any) => [
            t.name ?? t.technology ?? "—",
            t.category ?? "—",
            t.version ?? "—",
            t.confidence != null ? `${t.confidence}%` : "—",
          ]),
        );
        if (techList.length > 30) {
          doc.gap(3); doc.text(`…and ${techList.length - 30} more technologies`, { size: 8.5, color: TEXT2 });
        }
        doc.gap(6);
      }
      if (hasVulnStats) {
        doc.subsectionHeader("Vulnerability Template Scan (Nuclei)", TEXT);
        doc.gap(4);
        doc.statCards([
          { label: "Critical", value: vs.stats.critical ?? 0, color: CRIT },
          { label: "High",     value: vs.stats.high     ?? 0, color: HIGH },
          { label: "Medium",   value: vs.stats.medium   ?? 0, color: MED  },
          { label: "Low",      value: vs.stats.low      ?? 0, color: LOW  },
        ]);
        if ((vs.findings ?? []).length > 0) {
          doc.gap(4);
          doc.table(
            ["Template", "Severity", "Host / URL"],
            [220, 76, 358],
            (vs.findings as any[]).slice(0, 20).map((f: any) => [
              f.templateId ?? f.name ?? "—",
              f.severity ?? "—",
              f.host ?? f.url ?? "—",
            ]),
            { severityCol: 1 },
          );
        }
      }
      doc.gap(16);
    }

    // ── CARD 08: DNS Records ────────────────────────────────────────────
    if (dnsRecords.length > 0) {
      doc.cardHeader(8, `DNS Records${assetSuffix}`, BLUE,
        `${dnsRecords.length} DNS record${dnsRecords.length !== 1 ? "s" : ""} discovered`);
      doc.gap(4);
      doc.table(
        ["Type", "Name", "Value", "TTL"],
        [60, 180, 336, 66],
        dnsRecords.slice(0, 35).map((d: any) => [
          d.type ?? "—",
          d.name ?? "—",
          d.value ?? d.data ?? "—",
          d.ttl != null ? String(d.ttl) : "—",
        ]),
        { monoCol: [0, 2] },
      );
      if (dnsRecords.length > 35) {
        doc.gap(3); doc.text(`…and ${dnsRecords.length - 35} more records`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 09: Subdomains ──────────────────────────────────────────────
    if (subdomains.length > 0) {
      const live9 = subdomains.filter((s: any) => s.isLive).length;
      doc.cardHeader(9, `Subdomains${assetSuffix}`, BLUE,
        `${subdomains.length} discovered · ${live9} live`);
      doc.gap(4);
      doc.table(
        ["Subdomain", "IP Address", "Live", "Status", "Title"],
        [222, 116, 44, 60, 168],
        subdomains.slice(0, 35).map((s: any) => [
          s.name ?? s.subdomain ?? "—",
          s.ip ?? s.ipAddress ?? "—",
          s.isLive ? "YES" : "NO",
          s.statusCode != null ? String(s.statusCode) : "—",
          s.title ?? "—",
        ]),
        { monoCol: [1, 2] },
      );
      if (subdomains.length > 35) {
        doc.gap(3); doc.text(`…and ${subdomains.length - 35} more subdomains`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 10: HTTP Info ────────────────────────────────────────────────
    const httpPairs: [string, string][] = [];
    if (httpInfo.statusCode)                        httpPairs.push(["Status Code",    String(httpInfo.statusCode)]);
    if (httpInfo.title)                             httpPairs.push(["Page Title",     httpInfo.title]);
    if (httpInfo.server)                            httpPairs.push(["Server",         httpInfo.server]);
    if (httpInfo.contentType)                       httpPairs.push(["Content-Type",   httpInfo.contentType]);
    if (httpInfo.waf && httpInfo.waf !== "none")    httpPairs.push(["WAF / Firewall", httpInfo.waf]);
    if (httpInfo.cdn)                               httpPairs.push(["CDN",            httpInfo.cdn]);
    if (httpInfo.ip)                                httpPairs.push(["Resolved IP",    httpInfo.ip]);
    if (httpInfo.tlsVersion)                        httpPairs.push(["TLS Version",    httpInfo.tlsVersion]);
    if (httpInfo.redirectUrl)                       httpPairs.push(["Redirect URL",   httpInfo.redirectUrl]);
    Object.entries(httpHeaders).slice(0, 10).forEach(([k, v]) => httpPairs.push([k, String(v)]));
    if (httpPairs.length > 0) {
      doc.cardHeader(10, `HTTP Info${assetSuffix}`, INFO_C,
        `${httpPairs.length} properties collected`);
      doc.gap(4);
      doc.keyValue(httpPairs, 3);
      doc.gap(16);
    }

    // ── CARD 11: Endpoints ────────────────────────────────────────────────
    if (endpoints.length > 0) {
      const interesting = endpoints.filter((e: any) => e.isInteresting || e.statusCode === 200 || e.statusCode === 403);
      const toShow = endpoints.slice(0, 35);
      doc.cardHeader(11, `Endpoints${assetSuffix}`, INFO_C,
        `${endpoints.length} endpoints · ${interesting.length} interesting`);
      doc.gap(4);
      doc.table(
        ["URL", "Method", "Status", "Content-Type", "Source"],
        [302, 52, 54, 168, 58],
        toShow.map((e: any) => [
          e.url ?? e.path ?? "—",
          e.method ?? "GET",
          e.statusCode != null ? String(e.statusCode) : "—",
          e.contentType ?? "—",
          e.source ?? "—",
        ]),
        { monoCol: [0, 1, 2] },
      );
      if (endpoints.length > 35) {
        doc.gap(3); doc.text(`…and ${endpoints.length - 35} more endpoints`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 12: Intelligence ─────────────────────────────────────────────
    if (intelItems.length > 0) {
      doc.cardHeader(12, `Intelligence${assetSuffix}`, PURPLE,
        `${intelItems.length} intelligence item${intelItems.length !== 1 ? "s" : ""}`);
      doc.gap(4);
      doc.table(
        ["Type", "Source", "Data"],
        [120, 120, 434],
        intelItems.slice(0, 30).map((item: any) => [
          item.type ?? "—",
          item.source ?? "—",
          (typeof item.data === "object"
            ? JSON.stringify(item.data)
            : String(item.data ?? "—")
          ).slice(0, 90),
        ]),
      );
      if (intelItems.length > 30) {
        doc.gap(3); doc.text(`…and ${intelItems.length - 30} more items`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(16);
    }

    // ── CARD 13: Cloud Assets ─────────────────────────────────────────────
    if (cloudRecon) {
      const buckets: any[]  = cloudRecon.buckets ?? [];
      const firebase: any[] = cloudRecon.firebase ?? [];
      const ssrf: any[]     = cloudRecon.ssrfEndpoints ?? [];
      const cStats: any     = cloudRecon.stats ?? {};
      const totalCloud      = buckets.length + firebase.length + ssrf.length;
      doc.cardHeader(13, `Cloud Assets${assetSuffix}`, BLUE,
        `${cStats.existingBuckets ?? buckets.length} buckets · ${firebase.length} Firebase · ${ssrf.length} SSRF endpoints`);
      doc.gap(4);
      if (totalCloud === 0) {
        doc.text("No cloud assets (S3 / GCS / Azure / Firebase) detected.", { size: 9.5, color: TEXT2 });
      } else {
        if (buckets.length > 0) {
          doc.subsectionHeader(`Storage Buckets (${buckets.length})`);
          doc.gap(3);
          doc.table(
            ["Provider", "Bucket Name", "Status", "URL"],
            [80, 196, 76, 306],
            buckets.slice(0, 20).map((b: any) => [
              b.provider ?? "—", b.name ?? b.bucket ?? "—",
              b.status ?? (b.accessible ? "ACCESSIBLE" : "exists"),
              b.url ?? "—",
            ]),
            { monoCol: [2] },
          );
          doc.gap(6);
        }
        if (firebase.length > 0) {
          doc.subsectionHeader(`Firebase Endpoints (${firebase.length})`);
          doc.gap(3);
          doc.table(
            ["Endpoint", "Status", "Data Exposed"],
            [438, 80, 156],
            firebase.slice(0, 10).map((f: any) => [
              f.url ?? f.endpoint ?? "—", f.status ?? "—", f.dataExposed ? "YES" : "NO",
            ]),
          );
          doc.gap(6);
        }
        if (ssrf.length > 0) {
          doc.subsectionHeader(`SSRF / Internal Endpoints (${ssrf.length})`);
          doc.gap(3);
          doc.table(
            ["URL", "Source"],
            [560, 114],
            ssrf.slice(0, 10).map((e: any) => [e.url ?? String(e), e.source ?? "—"]),
          );
        }
      }
      doc.gap(16);
    }

    // ── CARD 14: Secrets Hunt ─────────────────────────────────────────────
    if (secretsHunt) {
      const shStats: any  = secretsHunt.stats ?? {};
      const ghSecrets: any[] = secretsHunt.githubSecrets ?? [];
      const gitDirs: any[]   = secretsHunt.gitDirectories ?? [];
      doc.cardHeader(14, `Secrets Hunt${assetSuffix}`, MED,
        `${shStats.secretsFound ?? 0} secrets · ${shStats.gitDirsExposed ?? 0} .git dirs exposed`);
      doc.gap(4);
      doc.keyValue([
        ["Secrets Found",    String(shStats.secretsFound    ?? 0)],
        [".git Dirs Exposed", String(shStats.gitDirsExposed  ?? 0)],
        ["Verified Secrets",  String(shStats.verifiedSecrets ?? 0)],
        ["GitHub Org",        secretsHunt.githubOrg?.login   ?? "—"],
      ], 4);
      if (ghSecrets.length > 0) {
        doc.gap(5);
        doc.subsectionHeader(`GitHub Leaked Secrets (${ghSecrets.length})`);
        doc.gap(3);
        doc.table(
          ["Secret Type", "File / Path", "Snippet"],
          [136, 220, 318],
          ghSecrets.slice(0, 20).map((s: any) => [
            s.type ?? s.secretType ?? "—",
            s.file ?? s.path ?? "—",
            String(s.snippet ?? s.value ?? "—").slice(0, 60),
          ]),
          { monoCol: [2] },
        );
      }
      if (gitDirs.length > 0) {
        doc.gap(5);
        doc.subsectionHeader(`Exposed .git Directories (${gitDirs.length})`);
        doc.gap(3);
        doc.table(
          ["URL", "Status"],
          [572, 92],
          gitDirs.slice(0, 15).map((d: any) => [d.url ?? String(d), "EXPOSED"]),
          { monoCol: [1] },
        );
      }
      doc.gap(16);
    }

    // ── CARD 15: Directory Fuzzing ────────────────────────────────────────
    if (dirFuzz) {
      const dfStats: any = dirFuzz.stats ?? {};
      const dfHosts: any[] = dirFuzz.hosts ?? [];
      const allFuzz: any[] = [];
      dfHosts.forEach((h: any) => {
        (h.endpoints ?? []).forEach((e: any) => {
          allFuzz.push({
            url:    e.url ?? `${h.host ?? ""}${e.path ?? ""}`,
            status: e.statusCode,
            size:   e.contentLength,
            source: e.source ?? "fuzz",
            host:   h.host,
          });
        });
      });
      doc.cardHeader(15, `Directory Fuzzing${assetSuffix}`, INFO_C,
        `${dfStats.totalUnique ?? allFuzz.length} unique paths · ${dfHosts.length} host${dfHosts.length !== 1 ? "s" : ""} fuzzed`);
      doc.gap(4);
      doc.keyValue([
        ["Hosts Fuzzed",  String(dfHosts.length)],
        ["Unique Paths",  String(dfStats.totalUnique ?? allFuzz.length)],
        ["Max Depth",     String(dfStats.maxDepth ?? 3)],
        ["Wordlist Size", String((dirFuzz.masterList ?? []).length)],
      ], 4);
      if (allFuzz.length > 0) {
        doc.gap(5);
        doc.table(
          ["URL", "Status", "Size (bytes)", "Source"],
          [400, 58, 90, 106],
          allFuzz.slice(0, 35).map((r: any) => [
            r.url ?? "—",
            r.status != null ? String(r.status) : "—",
            r.size   != null ? String(r.size)   : "—",
            r.source ?? "—",
          ]),
          { monoCol: [0, 1] },
        );
        if (allFuzz.length > 35) {
          doc.gap(3); doc.text(`…and ${allFuzz.length - 35} more paths`, { size: 8.5, color: TEXT2 });
        }
      }
      doc.gap(16);
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // CARD 16 — Brand Threat Intelligence
  // ════════════════════════════════════════════════════════════════════════
  const btd = brandThreatDetail;
  {
    const typosquatResults: any[] = btd?.results ?? [];
    const phishDetections: any[]  = btd?.phishingDetections ?? [];
    const dataLeaks: any[]        = btd?.dataLeaks ?? [];
    const brandAbuse: any[]       = btd?.brandAbuse ?? [];
    const btScan: any             = btd?.scan ?? null;
    const hasBrandData            = typosquatResults.length > 0 || phishDetections.length > 0
                                    || dataLeaks.length > 0 || brandAbuse.length > 0;

    const subtitle16 = hasBrandData
      ? `${typosquatResults.length} domains · ${phishDetections.length} phishing · ${dataLeaks.length} leaks · ${brandAbuse.length} abuse`
      : "No brand threat data linked to this scan";

    doc.cardHeader(16, "Brand Threat Intelligence", CRIT, subtitle16);
    doc.gap(4);

    if (!hasBrandData) {
      doc.text(
        "No brand threat scan results are associated with this asset. Run a brand threat scan from the Brand Monitoring module to populate this section.",
        { size: 9.5, color: TEXT2 },
      );
    } else {
      // Brand overview stats
      doc.statCards([
        { label: "Typosquat Domains",  value: typosquatResults.length,                                   color: HIGH   },
        { label: "Phishing Detected",  value: phishDetections.length,                                    color: CRIT   },
        { label: "Data Leaks",         value: dataLeaks.length,                                          color: MED    },
        { label: "Brand Abuse Cases",  value: brandAbuse.length,                                         color: HIGH   },
      ]);
      doc.gap(6);

      // Favicon clone info
      if (btScan?.faviconMd5) {
        doc.keyValue([
          ["Brand Domain",  btScan.domain ?? "—"],
          ["Favicon MD5",   btScan.faviconMd5],
          ["Phishing Risk", (btScan.phishingRisk ?? "—").toUpperCase()],
          ["Scan Status",   (btScan.status ?? "—").toUpperCase()],
        ], 4);
        doc.gap(6);
      }

      // Typosquatting / domain permutations
      if (typosquatResults.length > 0) {
        doc.subsectionHeader(`Typosquatting Domains (${typosquatResults.length})`);
        doc.gap(3);
        const dangerousDomains = typosquatResults.filter((r: any) =>
          r.isLive || r.isPhishing || r.phishingRisk === "high" || r.phishingRisk === "critical"
        );
        const toShowDomains = dangerousDomains.length > 0 ? dangerousDomains : typosquatResults;
        doc.table(
          ["Domain", "Risk Level", "Registrar", "Live", "Type"],
          [238, 70, 184, 52, 80],
          toShowDomains.slice(0, 30).map((r: any) => [
            r.domain ?? r.permutation ?? "—",
            (r.phishingRisk ?? r.risk ?? "low").toUpperCase(),
            r.registrar ?? "—",
            r.isLive ? "YES" : "NO",
            r.type ?? r.fuzzer ?? "—",
          ]),
          { monoCol: [3] },
        );
        if (toShowDomains.length > 30) {
          doc.gap(3); doc.text(`…and ${toShowDomains.length - 30} more domains`, { size: 8.5, color: TEXT2 });
        }
        doc.gap(6);
      }

      // Phishing detections
      if (phishDetections.length > 0) {
        doc.subsectionHeader(`Phishing Detections (${phishDetections.length})`);
        doc.gap(3);
        doc.table(
          ["URL / Domain", "Source", "Threat Type"],
          [350, 150, 164],
          phishDetections.slice(0, 15).map((p: any) => [
            p.url ?? p.domain ?? "—",
            p.source ?? "—",
            p.threatType ?? "phishing",
          ]),
        );
        doc.gap(6);
      }

      // Data leaks
      if (dataLeaks.length > 0) {
        doc.subsectionHeader(`Data Leaks (${dataLeaks.length})`);
        doc.gap(3);
        doc.table(
          ["Source", "Type", "Description", "Date"],
          [150, 110, 300, 104],
          dataLeaks.slice(0, 15).map((l: any) => [
            l.source ?? l.breachSource ?? "—",
            l.type ?? "—",
            (l.description ?? l.title ?? "—").slice(0, 60),
            l.date ?? l.breachDate ?? "—",
          ]),
        );
        doc.gap(6);
      }

      // Brand abuse (malicious ads, social impersonation, etc.)
      if (brandAbuse.length > 0) {
        doc.subsectionHeader(`Brand Abuse — Malicious Ads / Social / Favicon Clones (${brandAbuse.length})`);
        doc.gap(3);
        doc.table(
          ["Type", "Platform", "Risk", "Title / Description"],
          [130, 110, 60, 364],
          brandAbuse.slice(0, 15).map((a: any) => [
            a.type ?? "—",
            a.platform ?? "—",
            (a.risk ?? "—").toUpperCase(),
            (a.title ?? a.description ?? "—").slice(0, 70),
          ]),
        );
      }
    }
  }

  const safeName = (scan?.name ?? `scan-${scan?.id}`).replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  triggerDownload(buildPdf([cover, ...doc.finalize()]), `${safeName}_report.pdf`);
}

function formatScanDuration(startedAt: string, completedAt: string): string {
  const ms = new Date(completedAt).getTime() - new Date(startedAt).getTime();
  if (ms < 0) return "—";
  const totalSec = Math.round(ms / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return s > 0 ? `${m}m ${s}s` : `${m}m`;
}

// ── Full Reports Page PDF ────────────────────────────────────────────────
export async function downloadReportPdf(reportId: number, token: string | null): Promise<void> {
  const [logo, res] = await Promise.all([
    getLogo(),
    fetch(`/api/reports/pdf-data/report/${reportId}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
  ]);
  if (!res.ok) throw new Error("Failed to fetch report PDF data");

  const d = await res.json() as {
    report: { id: number; title: string; type: string; format: string; generatedAt?: string };
    assets: { id: number; name: string; type: string; value: string; riskLevel: string; ipAddress?: string; lastScannedAt?: string }[];
    findings: {
      id: number; title: string; severity: string; status: string;
      cve?: string; cvss?: number; cwe?: string;
      description?: string; remediation?: string;
      assetId: number; assetName: string;
    }[];
    riskScores: { assetId: number; score: number; level: string }[];
    brandScans: {
      id: number; domain: string; status: string; totalPermutations: number;
      liveCount: number; registeredCount: number; phishingRisk: string;
      dataLeakCount: number; phishingCount: number; brandAbuseCount: number;
      completedAt: string | null;
    }[];
    brandResults: {
      scanId: number; permutation: string; fuzzer: string;
      dnsA: string[]; riskScore: number; isSuspicious: boolean;
      geoCountry: string | null; vtMalicious: number | null;
      whoisRegistrar: string | null; whoisCreated: string | null;
    }[];
    findingCounts: { total: number; critical: number; high: number; medium: number; low: number; open: number };
  };

  const rpt     = d.report;
  const fc      = d.findingCounts;
  const brandScans    = d.brandScans ?? [];
  const brandResults  = d.brandResults ?? [];
  const worstSev = fc.critical > 0 ? "critical" : fc.high > 0 ? "high" : fc.medium > 0 ? "medium" : "low";
  const rc       = sevColor(worstSev);

  const riskMap: Record<number, { score: number; level: string }> = {};
  for (const rs of d.riskScores) riskMap[rs.assetId] = rs;

  const totalLiveDomains    = brandScans.reduce((s, b) => s + (b.liveCount ?? 0), 0);
  const totalPhishing       = brandScans.reduce((s, b) => s + (b.phishingCount ?? 0), 0);
  const totalLeaks          = brandScans.reduce((s, b) => s + (b.dataLeakCount ?? 0), 0);
  const totalBrandAbuse     = brandScans.reduce((s, b) => s + (b.brandAbuseCount ?? 0), 0);
  const suspiciousBrandDomains = brandResults.filter(r => r.isSuspicious).length;

  const cover = makeCover({
    title:      rpt.title,
    reportKind: `${rpt.type.replace(/_/g, " ")} Report`.toUpperCase(),
    metaPairs:  [
      ["Report Type",       rpt.type.replace(/_/g, " ").toUpperCase()],
      ["Generated",         rpt.generatedAt ? new Date(rpt.generatedAt).toLocaleDateString() : new Date().toLocaleDateString()],
      ["Total Assets",      String(d.assets.length)],
      ["Total Findings",    String(fc.total)],
      ["Critical / High",   `${fc.critical} / ${fc.high}`],
      ["Brand Threat Scans", String(brandScans.length)],
    ],
    riskLabel:  `Overall Risk: ${worstSev.toUpperCase()}`,
    riskColor:  rc,
    logo,
  });

  const doc = new PdfDoc(rpt.title, logo);
  doc.newPage();

  // Executive Summary
  doc.sectionHeader("Executive Summary");
  doc.gap(6);
  doc.statCards([
    { label: "Total Assets",   value: d.assets.length, color: NAVY },
    { label: "Total Findings", value: fc.total,        color: INFO_C },
    { label: "Critical",       value: fc.critical,     color: CRIT },
    { label: "High",           value: fc.high,         color: HIGH },
  ]);
  doc.statCards([
    { label: "Medium",        value: fc.medium,           color: MED },
    { label: "Low",           value: fc.low,              color: LOW },
    { label: "Open",          value: fc.open,             color: HIGH },
    { label: "Brand Threats", value: brandScans.length,   color: AMBER },
  ]);
  doc.gap(12);

  // Asset Inventory
  doc.sectionHeader("Asset Inventory");
  doc.gap(6);
  const riskScoreForSort = (a: any) => (riskMap[a.id]?.score ?? 0);
  const sortedAssets = [...d.assets].sort((a, b) => riskScoreForSort(b) - riskScoreForSort(a));
  doc.table(
    ["Asset Name", "Type", "Target / Value", "Risk Level", "Risk Score", "Last Scanned"],
    [140, 66, 162, 74, 68, 92],
    sortedAssets.map(a => {
      const rs = riskMap[a.id];
      return [
        a.name, a.type, a.value,
        (rs?.level ?? a.riskLevel ?? "—").toUpperCase(),
        rs ? String(rs.score) : "—",
        a.lastScannedAt ? new Date(a.lastScannedAt).toLocaleDateString() : "Never",
      ];
    }),
  );
  doc.gap(12);

  // All Findings Table
  if (d.findings.length > 0) {
    doc.sectionHeader("All Vulnerability Findings");
    doc.gap(6);
    doc.table(
      ["Severity", "Title", "Asset", "CVE / ID", "Status"],
      [74, 196, 130, 116, 72],
      d.findings.slice(0, 200).map(f => [
        f.severity, f.title, f.assetName, f.cve ?? "—", f.status,
      ]),
      { severityCol: 0, monoCol: [3], statusCol: 4 },
    );
    doc.gap(12);
  }

  // Per-Asset Finding Details
  const findingsByAsset: Record<number, typeof d.findings> = {};
  for (const f of d.findings) {
    (findingsByAsset[f.assetId] ??= []).push(f);
  }

  for (const asset of sortedAssets) {
    const af = findingsByAsset[asset.id] ?? [];
    if (af.length === 0) continue;

    doc.sectionHeader(`${asset.name} — Finding Details`, BLUE);
    doc.gap(6);
    doc.keyValue([
      ["Asset",      asset.name],
      ["Target",     asset.value],
      ["Type",       asset.type],
      ["Risk Level", (riskMap[asset.id]?.level ?? asset.riskLevel ?? "—").toUpperCase()],
      ["Risk Score", riskMap[asset.id] ? String(riskMap[asset.id].score) : "—"],
      ["Findings",   String(af.length)],
    ], 3);
    doc.gap(8);

    const critHigh = af.filter(f => f.severity === "critical" || f.severity === "high");
    const others   = af.filter(f => f.severity !== "critical" && f.severity !== "high");

    for (const f of critHigh.slice(0, 20)) {
      doc.findingCard(f);
    }

    if (others.length > 0) {
      doc.gap(4);
      doc.subsectionHeader(`Medium / Low Findings (${others.length})`, TEXT2);
      doc.gap(4);
      doc.table(
        ["Severity", "Title", "CVE / ID", "Status"],
        [74, 314, 130, 80],
        others.slice(0, 30).map(f => [f.severity, f.title, f.cve ?? "—", f.status]),
        { severityCol: 0, monoCol: [2], statusCol: 3 },
      );
    }

    if (af.length > 20 + others.length) {
      doc.gap(4);
      doc.text(`…and ${af.length - 20 - Math.min(others.length, 30)} more findings for this asset`, { size: 8.5, color: TEXT2 });
    }
    doc.gap(10);
  }

  // Brand Threat Monitoring Section
  if (brandScans.length > 0) {
    doc.sectionHeader("Brand Threat Monitoring", AMBER);
    doc.gap(6);
    doc.text(
      `Brand threat monitoring has been performed across ${brandScans.length} domain${brandScans.length !== 1 ? "s" : ""} in your attack surface. ` +
      `${suspiciousBrandDomains} suspicious permutation${suspiciousBrandDomains !== 1 ? "s" : ""} detected.`,
      { size: 9.5, color: TEXT2 },
    );
    doc.gap(10);

    // Brand threat summary stat cards
    doc.statCards([
      { label: "Brand Scans",        value: brandScans.length,         color: NAVY  },
      { label: "Live Domains",       value: totalLiveDomains,          color: CRIT  },
      { label: "Phishing Detected",  value: totalPhishing,             color: HIGH  },
      { label: "Suspicious Domains", value: suspiciousBrandDomains,    color: MED   },
    ]);
    doc.statCards([
      { label: "Data Leaks",   value: totalLeaks,      color: HIGH  },
      { label: "Brand Abuse",  value: totalBrandAbuse, color: MED   },
      { label: "Monitored",    value: brandScans.length, color: INFO_C },
      { label: "Brand Results", value: brandResults.length, color: NAVY },
    ]);
    doc.gap(10);

    // Per-domain brand scan details
    const brandResultsByScanId: Record<number, typeof brandResults> = {};
    for (const r of brandResults) {
      (brandResultsByScanId[r.scanId] ??= []).push(r);
    }

    doc.table(
      ["Domain Monitored", "Status", "Permutations", "Live", "Phishing Risk", "Data Leaks", "Brand Abuse"],
      [138, 66, 90, 52, 90, 76, 80],
      brandScans.map(s => [
        s.domain,
        s.status,
        String(s.totalPermutations),
        String(s.liveCount),
        s.phishingRisk.toUpperCase(),
        String(s.dataLeakCount),
        String(s.brandAbuseCount),
      ]),
    );
    doc.gap(10);

    // Top suspicious brand permutations
    const topSuspicious = brandResults.filter(r => r.isSuspicious).slice(0, 50);
    if (topSuspicious.length > 0) {
      doc.subsectionHeader(`Top Suspicious Permutations (${topSuspicious.length} shown)`, CRIT);
      doc.gap(4);
      doc.table(
        ["Permutation", "Fuzzer Type", "IP Addresses", "Risk Score", "Country", "Registrar"],
        [176, 86, 124, 72, 72, 106],
        topSuspicious.map(r => [
          r.permutation, r.fuzzer,
          (r.dnsA ?? []).slice(0, 2).join(", ") || "—",
          String(r.riskScore),
          r.geoCountry ?? "—",
          r.whoisRegistrar ?? "—",
        ]),
        { monoCol: [0, 2] },
      );
      if (brandResults.filter(r => r.isSuspicious).length > 50) {
        doc.gap(3);
        doc.text(`…and ${brandResults.filter(r => r.isSuspicious).length - 50} more suspicious domains. Download the dedicated brand threat report for full details.`, { size: 8.5, color: TEXT2 });
      }
    }
    doc.gap(10);
  }

  const safeName = rpt.title.replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  triggerDownload(buildPdf([cover, ...doc.finalize()]), `${safeName}_${rpt.type}.pdf`);
}

// ── Selected-Assets PDF ──────────────────────────────────────────────────
type AssetPdfAsset = {
  id: number; name: string; type: string; value: string;
  riskLevel: string; riskScore: number | null; riskScoreLevel: string | null;
  ipAddress: string | null; lastScannedAt: string | null;
};
type AssetPdfFinding = {
  id: number; title: string; severity: string; status: string;
  cve: string | null; cvss: number | null; cwe?: string | null;
  description: string | null; remediation: string | null;
  assetId: number; assetName: string;
};
type AssetPdfBrandScan = {
  id: number; domain: string; status: string;
  totalPermutations: number; liveCount: number; registeredCount: number;
  phishingRisk: string; completedAt: string | null;
};
type AssetPdfBrandResult = {
  id: number; scanId: number; permutation: string; fuzzer: string;
  dnsA: string[]; dnsMx: string[]; mxSpf: string | null;
  whoisRegistrar: string | null; whoisCreated: string | null; whoisCountry: string | null;
  riskScore: number; isSuspicious: boolean;
};

export async function downloadSelectedAssetsPdf(
  title: string,
  type: string,
  assetIds: number[],
  token: string | null,
): Promise<void> {
  const idsParam = assetIds.join(",");
  const [logo, res] = await Promise.all([
    getLogo(),
    fetch(`/api/reports/pdf-data/assets?ids=${idsParam}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }),
  ]);
  if (!res.ok) throw new Error("Failed to fetch asset PDF data");

  const d = await res.json() as {
    assets:       AssetPdfAsset[];
    findings:     AssetPdfFinding[];
    brandScans:   AssetPdfBrandScan[];
    brandResults: AssetPdfBrandResult[];
  };

  const findingsByAsset: Record<number, AssetPdfFinding[]> = {};
  for (const f of d.findings) {
    (findingsByAsset[f.assetId] ??= []).push(f);
  }
  const brandScansByDomain: Record<string, AssetPdfBrandScan[]> = {};
  for (const s of d.brandScans) {
    (brandScansByDomain[s.domain] ??= []).push(s);
  }
  const brandResultsByScanId: Record<number, AssetPdfBrandResult[]> = {};
  for (const r of d.brandResults) {
    (brandResultsByScanId[r.scanId] ??= []).push(r);
  }

  const totalFindings = d.findings.length;
  const critCount     = d.findings.filter(f => f.severity === "critical").length;
  const highCount     = d.findings.filter(f => f.severity === "high").length;
  const medCount      = d.findings.filter(f => f.severity === "medium").length;
  const lowCount      = d.findings.filter(f => f.severity === "low").length;
  const openCount     = d.findings.filter(f => f.status === "open").length;
  const worstSev      = critCount > 0 ? "critical" : highCount > 0 ? "high" : medCount > 0 ? "medium" : "low";
  const riskColor     = sevColor(worstSev);

  const cover = makeCover({
    title,
    reportKind: `${type.replace(/_/g, " ")} REPORT`.toUpperCase(),
    metaPairs: [
      ["Report Type",       type.replace(/_/g, " ").toUpperCase()],
      ["Generated",         new Date().toLocaleDateString()],
      ["Assets Covered",    String(d.assets.length)],
      ["Total Findings",    String(totalFindings)],
      ["Critical / High",   `${critCount} / ${highCount}`],
      ["Brand Threat Scans", String(d.brandScans.length)],
    ],
    riskLabel:  `Overall Risk: ${worstSev.toUpperCase()}`,
    riskColor,
    logo,
  });

  const doc = new PdfDoc(title, logo);
  doc.newPage();

  // Executive Summary
  doc.sectionHeader("Executive Summary");
  doc.gap(6);
  doc.statCards([
    { label: "Assets",       value: d.assets.length, color: NAVY },
    { label: "Findings",     value: totalFindings,   color: INFO_C },
    { label: "Critical",     value: critCount,       color: CRIT },
    { label: "High",         value: highCount,       color: HIGH },
  ]);
  doc.statCards([
    { label: "Medium",        value: medCount,            color: MED   },
    { label: "Low",           value: lowCount,            color: LOW   },
    { label: "Open",          value: openCount,           color: HIGH  },
    { label: "Brand Threats", value: d.brandScans.length, color: AMBER },
  ]);
  doc.gap(12);

  // Asset Overview Table (multi-asset)
  if (d.assets.length > 1) {
    doc.sectionHeader("Assets Selected");
    doc.gap(6);
    doc.table(
      ["Asset Name", "Type", "Target / Value", "Risk Level", "Score", "Findings"],
      [140, 66, 162, 78, 58, 62],
      d.assets.map(a => [
        a.name, a.type, a.value,
        (a.riskScoreLevel ?? a.riskLevel ?? "—").toUpperCase(),
        a.riskScore !== null ? String(a.riskScore) : "—",
        String((findingsByAsset[a.id] ?? []).length),
      ]),
    );
    doc.gap(12);
  }

  // Per-asset deep-dive
  for (const asset of d.assets) {
    const af             = findingsByAsset[asset.id] ?? [];
    const assetBrandScans = brandScansByDomain[asset.value] ?? [];

    doc.ensureSpace(64);
    doc.sectionHeader(`${asset.name}`, BLUE);
    doc.gap(6);
    doc.keyValue([
      ["Target / Value",  asset.value],
      ["Asset Type",      asset.type],
      ["Risk Level",      (asset.riskScoreLevel ?? asset.riskLevel ?? "—").toUpperCase()],
      ["Risk Score",      asset.riskScore !== null ? String(asset.riskScore) : "—"],
      ["IP Address",      asset.ipAddress ?? "—"],
      ["Last Scanned",    asset.lastScannedAt ? new Date(asset.lastScannedAt).toLocaleDateString() : "Never"],
    ], 3);
    doc.gap(10);

    // Findings
    if (af.length > 0) {
      doc.sectionHeader(`Vulnerability Findings (${af.length})`, CRIT);
      doc.gap(6);

      const aCrit = af.filter(f => f.severity === "critical").length;
      const aHigh = af.filter(f => f.severity === "high").length;
      const aMed  = af.filter(f => f.severity === "medium").length;
      const aLow  = af.filter(f => f.severity === "low").length;
      doc.statCards([
        { label: "Critical", value: aCrit, color: CRIT },
        { label: "High",     value: aHigh, color: HIGH },
        { label: "Medium",   value: aMed,  color: MED  },
        { label: "Low",      value: aLow,  color: LOW  },
      ]);
      doc.gap(8);

      // Full findings table
      doc.table(
        ["Severity", "Title", "CVE / ID", "CVSS", "Status"],
        [74, 266, 130, 58, 80],
        af.slice(0, 200).map(f => [
          f.severity, f.title, f.cve ?? "—",
          f.cvss !== null ? String(f.cvss) : "—", f.status,
        ]),
        { severityCol: 0, monoCol: [2], statusCol: 4 },
      );
      doc.gap(10);

      // Detailed cards — critical + high (up to 30)
      const critHighDetail = af.filter(f => f.severity === "critical" || f.severity === "high").slice(0, 30);
      if (critHighDetail.length > 0) {
        doc.sectionHeader("Critical & High — Full Detail", CRIT);
        doc.gap(6);
        for (const f of critHighDetail) {
          doc.findingCard(f);
        }
        if (af.filter(f => f.severity === "critical" || f.severity === "high").length > 30) {
          doc.gap(4);
          doc.text(
            `…and ${af.filter(f => f.severity === "critical" || f.severity === "high").length - 30} more critical/high findings — see summary table above.`,
            { size: 8.5, color: TEXT2 },
          );
        }
      }
      doc.gap(10);
    } else {
      doc.text("No findings recorded for this asset.", { size: 10, color: TEXT2 });
      doc.gap(10);
    }

    // Brand Threat section
    if (assetBrandScans.length > 0) {
      doc.sectionHeader(`Brand Threat Intelligence — ${asset.value}`, AMBER);
      doc.gap(6);

      for (const scan of assetBrandScans) {
        doc.keyValue([
          ["Domain Monitored",   scan.domain],
          ["Phishing Risk",      scan.phishingRisk.toUpperCase()],
          ["Total Permutations", String(scan.totalPermutations)],
          ["Live Domains",       String(scan.liveCount)],
          ["Registered Domains", String(scan.registeredCount)],
          ["Scan Completed",     scan.completedAt ? new Date(scan.completedAt).toLocaleDateString() : "In progress"],
        ], 3);
        doc.gap(8);

        const results   = brandResultsByScanId[scan.id] ?? [];
        const suspicious = results.filter(r => r.isSuspicious);
        const live       = results.filter(r => (r.dnsA?.length ?? 0) > 0);

        if (suspicious.length > 0) {
          doc.subsectionHeader(`Suspicious Domains (${suspicious.length})`, CRIT);
          doc.gap(4);
          doc.table(
            ["Permutation", "Fuzzer", "DNS A", "Risk Score", "Registrar"],
            [184, 74, 122, 74, 162],
            suspicious.slice(0, 40).map(r => [
              r.permutation, r.fuzzer,
              (r.dnsA ?? []).slice(0, 2).join(", ") || "—",
              String(r.riskScore),
              r.whoisRegistrar ?? "—",
            ]),
            { monoCol: [0, 2] },
          );
          doc.gap(8);
        }

        const nonSuspiciousLive = live.filter(r => !r.isSuspicious);
        if (nonSuspiciousLive.length > 0) {
          doc.subsectionHeader(`Other Live Domains (${nonSuspiciousLive.length})`, TEXT);
          doc.gap(4);
          doc.table(
            ["Permutation", "Fuzzer", "DNS A", "Country"],
            [202, 84, 144, 176],
            nonSuspiciousLive.slice(0, 20).map(r => [
              r.permutation, r.fuzzer,
              (r.dnsA ?? []).slice(0, 2).join(", ") || "—",
              r.whoisCountry ?? "—",
            ]),
            { monoCol: [0, 2] },
          );
          doc.gap(8);
        }

        if (results.length === 0) {
          doc.text("No domain permutation results found for this scan.", { size: 9, color: TEXT2 });
          doc.gap(6);
        }
      }
      doc.gap(8);
    }
  }

  const safeName = title.replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  triggerDownload(buildPdf([cover, ...doc.finalize()]), `${safeName}_asset_report.pdf`);
}
