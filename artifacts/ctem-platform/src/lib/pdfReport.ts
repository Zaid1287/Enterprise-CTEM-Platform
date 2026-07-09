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
    img.src = "/sentinelware-logo-white.png";
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

  // ── Background ──
  const grad = ctx.createLinearGradient(0, 0, 0, PH);
  grad.addColorStop(0.0, "#0b1120");
  grad.addColorStop(0.5, "#0f172a");
  grad.addColorStop(1.0, "#111827");
  ctx.fillStyle = grad;
  ctx.fillRect(0, 0, PW, PH);

  // ── Top accent ──
  ctx.fillStyle = BLUE;
  ctx.fillRect(0, 0, PW, 4);

  // ── Side accent bars ──
  ctx.fillStyle = "rgba(59,130,246,0.14)";
  ctx.fillRect(0, 4, 6, PH - 4);
  ctx.fillRect(PW - 6, 4, 6, PH - 4);

  // ── Header area ──
  const hh = 76;
  ctx.fillStyle = "rgba(255,255,255,0.04)";
  ctx.fillRect(0, 4, PW, hh);
  ctx.fillStyle = "rgba(59,130,246,0.15)";
  ctx.fillRect(0, 4 + hh, PW, 1);

  // ── Logo / branding ──
  if (o.logo) {
    drawLogo(ctx, o.logo, PW / 2, 4 + hh / 2, 180);
  } else {
    drawShield(ctx, M + 20, 4 + hh / 2, 32, BLUE);
    tx(ctx, "SENTINELWARE", M + 44, 4 + hh / 2 + 5, 14, WHITE, "bold");
    const lw = mw(ctx, "SENTINELWARE", 14, "bold");
    ctx.fillStyle = AMBER;
    ctx.beginPath();
    ctx.arc(M + 44 + lw + 8, 4 + hh / 2 - 4, 5, 0, Math.PI * 2);
    ctx.fill();
  }

  // ── Report kind badge ──
  const bKind = o.reportKind.toUpperCase();
  const bW    = mw(ctx, bKind, 9, "bold") + 28;
  rr(ctx, PW / 2 - bW / 2, 120, bW, 24, 12, "rgba(59,130,246,0.2)", BLUE, 1);
  tx(ctx, bKind, PW / 2, 136, 9, BLUE, "bold", "center");

  // ── Title ──
  const titleLines = wrapText(ctx, o.title, 22, "bold", PW - 100);
  let titleY = 170;
  for (const line of titleLines.slice(0, 3)) {
    tx(ctx, line, PW / 2, titleY, 22, WHITE, "bold", "center");
    titleY += 30;
  }

  // ── Divider ──
  ctx.fillStyle = "rgba(59,130,246,0.35)";
  ctx.fillRect(M + 40, titleY + 10, CW - 80, 1);

  // ── Meta grid ──
  const metaY   = titleY + 30;
  const metaCols = 2;
  const colW    = (CW - 20) / metaCols;
  const rowH    = 50;
  o.metaPairs.forEach(([k, v], i) => {
    const col = i % metaCols;
    const row = Math.floor(i / metaCols);
    const x   = M + col * (colW + 20);
    const y   = metaY + row * rowH;
    rr(ctx, x, y, colW, rowH - 6, 6, "rgba(255,255,255,0.05)", "rgba(255,255,255,0.1)", 1);
    tx(ctx, k.toUpperCase(), x + 10, y + 16, 7.5, GR400, "bold");
    tx(ctx, String(v || "—"), x + 10, y + 36, 10.5, WHITE, "500", "left", colW - 20);
  });

  // ── Risk badge ──
  const badgeY = metaY + Math.ceil(o.metaPairs.length / metaCols) * rowH + 20;
  const bLabel = o.riskLabel.toUpperCase();
  const bBW    = mw(ctx, bLabel, 11.5, "bold") + 40;
  rr(ctx, PW / 2 - bBW / 2, badgeY, bBW, 34, 17, o.riskColor);
  tx(ctx, bLabel, PW / 2, badgeY + 22, 11.5, WHITE, "bold", "center");

  // ── Confidential strip ──
  ctx.fillStyle = "#450a0a";
  ctx.fillRect(0, PH - 40, PW, 40);
  tx(ctx, "⚠  CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY", PW / 2, PH - 12, 8.5, "#fca5a5", "bold", "center");

  // ── Generated date ──
  const gen = new Date().toLocaleString("en-US", { year:"numeric", month:"short", day:"numeric", hour:"2-digit", minute:"2-digit" });
  tx(ctx, `Generated: ${gen}`, PW / 2, PH - 54, 8, GR400, "normal", "center");

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

export async function downloadScanReportPdf(scan: any, assetReports: any[]): Promise<void> {
  const logo = await getLogo();

  const totalVulns    = assetReports.reduce((a, r) => a + (r.summary?.vulnerabilities ?? 0), 0);
  const totalCritical = assetReports.reduce((a, r) => a + (r.summary?.criticalVulns ?? 0) + (r.vulnScan?.stats?.critical ?? 0), 0);
  const totalHigh     = assetReports.reduce((a, r) => a + (r.summary?.highVulns ?? 0) + (r.vulnScan?.stats?.high ?? 0), 0);
  const totalMedium   = assetReports.reduce((a, r) => a + (r.cves ?? []).filter((c: any) => c.severity === "medium").length, 0);
  const totalSecrets  = assetReports.reduce((a, r) => a + (r.secrets ?? []).length + (r.secretsHunt?.stats?.secretsFound ?? 0), 0);
  const avgAsm        = assetReports.length > 0
    ? Math.round(assetReports.map(computeAsmScore).reduce((a, b) => a + b, 0) / assetReports.length)
    : 100;
  const worstSeverity = totalCritical > 0 ? "critical" : totalHigh > 0 ? "high" : "medium";
  const rc            = sevColor(worstSeverity);
  const ts            = scan?.completedAt ? new Date(scan.completedAt).toLocaleString() : new Date().toLocaleString();

  const cover = makeCover({
    title:      `${scan?.name ?? `Scan #${scan?.id}`} — Full Scan Report`,
    reportKind: "Pipeline Vulnerability Scan Report",
    metaPairs:  [
      ["Scan Name",       scan?.name ?? `Scan #${scan?.id}`],
      ["Completed",       ts],
      ["Assets Scanned",  String(assetReports.length)],
      ["Total Findings",  String(totalVulns)],
      ["Critical / High", `${totalCritical} / ${totalHigh}`],
      ["Secrets Found",   String(totalSecrets)],
    ],
    riskLabel:  `Threat Level: ${worstSeverity.toUpperCase()}`,
    riskColor:  rc,
    logo,
  });

  const doc = new PdfDoc(`${scan?.name ?? `Scan #${scan?.id}`} — Scan Report`, logo);
  doc.newPage();

  // Executive Summary
  doc.sectionHeader("Executive Summary");
  doc.gap(6);
  doc.statCards([
    { label: "ASM Score",      value: avgAsm,            color: avgAsm >= 70 ? LOW : avgAsm >= 40 ? MED : CRIT },
    { label: "Assets Scanned", value: assetReports.length, color: NAVY },
    { label: "Critical",       value: totalCritical,     color: CRIT },
    { label: "High",           value: totalHigh,         color: HIGH },
  ]);
  doc.statCards([
    { label: "Medium",       value: totalMedium,  color: MED   },
    { label: "Total Vulns",  value: totalVulns,   color: INFO_C },
    { label: "Secrets",      value: totalSecrets, color: MED   },
    { label: "Threat Level", value: worstSeverity.toUpperCase(), color: rc },
  ]);
  doc.gap(12);

  // Scan Details
  doc.sectionHeader("Scan Information");
  doc.gap(6);
  doc.keyValue([
    ["Scan Name",      scan?.name ?? `Scan #${scan?.id}`],
    ["Scan ID",        String(scan?.id ?? "—")],
    ["Status",         (scan?.status ?? "—").toUpperCase()],
    ["Completed At",   ts],
    ["Assets in Scan", String(assetReports.length)],
    ["Scan Type",      scan?.type ?? "full"],
  ], 3);
  doc.gap(12);

  // Asset Summary Table
  if (assetReports.length > 0) {
    doc.sectionHeader("Asset Overview");
    doc.gap(6);
    doc.table(
      ["Asset", "Target", "Open Ports", "Vulns", "Critical", "Secrets"],
      [158, 170, 66, 60, 66, 66],
      assetReports.map(r => [
        r.assetName ?? "—",
        r.assetValue ?? "—",
        String(r.summary?.openPorts ?? 0),
        String(r.summary?.vulnerabilities ?? 0),
        String((r.summary?.criticalVulns ?? 0) + (r.vulnScan?.stats?.critical ?? 0)),
        String((r.secrets ?? []).length + (r.secretsHunt?.stats?.secretsFound ?? 0)),
      ]),
    );
    doc.gap(12);
  }

  // Per-Asset Sections
  for (const asset of assetReports) {
    const cves: any[]    = asset.cves ?? [];
    const secrets: any[] = asset.secrets ?? [];
    const ports: any[]   = asset.ports ?? [];
    const asmScore       = computeAsmScore(asset);

    doc.sectionHeader(`Asset: ${asset.assetName ?? "Unknown"}`, BLUE);
    doc.gap(6);

    doc.keyValue([
      ["Target",       asset.assetValue ?? "—"],
      ["ASM Score",    `${asmScore} / 100`],
      ["Open Ports",   String(asset.summary?.openPorts ?? 0)],
      ["Subdomains",   String(asset.summary?.subdomains ?? 0)],
      ["Endpoints",    String(asset.summary?.endpoints ?? 0)],
      ["DNS Records",  String(asset.summary?.dnsRecords ?? 0)],
    ], 3);
    doc.gap(8);

    if (asset.httpInfo?.waf && asset.httpInfo.waf !== "none") {
      doc.text(`WAF / CDN Detected: ${asset.httpInfo.waf}`, { size: 9, color: LOW, weight: "bold" });
      doc.gap(6);
    }

    // CVEs / Vulnerabilities
    if (cves.length > 0) {
      doc.subsectionHeader(`Vulnerability Findings (${cves.length} total)`, TEXT);
      doc.gap(4);
      doc.table(
        ["CVE / ID", "Title", "Severity", "CVSS"],
        [136, 276, 82, 62],
        cves.slice(0, 25).map(c => [
          c.cve ?? c.cveId ?? c.id ?? "—",
          c.title ?? c.description ?? "—",
          c.severity ?? "—",
          c.cvss != null ? String(c.cvss) : "—",
        ]),
        { severityCol: 2, monoCol: [0] },
      );
      if (cves.length > 25) {
        doc.gap(3);
        doc.text(`…and ${cves.length - 25} more findings not shown`, { size: 8.5, color: TEXT2 });
      }
      doc.gap(8);
    }

    // Nuclei / VulnScan stats
    const vs = asset.vulnScan?.stats;
    if (vs && (vs.critical + vs.high + vs.medium + vs.low > 0)) {
      doc.subsectionHeader("Template Scan Results", TEXT);
      doc.gap(4);
      doc.statCards([
        { label: "Critical", value: vs.critical ?? 0, color: CRIT },
        { label: "High",     value: vs.high ?? 0,     color: HIGH },
        { label: "Medium",   value: vs.medium ?? 0,   color: MED  },
        { label: "Low",      value: vs.low ?? 0,      color: LOW  },
      ]);
      doc.gap(8);
    }

    // Secrets
    if (secrets.length > 0) {
      doc.subsectionHeader(`Exposed Secrets (${secrets.length})`, MED);
      doc.gap(4);
      doc.table(
        ["Type", "File / Location", "Value (truncated)"],
        [134, 222, 200],
        secrets.slice(0, 15).map((s: any) => [
          s.type ?? "Secret",
          s.file ?? "—",
          s.value ? String(s.value).slice(0, 48) : "—",
        ]),
        { monoCol: [2] },
      );
      doc.gap(8);
    }

    // Open Ports
    if (ports.length > 0) {
      const openPorts = ports.filter((p: any) => p.state === "open" || !p.state).slice(0, 20);
      if (openPorts.length > 0) {
        doc.subsectionHeader(`Open Ports (${openPorts.length} shown)`, TEXT);
        doc.gap(4);
        doc.table(
          ["Port", "Protocol", "Service", "Version / Banner"],
          [56, 64, 96, 340],
          openPorts.map((p: any) => [
            String(p.port ?? "—"),
            p.protocol ?? "tcp",
            p.service ?? "unknown",
            p.version ?? p.banner ?? "—",
          ]),
          { monoCol: [0, 1] },
        );
        doc.gap(8);
      }
    }

    doc.gap(6);
  }

  const safeName = (scan?.name ?? `scan-${scan?.id}`).replace(/[^a-z0-9_\-. ]/gi, "_").replace(/\s+/g, "_");
  triggerDownload(buildPdf([cover, ...doc.finalize()]), `${safeName}_report.pdf`);
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
