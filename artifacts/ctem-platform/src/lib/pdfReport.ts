// Branded PDF report generation for Sentinelware CTEM Platform
// Produces pixel-perfect A4 PDFs via Canvas → JPEG → hand-written PDF binary

// ── Page geometry ──────────────────────────────────────────────────────
const PW = 794;   // A4 at 96 dpi
const PH = 1123;
const M  = 48;    // left/right margin
const CW = PW - M * 2;  // content width = 698

// ── Color palette ──────────────────────────────────────────────────────
const NAVY   = "#0f172a";
const BLUE   = "#3b82f6";
const BLUELT = "#93c5fd";
const AMBER  = "#f59e0b";
const WHITE  = "#ffffff";
const GR50   = "#f8fafc";
const GR100  = "#f1f5f9";
const GR200  = "#e2e8f0";
const GR400  = "#94a3b8";
const TEXT   = "#0f172a";
const TEXT2  = "#64748b";
const CRIT   = "#dc2626";  const CRIT_BG = "#fef2f2";
const HIGH   = "#ea580c";  const HIGH_BG = "#fff7ed";
const MED    = "#d97706";  const MED_BG  = "#fffbeb";
const LOW    = "#16a34a";  const LOW_BG  = "#f0fdf4";
const INFO_C = "#3b82f6";  const INFO_BG = "#eff6ff";

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

const FONT = "'Segoe UI', system-ui, -apple-system, sans-serif";
const MONO = "'Consolas', 'Cascadia Code', 'Courier New', monospace";

// ── Low-level drawing helpers ──────────────────────────────────────────

function rr(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number, r: number,
  fill: string, stroke?: string,
) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + w - r, y);
  ctx.quadraticCurveTo(x + w, y, x + w, y + r);
  ctx.lineTo(x + w, y + h - r);
  ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  ctx.lineTo(x + r, y + h);
  ctx.quadraticCurveTo(x, y + h, x, y + h - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
  if (fill) { ctx.fillStyle = fill; ctx.fill(); }
  if (stroke) { ctx.strokeStyle = stroke; ctx.lineWidth = 1; ctx.stroke(); }
}

function tx(
  ctx: CanvasRenderingContext2D,
  text: string, x: number, y: number, size: number, color: string,
  weight = "normal", align: CanvasTextAlign = "left", maxW?: number,
) {
  ctx.fillStyle = color;
  ctx.font = `${weight} ${size}px ${FONT}`;
  ctx.textAlign = align;
  if (maxW !== undefined) ctx.fillText(text, x, y, maxW);
  else                    ctx.fillText(text, x, y);
  ctx.textAlign = "left";
}

function monoTx(
  ctx: CanvasRenderingContext2D,
  text: string, x: number, y: number, size: number, color: string, maxW?: number,
) {
  ctx.fillStyle = color;
  ctx.font = `${size}px ${MONO}`;
  if (maxW !== undefined) ctx.fillText(text, x, y, maxW);
  else                    ctx.fillText(text, x, y);
}

function mw(ctx: CanvasRenderingContext2D, text: string, size: number, weight = "normal"): number {
  ctx.font = `${weight} ${size}px ${FONT}`;
  return ctx.measureText(text).width;
}

function drawShield(ctx: CanvasRenderingContext2D, cx: number, cy: number, sz: number, color: string) {
  const w = sz * 0.64;
  const h = sz;
  const x = cx - w / 2;
  const y = cy - h / 2;
  ctx.beginPath();
  ctx.moveTo(cx, y);
  ctx.lineTo(x + w, y + h * 0.27);
  ctx.lineTo(x + w, y + h * 0.62);
  ctx.bezierCurveTo(x + w, y + h * 0.86, cx + w * 0.18, y + h * 0.96, cx, y + h);
  ctx.bezierCurveTo(cx - w * 0.18, y + h * 0.96, x, y + h * 0.86, x, y + h * 0.62);
  ctx.lineTo(x, y + h * 0.27);
  ctx.closePath();
  ctx.fillStyle = color;
  ctx.fill();
  ctx.strokeStyle = "rgba(255,255,255,0.88)";
  ctx.lineWidth = sz * 0.065;
  ctx.lineCap = "round";
  ctx.lineJoin = "round";
  ctx.beginPath();
  ctx.moveTo(cx - w * 0.21, cy + h * 0.04);
  ctx.lineTo(cx - w * 0.03, cy + h * 0.19);
  ctx.lineTo(cx + w * 0.21, cy - h * 0.1);
  ctx.stroke();
  ctx.lineCap = "butt";
  ctx.lineJoin = "miter";
}

function wrapText(
  ctx: CanvasRenderingContext2D, str: string, size: number, weight: string, maxWidth: number,
): string[] {
  ctx.font = `${weight} ${size}px ${FONT}`;
  const words = str.split(" ");
  const lines: string[] = [];
  let line = "";
  for (const word of words) {
    const test = line ? `${line} ${word}` : word;
    if (ctx.measureText(test).width > maxWidth && line) { lines.push(line); line = word; }
    else line = test;
  }
  if (line) lines.push(line);
  return lines;
}

function trunc(ctx: CanvasRenderingContext2D, str: string, size: number, maxWidth: number): string {
  ctx.font = `${size}px ${FONT}`;
  if (ctx.measureText(str).width <= maxWidth) return str;
  let s = str;
  while (s.length > 0 && ctx.measureText(s + "…").width > maxWidth) s = s.slice(0, -1);
  return s + "…";
}

// ── Cover page ──────────────────────────────────────────────────────────

interface CoverData {
  title: string;
  reportKind: string;
  metaPairs: [string, string][];
  riskLabel: string;
  riskColor: string;
}

function makeCover(d: CoverData): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.width = PW; canvas.height = PH;
  const ctx = canvas.getContext("2d")!;

  // ── Background ──
  ctx.fillStyle = NAVY;
  ctx.fillRect(0, 0, PW, PH);

  // Subtle grid
  ctx.save();
  ctx.globalAlpha = 0.025;
  ctx.strokeStyle = BLUE;
  ctx.lineWidth = 1;
  for (let xi = 0; xi < PW; xi += 40) {
    ctx.beginPath(); ctx.moveTo(xi, 0); ctx.lineTo(xi, PH); ctx.stroke();
  }
  for (let yi = 0; yi < PH; yi += 40) {
    ctx.beginPath(); ctx.moveTo(0, yi); ctx.lineTo(PW, yi); ctx.stroke();
  }
  ctx.restore();

  // Top-right decorative rings
  ctx.save();
  ctx.globalAlpha = 0.06;
  ctx.strokeStyle = BLUE;
  ctx.lineWidth = 1;
  for (let i = 0; i < 5; i++) {
    ctx.beginPath();
    ctx.arc(PW + 30, -30, 160 + i * 65, 0, Math.PI * 2);
    ctx.stroke();
  }
  ctx.restore();

  // ── Top accent bar ──
  ctx.fillStyle = BLUE;
  ctx.fillRect(0, 0, PW, 5);

  // ── Shield area glow ──
  const glow = ctx.createRadialGradient(PW / 2, 272, 0, PW / 2, 272, 190);
  glow.addColorStop(0, "rgba(59,130,246,0.20)");
  glow.addColorStop(1, "rgba(59,130,246,0)");
  ctx.fillStyle = glow;
  ctx.fillRect(PW / 2 - 190, 82, 380, 380);

  // Concentric rings
  [68, 90, 114].forEach((r, i) => {
    ctx.strokeStyle = `rgba(59,130,246,${0.28 - i * 0.08})`;
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(PW / 2, 272, r, 0, Math.PI * 2); ctx.stroke();
  });

  // ── Shield icon ──
  drawShield(ctx, PW / 2, 272, 84, BLUE);

  // ── Brand name ──
  const bw = mw(ctx, "SENTINELWARE", 30, "bold");
  tx(ctx, "SENTINELWARE", PW / 2 - bw / 2, 365, 30, WHITE, "bold");
  ctx.fillStyle = AMBER;
  ctx.beginPath(); ctx.arc(PW / 2 + bw / 2 + 10, 352, 5.5, 0, Math.PI * 2); ctx.fill();
  tx(ctx, "Continuous Threat Exposure Management", PW / 2, 391, 10.5, GR400, "normal", "center");

  // ── Gradient divider ──
  {
    const grd = ctx.createLinearGradient(M, 420, PW - M, 420);
    grd.addColorStop(0, "transparent");
    grd.addColorStop(0.25, "rgba(59,130,246,0.55)");
    grd.addColorStop(0.75, "rgba(59,130,246,0.55)");
    grd.addColorStop(1, "transparent");
    ctx.strokeStyle = grd;
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(M, 420); ctx.lineTo(PW - M, 420); ctx.stroke();
  }

  // ── Report title ──
  const titleLines = wrapText(ctx, d.title, 26, "bold", CW - 60);
  let titleY = 462;
  for (const line of titleLines.slice(0, 3)) {
    tx(ctx, line, PW / 2, titleY, 26, WHITE, "bold", "center", CW - 40);
    titleY += 38;
  }
  tx(ctx, d.reportKind.toUpperCase(), PW / 2, titleY + 12, 10, BLUELT, "bold", "center");
  titleY += 34;

  // ── Risk badge ──
  if (d.riskLabel) {
    const bw2 = 160;
    const bx = PW / 2 - bw2 / 2;
    const by = titleY + 14;
    rr(ctx, bx, by, bw2, 28, 14, `${d.riskColor}22`, `${d.riskColor}70`);
    tx(ctx, d.riskLabel, PW / 2, by + 18.5, 10, d.riskColor, "bold", "center");
    titleY += 58;
  }

  // ── Metadata grid ──
  const metaY = Math.max(titleY + 36, 726);
  const colW  = (CW - 14) / 2;
  d.metaPairs.forEach(([k, v], i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const mx  = M + col * (colW + 14);
    const my  = metaY + row * 52;
    rr(ctx, mx, my, colW, 44, 6, "rgba(30,41,59,0.90)", "rgba(59,130,246,0.20)");
    tx(ctx, k.toUpperCase(), mx + 12, my + 15, 7.5, "rgba(148,163,184,0.72)", "bold");
    tx(ctx, v || "—", mx + 12, my + 33, 10, WHITE, "normal", "left", colW - 24);
  });

  // ── Confidential strip ──
  ctx.fillStyle = "#450a0a";
  ctx.fillRect(0, PH - 42, PW, 42);
  tx(ctx, "⚠  CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY", PW / 2, PH - 13, 8.5, "#fca5a5", "bold", "center");

  return canvas;
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

  constructor(title: string) {
    this.title_   = title;
    this.genDate_ = new Date().toLocaleString("en-US", {
      year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  }

  newPage() {
    if (this.pn_ > 0) this._endPage();
    this.pn_++;
    this.cur_ = document.createElement("canvas");
    this.cur_.width = PW; this.cur_.height = PH;
    this._ctx = this.cur_.getContext("2d")!;
    this._drawFrame();
    this.y = 66;
  }

  private _drawFrame() {
    const c = this._ctx;
    c.fillStyle = WHITE;
    c.fillRect(0, 0, PW, PH);

    // Top accent
    c.fillStyle = BLUE;
    c.fillRect(0, 0, PW, 4);

    // Header strip
    c.fillStyle = NAVY;
    c.fillRect(0, 4, PW, 42);

    // Shield + Logo
    drawShield(c, M + 11, 25, 22, BLUE);
    tx(c, "SENTINELWARE", M + 24, 30, 10, WHITE, "bold");
    const lw = mw(c, "SENTINELWARE", 10, "bold");
    c.fillStyle = AMBER;
    c.beginPath(); c.arc(M + 24 + lw + 5, 21.5, 3.5, 0, Math.PI * 2); c.fill();

    // Center: report title
    const short = this.title_.length > 58 ? this.title_.slice(0, 55) + "…" : this.title_;
    tx(c, short, PW / 2, 30, 8.5, GR400, "normal", "center");

    // Right: page number
    tx(c, `Page ${this.pn_}`, PW - M, 30, 8.5, GR400, "normal", "right");

    // Thin accent line below header
    c.fillStyle = "rgba(59,130,246,0.22)";
    c.fillRect(0, 46, PW, 1);
  }

  private _endPage() {
    const c = this._ctx;
    c.fillStyle = GR200;
    c.fillRect(M, PH - 44, CW, 1);
    tx(c, "CONFIDENTIAL — Sentinelware CTEM Platform", M, PH - 27, 8, TEXT2);
    tx(c, this.genDate_, PW - M, PH - 27, 8, TEXT2, "normal", "right");
    this.pages_.push(this.cur_);
  }

  ensureSpace(h: number) {
    if (this.y + h > PH - 58) this.newPage();
  }

  gap(h: number) { this.y += h; }

  sectionHeader(title: string, color = BLUE) {
    this.ensureSpace(36);
    const c = this._ctx;
    c.fillStyle = color;
    c.fillRect(M, this.y, 3, 22);
    tx(c, title.toUpperCase(), M + 10, this.y + 15.5, 10, TEXT, "bold");
    c.fillStyle = GR200;
    c.fillRect(M + 10, this.y + 23, CW - 10, 1);
    this.y += 34;
  }

  text(str: string, opts: { size?: number; color?: string; weight?: string; indent?: number } = {}) {
    const { size = 10, color = TEXT, weight = "normal", indent = 0 } = opts;
    const lines = wrapText(this._ctx, str, size, weight, CW - indent - 4);
    for (const line of lines) {
      this.ensureSpace(size + 8);
      tx(this._ctx, line, M + indent, this.y + size, size, color, weight);
      this.y += size + 5;
    }
  }

  keyValue(pairs: [string, string][], columns = 2) {
    const cardH = 42;
    const gap   = 10;
    const colW  = (CW - gap * (columns - 1)) / columns;
    const rows  = Math.ceil(pairs.length / columns);
    this.ensureSpace(rows * (cardH + gap) + 8);
    const c = this._ctx;
    pairs.forEach(([k, v], i) => {
      const col = i % columns;
      const row = Math.floor(i / columns);
      const x   = M + col * (colW + gap);
      const y   = this.y + row * (cardH + gap);
      rr(c, x, y, colW, cardH, 5, GR50, GR200);
      tx(c, k, x + 10, y + 14, 8, TEXT2);
      tx(c, String(v || "—"), x + 10, y + 30, 10, TEXT, "500", "left", colW - 20);
    });
    this.y += rows * (cardH + gap) + 4;
  }

  statCards(stats: { label: string; value: string | number; color: string }[]) {
    const cardH = 68;
    const gap   = 10;
    const colW  = (CW - gap * (stats.length - 1)) / stats.length;
    this.ensureSpace(cardH + 14);
    const c = this._ctx;
    stats.forEach((s, i) => {
      const x = M + i * (colW + gap);
      const y = this.y;
      rr(c, x, y, colW, cardH, 6, WHITE, GR200);
      c.fillStyle = s.color;
      c.fillRect(x, y, 3, cardH);
      tx(c, String(s.value), x + 14, y + 41, 26, s.color, "bold");
      tx(c, s.label.toUpperCase(), x + 14, y + 58, 8, TEXT2, "bold");
    });
    this.y += cardH + 14;
  }

  table(
    headers: string[],
    colWidths: number[],
    rows: (string | null)[][],
    opts: { rowH?: number; severityCol?: number; monoCol?: number[] } = {},
  ) {
    const { rowH = 24, severityCol, monoCol = [] } = opts;
    const totalW  = colWidths.reduce((a, b) => a + b, 0) + (headers.length - 1) * 8;
    const headerH = 26;

    this.ensureSpace(headerH + Math.min(rows.length, 2) * rowH);
    const c = this._ctx;

    // Header row
    c.fillStyle = NAVY;
    c.fillRect(M, this.y, totalW, headerH);
    let hx = M;
    for (let ci = 0; ci < headers.length; ci++) {
      tx(c, headers[ci].toUpperCase(), hx + 8, this.y + 17, 8, WHITE, "bold");
      hx += colWidths[ci] + 8;
    }
    this.y += headerH;

    // Data rows
    for (let ri = 0; ri < rows.length; ri++) {
      this.ensureSpace(rowH);
      const bg = ri % 2 === 0 ? WHITE : GR50;
      c.fillStyle = bg;
      c.fillRect(M, this.y, totalW, rowH);
      c.strokeStyle = GR100;
      c.lineWidth   = 1;
      c.beginPath();
      c.moveTo(M, this.y + rowH);
      c.lineTo(M + totalW, this.y + rowH);
      c.stroke();

      let cx2 = M;
      for (let ci = 0; ci < headers.length; ci++) {
        const cell = rows[ri][ci] ?? "";
        const cw   = colWidths[ci];

        if (ci === severityCol) {
          const sev  = cell.toLowerCase();
          const bw3  = 62; const bh = 16;
          rr(c, cx2 + 6, this.y + (rowH - bh) / 2, bw3, bh, 8, sevBg(sev));
          tx(c, cell.toUpperCase(), cx2 + 6 + bw3 / 2, this.y + (rowH - bh) / 2 + 11.5, 7.5, sevColor(sev), "bold", "center");
        } else if (monoCol.includes(ci)) {
          monoTx(c, cell, cx2 + 8, this.y + rowH - 7, 8.5, TEXT, cw - 10);
        } else {
          tx(c, trunc(c, cell, 9, cw - 12), cx2 + 8, this.y + rowH - 7, 9, TEXT);
        }
        cx2 += cw + 8;
      }
      this.y += rowH;
    }
    this.y += 10;
  }

  findingCard(title: string, severity: string, cve?: string | null, cvss?: number | null) {
    this.ensureSpace(34);
    const c   = this._ctx;
    const sc  = sevColor(severity);
    const sbg = sevBg(severity);
    const y   = this.y;
    rr(c, M, y, CW, 28, 5, sbg, `${sc}44`);
    // Severity pill
    rr(c, M + 8, y + 6, 66, 16, 8, sc);
    tx(c, severity.toUpperCase(), M + 8 + 33, y + 17, 7.5, WHITE, "bold", "center");
    // Title
    const titleMaxW = CW - 178;
    tx(c, trunc(c, title, 9.5, titleMaxW), M + 84, y + 18, 9.5, NAVY, "bold");
    // CVE / CVSS right-aligned
    let rx = PW - M - 10;
    if (cvss != null) {
      const str  = `CVSS ${cvss}`;
      const strW = mw(c, str, 9, "bold");
      tx(c, str, rx - strW, y + 18, 9, sc, "bold");
      rx -= strW + 14;
    }
    if (cve) {
      const cveW = mw(c, cve, 8.5);
      monoTx(c, cve, rx - cveW, y + 18, 8.5, TEXT2);
    }
    this.y += 34;
  }

  finalize(): HTMLCanvasElement[] {
    if (this.pn_ > 0) this._endPage();
    return this.pages_;
  }
}

// ── PDF binary assembly ──────────────────────────────────────────────────
// Encodes each canvas as a JPEG and stitches into a multi-page PDF

function buildPdf(canvases: HTMLCanvasElement[]): Blob {
  const ptW = Math.round(PW * 72 / 96);
  const ptH = Math.round(PH * 72 / 96);

  const images: Uint8Array[] = canvases.map(cv => {
    const b64 = cv.toDataURL("image/jpeg", 0.92).split(",")[1];
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  });

  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const offsets: number[] = [];
  let offset = 0;

  function push(s: string) { const b = enc.encode(s); parts.push(b); offset += b.length; }
  function pushB(b: Uint8Array) { parts.push(b); offset += b.length; }

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
      `/Width ${PW} /Height ${PH} /ColorSpace /DeviceRGB /BitsPerComponent 8 ` +
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
  a.href = url;
  a.download = filename.endsWith(".pdf") ? filename : filename + ".pdf";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 6000);
}

// ── Asset PDF ──────────────────────────────────────────────────────────

export async function downloadAssetPdf(assetId: number, token: string | null): Promise<void> {
  const hdrs: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`/api/reports/pdf-data/asset/${assetId}`, { headers: hdrs });
  if (!res.ok) throw new Error("Failed to fetch asset PDF data");
  const d = await res.json() as {
    asset: { name: string; value: string; type: string; ipAddress?: string; port?: number; riskLevel: string; verificationStatus: string; lastScannedAt?: string };
    riskScore?: { score: number; level: string };
    findings: { title: string; severity: string; status: string; cve?: string; cvss?: number; description?: string; remediation?: string }[];
    technologies: { technology: string; category?: string; version?: string; confidence?: number }[];
    findingCounts: { total: number; open: number; critical: number; high: number; medium: number; low: number };
  };

  const rLevel = (d.riskScore?.level ?? d.asset.riskLevel ?? "low");
  const rc     = sevColor(rLevel);

  const cover = makeCover({
    title:      `${d.asset.name} — Security Assessment Report`,
    reportKind: "Asset Vulnerability Report",
    metaPairs:  [
      ["Asset Name",   d.asset.name],
      ["Target",       d.asset.value],
      ["Asset Type",   d.asset.type.toUpperCase()],
      ["Risk Level",   rLevel.toUpperCase()],
      ["IP Address",   d.asset.ipAddress ?? "—"],
      ["Last Scanned", d.asset.lastScannedAt ? new Date(d.asset.lastScannedAt).toLocaleDateString() : "Never"],
    ],
    riskLabel:  `Risk Level: ${rLevel.toUpperCase()}`,
    riskColor:  rc,
  });

  const doc = new PdfDoc(`${d.asset.name} — Security Assessment`);
  doc.newPage();

  // ── Executive Summary ──
  doc.sectionHeader("Executive Summary");
  doc.gap(4);
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
  doc.gap(8);

  // ── Asset Details ──
  doc.sectionHeader("Asset Details");
  doc.gap(4);
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
  doc.gap(8);

  // ── Findings Table ──
  if (d.findings.length > 0) {
    doc.sectionHeader("Vulnerability Findings");
    doc.gap(4);
    doc.table(
      ["Severity", "Title", "CVE", "CVSS", "Status"],
      [70, 254, 96, 52, 76],
      d.findings.map(f => [f.severity, f.title, f.cve ?? "—", f.cvss != null ? String(f.cvss) : "—", f.status]),
      { severityCol: 0, monoCol: [2] },
    );
    doc.gap(8);

    // ── Finding Details ──
    doc.sectionHeader("Finding Details");
    doc.gap(4);
    for (const f of d.findings.slice(0, 25)) {
      doc.findingCard(f.title, f.severity, f.cve, f.cvss);
      if (f.description)  doc.text(f.description,               { size: 9, color: TEXT2, indent: 12 });
      if (f.remediation)  doc.text(`Fix: ${f.remediation}`,    { size: 9, color: LOW,   indent: 12 });
      doc.gap(6);
    }
  } else {
    doc.gap(8);
    doc.text("No vulnerability findings recorded for this asset. The asset appears clean.", { size: 10, color: LOW });
    doc.gap(8);
  }

  // ── Technology Stack ──
  if (d.technologies.length > 0) {
    doc.sectionHeader("Technology Stack");
    doc.gap(4);
    doc.table(
      ["Technology", "Category", "Version", "Confidence"],
      [200, 180, 128, 130],
      d.technologies.map(t => [t.technology, t.category ?? "—", t.version ?? "—", t.confidence != null ? `${t.confidence}%` : "—"]),
    );
  }

  const filename = `${d.asset.name.replace(/[^a-z0-9]/gi, "_")}_security_report.pdf`;
  triggerDownload(buildPdf([cover, ...doc.finalize()]), filename);
}

// ── Brand Threat PDF ───────────────────────────────────────────────────

export async function downloadBrandThreatPdf(scanId: number, token: string | null): Promise<void> {
  const hdrs: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(`/api/reports/pdf-data/brand-threat/${scanId}`, { headers: hdrs });
  if (!res.ok) throw new Error("Failed to fetch brand threat PDF data");
  const d = await res.json() as {
    scan: {
      id: number; domain: string; status: string; totalPermutations: number;
      liveCount: number; registeredCount: number; phishingRisk: string;
      fuzzerBreakdown?: Record<string, number>;
      faviconUrl?: string; faviconMmh3?: number; faviconMd5?: string; faviconSha256?: string;
      faviconSearchUrls?: Record<string, { url: string; hash_type: string }>;
      favihunterStatus?: string; createdAt: string; completedAt?: string;
    };
    topResults:  { permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[]; mxSpf?: string; riskScore: number; isSuspicious: boolean }[];
    liveResults: { permutation: string; fuzzer: string; dnsA?: string[]; dnsMx?: string[]; mxSpf?: string; riskScore: number; isSuspicious: boolean }[];
  };

  const phishRisk = d.scan.phishingRisk ?? "low";
  const rc        = sevColor(phishRisk);

  const cover = makeCover({
    title:      `${d.scan.domain} — Brand Threat Intelligence Report`,
    reportKind: "Domain & Phishing Threat Analysis",
    metaPairs:  [
      ["Target Domain",    d.scan.domain],
      ["Phishing Risk",    phishRisk.toUpperCase()],
      ["Permutations",     String(d.scan.totalPermutations)],
      ["Live Domains",     String(d.scan.liveCount)],
      ["Favicon Analysis", d.scan.favihunterStatus === "done" ? "Completed" : "Not Run"],
      ["Scan Date",        new Date(d.scan.createdAt).toLocaleDateString()],
    ],
    riskLabel:  `Phishing Risk: ${phishRisk.toUpperCase()}`,
    riskColor:  rc,
  });

  const doc = new PdfDoc(`${d.scan.domain} — Brand Threat Report`);
  doc.newPage();

  // ── Scan Summary ──
  doc.sectionHeader("Scan Summary");
  doc.gap(4);
  const suspCount = d.topResults.filter(r => r.isSuspicious).length;
  doc.statCards([
    { label: "Total Permutations", value: d.scan.totalPermutations, color: NAVY },
    { label: "Live Domains",       value: d.scan.liveCount,         color: CRIT },
    { label: "Registered",         value: d.scan.registeredCount,   color: HIGH },
    { label: "Suspicious",         value: suspCount,                color: MED  },
  ]);
  doc.gap(8);

  // ── Domain Intelligence ──
  doc.sectionHeader("Domain Intelligence");
  doc.gap(4);
  doc.keyValue([
    ["Target Domain",      d.scan.domain],
    ["Phishing Risk",      phishRisk.toUpperCase()],
    ["Scan Started",       new Date(d.scan.createdAt).toLocaleString()],
    ["Scan Completed",     d.scan.completedAt ? new Date(d.scan.completedAt).toLocaleString() : "—"],
    ["Total Permutations", String(d.scan.totalPermutations)],
    ["Live / Resolving",   String(d.scan.liveCount)],
  ], 3);
  doc.gap(8);

  // ── Favicon Intelligence ──
  if (d.scan.favihunterStatus === "done" && d.scan.faviconMd5) {
    doc.sectionHeader("Favicon Intelligence", "#8b5cf6");
    doc.gap(4);
    doc.keyValue([
      ["Favicon URL", d.scan.faviconUrl ?? "—"],
      ["MMH3 Hash",   String(d.scan.faviconMmh3 ?? "—")],
      ["MD5 Hash",    d.scan.faviconMd5 ?? "—"],
      ["SHA256",      d.scan.faviconSha256 ? d.scan.faviconSha256.slice(0, 40) + "…" : "—"],
    ], 2);

    if (d.scan.faviconSearchUrls) {
      doc.gap(6);
      doc.text("Search Engine Pivot URLs (use to find infrastructure sharing this favicon):", { size: 9, color: TEXT2, weight: "bold" });
      for (const [name, info] of Object.entries(d.scan.faviconSearchUrls)) {
        doc.gap(2);
        doc.text(`• ${name}  [${info.hash_type}]`, { size: 9, color: NAVY, indent: 8 });
        doc.text(info.url, { size: 8, color: TEXT2, indent: 22 });
      }
    }
    doc.gap(8);
  }

  // ── Fuzzer Breakdown ──
  if (d.scan.fuzzerBreakdown) {
    doc.sectionHeader("Permutation Type Breakdown");
    doc.gap(4);
    const fuzzers = Object.entries(d.scan.fuzzerBreakdown)
      .filter(([k]) => !k.startsWith("*"))
      .sort(([, a], [, b]) => (b as number) - (a as number));
    doc.table(
      ["Fuzzer Type", "Count", "% of Total"],
      [310, 120, 110],
      fuzzers.map(([k, v]) => [
        k.charAt(0).toUpperCase() + k.slice(1),
        String(v),
        `${(((v as number) / Math.max(d.scan.totalPermutations, 1)) * 100).toFixed(1)}%`,
      ]),
    );
    doc.gap(8);
  }

  // ── Notable Domains ──
  const live    = d.liveResults;
  const susp    = d.topResults.filter(r => r.isSuspicious);
  const notable = [
    ...live,
    ...susp.filter(r => !live.find(lr => lr.permutation === r.permutation)),
  ].slice(0, 60);

  if (notable.length > 0) {
    doc.sectionHeader("Notable Domains — Live & Suspicious", CRIT);
    doc.gap(4);
    doc.table(
      ["Domain", "Type", "IP Addresses", "Risk", "MX / SPF"],
      [194, 88, 172, 54, 130],
      notable.map(r => [
        r.permutation,
        r.fuzzer,
        r.dnsA?.join(", ") ?? "—",
        String(r.riskScore),
        r.mxSpf ?? (r.dnsMx?.length ? "Has MX" : "—"),
      ]),
      { monoCol: [0, 2] },
    );
  } else {
    doc.gap(8);
    doc.text(
      "No live or suspicious domains detected. The brand appears well-protected from " +
      "active typosquatting and phishing campaigns at the time of this scan.",
      { size: 10, color: LOW },
    );
    doc.gap(8);
  }

  const filename = `${d.scan.domain.replace(/\./g, "_")}_brand_threat_report.pdf`;
  triggerDownload(buildPdf([cover, ...doc.finalize()]), filename);
}
