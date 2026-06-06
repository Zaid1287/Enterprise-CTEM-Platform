// Generates a real PDF using the browser's Canvas API (no external deps)

interface PdfSection {
  title?: string;
  lines: string[];
}

export function downloadAsPdf(filename: string, title: string, sections: PdfSection[]) {
  const PAGE_W = 794;   // A4 at 96dpi
  const PAGE_H = 1123;
  const MARGIN = 48;
  const FONT = "Inter, system-ui, sans-serif";
  const MONO = "ui-monospace, 'Cascadia Code', monospace";

  // ── Measure all content to know how many pages we need ──────────────
  const canvas = document.createElement("canvas");
  canvas.width = PAGE_W;
  canvas.height = PAGE_H;
  const ctx = canvas.getContext("2d")!;

  // Collect all "draw commands" with y-offsets, then split into pages
  interface DrawCmd {
    type: "title" | "section" | "text" | "divider" | "gap";
    text?: string;
    h: number;
  }
  const cmds: DrawCmd[] = [];
  cmds.push({ type: "title", text: title, h: 52 });
  cmds.push({ type: "gap", h: 12 });

  for (const section of sections) {
    if (section.title) {
      cmds.push({ type: "section", text: section.title, h: 28 });
    }
    for (const line of section.lines) {
      if (line === "---") {
        cmds.push({ type: "divider", h: 16 });
      } else {
        cmds.push({ type: "text", text: line, h: 18 });
      }
    }
    cmds.push({ type: "gap", h: 14 });
  }

  // ── Paginate ─────────────────────────────────────────────────────────
  const CONTENT_H = PAGE_H - MARGIN * 2 - 24; // leave room for header/footer
  const pages: DrawCmd[][] = [];
  let page: DrawCmd[] = [];
  let usedH = 0;

  for (const cmd of cmds) {
    if (usedH + cmd.h > CONTENT_H && page.length > 0) {
      pages.push(page);
      page = [];
      usedH = 0;
    }
    page.push(cmd);
    usedH += cmd.h;
  }
  if (page.length > 0) pages.push(page);

  // ── Render each page to its own canvas, then stitch as PDF via data URL ──
  // We'll use a multi-canvas approach and produce a PDF using the PDF-via-image
  // technique (embed images in a minimal hand-written PDF).

  const pageCanvases: HTMLCanvasElement[] = [];

  for (let pi = 0; pi < pages.length; pi++) {
    const pc = document.createElement("canvas");
    pc.width = PAGE_W;
    pc.height = PAGE_H;
    const c = pc.getContext("2d")!;

    // Background
    c.fillStyle = "#0f1117";
    c.fillRect(0, 0, PAGE_W, PAGE_H);

    // Top accent bar
    c.fillStyle = "#3b82f6";
    c.fillRect(0, 0, PAGE_W, 4);

    // Header line
    c.fillStyle = "#1e2333";
    c.fillRect(MARGIN, 18, PAGE_W - MARGIN * 2, 1);

    // Header text (logo area)
    c.fillStyle = "#3b82f6";
    c.font = `bold 11px ${FONT}`;
    c.fillText("CTEM PLATFORM", MARGIN, 14);

    c.fillStyle = "#6b7280";
    c.font = `10px ${FONT}`;
    c.fillText(`Page ${pi + 1} of ${pages.length}`, PAGE_W - MARGIN - 60, 14);

    // Content area
    let y = MARGIN + 24;

    for (const cmd of pages[pi]) {
      if (cmd.type === "title") {
        c.fillStyle = "#f9fafb";
        c.font = `bold 22px ${FONT}`;
        c.fillText(cmd.text!, MARGIN, y + 24);
        y += cmd.h;
      } else if (cmd.type === "section") {
        c.fillStyle = "#3b82f6";
        c.font = `bold 11px ${FONT}`;
        c.fillText((cmd.text ?? "").toUpperCase(), MARGIN, y + 12);
        // Underline
        c.fillStyle = "#3b82f620";
        c.fillRect(MARGIN, y + 15, PAGE_W - MARGIN * 2, 1);
        y += cmd.h;
      } else if (cmd.type === "divider") {
        c.fillStyle = "#374151";
        c.fillRect(MARGIN, y + 7, PAGE_W - MARGIN * 2, 1);
        y += cmd.h;
      } else if (cmd.type === "gap") {
        y += cmd.h;
      } else if (cmd.type === "text") {
        const line = cmd.text ?? "";
        const isKeyVal = line.includes(":") && !line.startsWith(" ");
        const isIndented = line.startsWith("  ");
        const isBullet = line.trimStart().startsWith("•");

        if (isKeyVal && !isIndented) {
          const colonIdx = line.indexOf(":");
          const key = line.slice(0, colonIdx + 1);
          const val = line.slice(colonIdx + 1);
          c.fillStyle = "#9ca3af";
          c.font = `10px ${FONT}`;
          c.fillText(key, MARGIN, y + 12);
          const keyW = c.measureText(key).width;
          c.fillStyle = "#e5e7eb";
          c.font = `10px ${MONO}`;
          c.fillText(val, MARGIN + keyW + 2, y + 12);
        } else if (isBullet) {
          c.fillStyle = "#3b82f6";
          c.font = `10px ${FONT}`;
          c.fillText("•", MARGIN + 8, y + 12);
          c.fillStyle = "#d1d5db";
          c.font = `10px ${FONT}`;
          c.fillText(line.replace(/^\s*•\s*/, ""), MARGIN + 20, y + 12);
        } else {
          c.fillStyle = isIndented ? "#9ca3af" : "#d1d5db";
          c.font = `10px ${isIndented ? MONO : FONT}`;
          c.fillText(line, MARGIN + (isIndented ? 16 : 0), y + 12);
        }
        y += cmd.h;
      }
    }

    // Footer
    c.fillStyle = "#1e2333";
    c.fillRect(MARGIN, PAGE_H - MARGIN, PAGE_W - MARGIN * 2, 1);
    c.fillStyle = "#4b5563";
    c.font = `9px ${FONT}`;
    c.fillText("Confidential — Generated by CTEM Platform", MARGIN, PAGE_H - MARGIN + 14);
    c.fillText(new Date().toLocaleString(), PAGE_W - MARGIN - 120, PAGE_H - MARGIN + 14);

    pageCanvases.push(pc);
  }

  // ── Build a minimal multi-page PDF (image-based) ─────────────────────
  buildImagePdf(pageCanvases, filename, PAGE_W, PAGE_H);
}

function buildImagePdf(
  canvases: HTMLCanvasElement[],
  filename: string,
  pageW: number,
  pageH: number,
) {
  // Encode each canvas as JPEG and embed in a hand-written PDF
  const jpegQuality = 0.92;
  const images: Uint8Array[] = canvases.map(c => {
    const dataUrl = c.toDataURL("image/jpeg", jpegQuality);
    const b64 = dataUrl.split(",")[1];
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  });

  // PDF dimensions in points (1pt = 1/72 inch; 96dpi canvas → 72pt: multiply by 72/96)
  const ptW = Math.round(pageW * 72 / 96);
  const ptH = Math.round(pageH * 72 / 96);

  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];
  const offsets: number[] = [];
  let offset = 0;

  function push(s: string) {
    const b = enc.encode(s);
    parts.push(b);
    offset += b.length;
  }

  function pushBytes(b: Uint8Array) {
    parts.push(b);
    offset += b.length;
  }

  // Header
  push("%PDF-1.4\n");
  push("%\xFF\xFF\xFF\xFF\n");

  // Objects: 1=catalog, 2=pages, 3+(2*i)=page, 3+(2*i)+1=xobject
  const nPages = images.length;
  const catalogObj = 1;
  const pagesObj = 2;
  const firstPageObj = 3; // pages at 3, 5, 7, ...
  const firstImgObj = 4;  // images at 4, 6, 8, ...

  // Catalog
  offsets[catalogObj] = offset;
  push(`${catalogObj} 0 obj\n<< /Type /Catalog /Pages ${pagesObj} 0 R >>\nendobj\n`);

  // Pages
  const pageRefs = Array.from({ length: nPages }, (_, i) => `${firstPageObj + i * 2} 0 R`).join(" ");
  offsets[pagesObj] = offset;
  push(`${pagesObj} 0 obj\n<< /Type /Pages /Kids [${pageRefs}] /Count ${nPages} >>\nendobj\n`);

  for (let i = 0; i < nPages; i++) {
    const pageObjId = firstPageObj + i * 2;
    const imgObjId = firstImgObj + i * 2;
    const imgName = `Im${i}`;

    // Content stream: draw image to fill page
    const stream = `q ${ptW} 0 0 ${ptH} 0 0 cm /${imgName} Do Q\n`;
    const streamBytes = enc.encode(stream);
    const contentObjId = imgObjId + nPages * 2; // safe non-colliding ids
    // Instead, embed content inline in page (simpler):
    // Use a resources + content stream embedded in the page dict
    const contentStream = `q ${ptW} 0 0 ${ptH} 0 0 cm /${imgName} Do Q`;
    const csBytes = enc.encode(contentStream);

    // Content stream object
    const csObjId = firstPageObj + i * 2 + nPages * 2 + 10;
    offsets[csObjId] = offset;
    push(`${csObjId} 0 obj\n<< /Length ${csBytes.length} >>\nstream\n`);
    pushBytes(csBytes);
    push(`\nendstream\nendobj\n`);

    // Page
    offsets[pageObjId] = offset;
    push(
      `${pageObjId} 0 obj\n<< /Type /Page /Parent ${pagesObj} 0 R ` +
      `/MediaBox [0 0 ${ptW} ${ptH}] ` +
      `/Resources << /XObject << /${imgName} ${imgObjId} 0 R >> >> ` +
      `/Contents ${csObjId} 0 R >>\nendobj\n`,
    );

    // Image XObject
    offsets[imgObjId] = offset;
    push(
      `${imgObjId} 0 obj\n<< /Type /XObject /Subtype /Image ` +
      `/Width ${pageW} /Height ${pageH} ` +
      `/ColorSpace /DeviceRGB /BitsPerComponent 8 ` +
      `/Filter /DCTDecode /Length ${images[i].length} >>\nstream\n`,
    );
    pushBytes(images[i]);
    push(`\nendstream\nendobj\n`);
  }

  // xref
  const xrefOffset = offset;
  // Collect all used object ids
  const allIds = Object.keys(offsets).map(Number).sort((a, b) => a - b);
  const maxId = Math.max(...allIds);

  push(`xref\n0 ${maxId + 1}\n`);
  push(`0000000000 65535 f \n`);
  for (let id = 1; id <= maxId; id++) {
    if (offsets[id] !== undefined) {
      push(`${String(offsets[id]).padStart(10, "0")} 00000 n \n`);
    } else {
      push(`0000000000 65535 f \n`);
    }
  }

  push(`trailer\n<< /Size ${maxId + 1} /Root ${catalogObj} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`);

  // Assemble
  const totalLen = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(totalLen);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }

  const blob = new Blob([out], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename.endsWith(".pdf") ? filename : filename + ".pdf";
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}
