/**
 * Converts a subset of Markdown (used in security reports) to HTML.
 * Handles: headings, bold/italic, code blocks, inline code, tables,
 * ordered/unordered lists, blockquotes, horizontal rules, severity badges.
 */
function markdownToHtml(md) {
  const lines = md.split('\n')
  let html = ''
  let inCode = false
  let inTable = false
  let tableHasHead = false
  let inList = false
  let listTag = ''

  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

  const inline = (s) => {
    s = esc(s)
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>')
    s = s.replace(/\*\*\*([^*]+)\*\*\*/g, '<strong><em>$1</em></strong>')
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    s = s.replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
    s = s.replace(/\[CRITICAL\]/g, '<span class="crit">[CRITICAL]</span>')
    s = s.replace(/\[HIGH\]/g,     '<span class="high">[HIGH]</span>')
    s = s.replace(/\[MEDIUM\]/g,   '<span class="med">[MEDIUM]</span>')
    s = s.replace(/\[LOW\]/g,      '<span class="low">[LOW]</span>')
    s = s.replace(/\[INFO(?:RMATIONAL)?\]/gi, '<span class="info">[INFO]</span>')
    return s
  }

  const closeList = () => {
    if (inList) { html += `</${listTag}>\n`; inList = false; listTag = '' }
  }
  const closeTable = () => {
    if (inTable) { html += '</tbody></table>\n'; inTable = false; tableHasHead = false }
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    // ── Code fence ──────────────────────────────────────────────────────────
    if (line.startsWith('```')) {
      if (inCode) {
        html += '</code></pre>\n'; inCode = false
      } else {
        closeList(); closeTable()
        const lang = esc(line.slice(3).trim())
        html += `<pre><code${lang ? ` class="lang-${lang}"` : ''}>`
        inCode = true
      }
      continue
    }
    if (inCode) { html += esc(line) + '\n'; continue }

    // ── Table ────────────────────────────────────────────────────────────────
    if (line.startsWith('|')) {
      // Separator row (| --- | --- |) — skip, just marks end of thead
      if (/^\|[\s\-:|]+\|/.test(line) && inTable) {
        html += '</thead><tbody>\n'
        continue
      }
      const cells = line.split('|').slice(1, -1)
      if (!inTable) {
        closeList()
        html += '<table><thead>\n'
        inTable = true; tableHasHead = true
        html += '<tr>' + cells.map(c => `<th>${inline(c.trim())}</th>`).join('') + '</tr>\n'
      } else {
        html += '<tr>' + cells.map(c => `<td>${inline(c.trim())}</td>`).join('') + '</tr>\n'
      }
      continue
    }
    closeTable()

    // ── Heading ──────────────────────────────────────────────────────────────
    const hm = line.match(/^(#{1,6})\s+(.+)/)
    if (hm) {
      closeList()
      html += `<h${hm[1].length}>${inline(hm[2])}</h${hm[1].length}>\n`
      continue
    }

    // ── Horizontal rule ──────────────────────────────────────────────────────
    if (/^[-*_]{3,}$/.test(line.trim())) {
      closeList(); html += '<hr>\n'; continue
    }

    // ── Blockquote ───────────────────────────────────────────────────────────
    if (line.startsWith('> ')) {
      closeList()
      html += `<blockquote><p>${inline(line.slice(2))}</p></blockquote>\n`
      continue
    }

    // ── Unordered list ───────────────────────────────────────────────────────
    const ulm = line.match(/^[ \t]*[-*+]\s+(.+)/)
    if (ulm) {
      if (!inList) { html += '<ul>\n'; inList = true; listTag = 'ul' }
      html += `<li>${inline(ulm[1])}</li>\n`
      continue
    }

    // ── Ordered list ─────────────────────────────────────────────────────────
    const olm = line.match(/^[ \t]*\d+[.)]\s+(.+)/)
    if (olm) {
      if (!inList) { html += '<ol>\n'; inList = true; listTag = 'ol' }
      html += `<li>${inline(olm[1])}</li>\n`
      continue
    }

    // ── Blank line ───────────────────────────────────────────────────────────
    if (line.trim() === '') {
      closeList(); html += '\n'; continue
    }

    // ── Paragraph ────────────────────────────────────────────────────────────
    closeList()
    html += `<p>${inline(line)}</p>\n`
  }

  closeList(); closeTable()
  if (inCode) html += '</code></pre>\n'
  return html
}

const PRINT_CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
    font-size: 13px; line-height: 1.65; color: #1a1a1a;
    max-width: 960px; margin: 0 auto; padding: 2.5rem 2rem;
  }
  h1 { font-size: 1.9em; border-bottom: 2px solid #cc0000; padding-bottom: .4em; margin: 1.4em 0 .6em; }
  h2 { font-size: 1.4em; border-bottom: 1px solid #ddd; padding-bottom: .3em; margin: 1.4em 0 .5em; color: #111; }
  h3 { font-size: 1.15em; margin: 1.1em 0 .4em; color: #222; }
  h4 { font-size: 1em; margin: .9em 0 .3em; color: #333; font-weight: 700; }
  p  { margin: .55em 0; }
  ul, ol { margin: .55em 0 .55em 1.6em; }
  li { margin: .22em 0; }
  code {
    background: #f3f3f3; border: 1px solid #ddd;
    padding: .12em .35em; border-radius: 3px;
    font-family: 'Courier New', monospace; font-size: .88em;
  }
  pre {
    background: #f6f6f6; border: 1px solid #ddd;
    padding: 1em; overflow-x: auto; margin: .8em 0;
    white-space: pre-wrap; word-break: break-all;
  }
  pre code { background: none; border: none; padding: 0; font-size: .85em; }
  table { border-collapse: collapse; width: 100%; margin: .8em 0; font-size: .92em; }
  th { background: #eee; font-weight: 700; text-align: left; }
  th, td { border: 1px solid #ccc; padding: .38em .65em; vertical-align: top; }
  blockquote {
    border-left: 3px solid #aaa; margin: .8em 0;
    padding: .4em 1em; color: #555; background: #fafafa;
  }
  hr { border: none; border-top: 1px solid #ddd; margin: 1.4em 0; }
  strong { font-weight: 700; }
  em { font-style: italic; }
  .crit { color: #cc0000; font-weight: 700; }
  .high { color: #e05000; font-weight: 700; }
  .med  { color: #b07000; font-weight: 700; }
  .low  { color: #2a7a2a; }
  .info { color: #1a5faa; }
  .report-header {
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 2px solid #cc0000; padding-bottom: .9rem; margin-bottom: 1.8rem;
  }
  .report-header img {
    height: 48px; width: auto; object-fit: contain;
  }
  .report-header-meta {
    text-align: right; font-size: .78em; color: #666; line-height: 1.5;
  }
  .report-header-meta strong { font-size: 1em; color: #1a1a1a; letter-spacing: .04em; }
  @media print {
    body { padding: 1rem; }
    a { text-decoration: none; color: inherit; }
    .report-header { break-inside: avoid; }
  }
`

/**
 * Opens a print-ready window from a Markdown security report string.
 * The user can Save as PDF from the browser print dialog.
 * @param {string} markdown — raw markdown content (may include <!-- REPORT --> marker)
 */
export function exportReportAsPdf(markdown) {
  // Strip internal markers and PDF offer line
  const clean = markdown
    .replace(/<!--\s*REPORT\s*-->\s*/g, '')
    .replace(/^>\s*📄.*$/gm, '')
    .replace(/^\s*---\s*$/gm, (m, offset, str) => {
      // Keep --- that are part of the content, remove trailing one before PDF offer
      const after = str.slice(offset + m.length).trim()
      return after.startsWith('> 📄') || after === '' ? '' : m
    })
    .trim()

  const body = markdownToHtml(clean)
  const now = new Date().toLocaleString()
  const logoUrl = `${window.location.origin}/ramibot.png`

  const reportHeader = `
<div class="report-header">
  <img src="${logoUrl}" alt="RamiBot" onerror="this.style.display='none'">
  <div class="report-header-meta">
    <strong>SECURITY REPORT</strong><br>
    Generated: ${now}<br>
    RamiBot — AI Cybersecurity Platform
  </div>
</div>`

  const win = window.open('', '_blank', 'width=1000,height=750')
  if (!win) {
    alert('El navegador bloqueó la ventana emergente. Permite popups para este sitio.')
    return
  }

  win.document.write(`<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Security Report — ${now}</title>
  <style>${PRINT_CSS}</style>
</head>
<body>
${reportHeader}
${body}
<script>
  window.addEventListener('load', () => setTimeout(() => window.print(), 200))
<\/script>
</body>
</html>`)
  win.document.close()
}
