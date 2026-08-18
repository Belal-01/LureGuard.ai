"""Render docs/CHANGE-REGISTER.md to the styled HTML artifact.

The markdown is the single source of truth; this only presents it. Run
regen_board.py first so the board and counts are current.
"""
import html as H
import pathlib
import re
import sys

SRC = pathlib.Path('docs/CHANGE-REGISTER.md')
OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'register.html')
CSS = pathlib.Path('scripts/register.css').read_text()

SEV = {'🔴': ('crit', 'Critical'), '🟠': ('high', 'High'),
       '🟡': ('med', 'Medium'), '✅': ('fixed', 'Fixed')}


def inline(t: str) -> str:
    t = H.escape(t)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'(?<!\*)\*([^*]+)\*(?!\*)', r'<em>\1</em>', t)
    return t


def paras(rest: str) -> str:
    """Split a long item body into readable paragraphs.

    Items are one markdown table cell, so the structure is carried by bolded
    lead-ins (**Fixed:**, **Caught in review:**) rather than newlines. Split on
    those, and lift a trailing file:line citation into its own .ev line.
    """
    rest = rest.strip()
    if not rest:
        return ''
    # A bolded lead-in that starts a new thought begins a new paragraph.
    chunks = re.split(r'(?<=[.)\]])\s+(?=\*\*[A-Z][^*]{2,40}?[:.]?\*\*)', rest)
    out = []
    for c in chunks:
        c = c.strip()
        if not c:
            continue
        # Trailing bare code paths are evidence, not prose.
        m = re.match(r'^((?:`[^`]+`(?:\s*[·,]\s*)?)+)$', c)
        cls = ' class="ev"' if m else ''
        out.append(f'<p{cls}>{inline(c)}</p>')
    return ''.join(out)


def main() -> None:
    md = SRC.read_text()
    body, i = [], 0
    lines = md.split('\n')

    m = re.search(r'\*\*(\d+) items — (\d+) critical · (\d+) high · (\d+) medium · (\d+) fixed\*\*', md)
    total, crit, high, med, fixed = m.groups()

    body.append(f'''<header class="masthead">
      <p class="eyebrow">LureGuard.ai · Engineering Register</p>
      <h1>Change Register</h1>
      <p class="standfirst">Every known defect, gap and decision, with evidence. Source of truth for project state; replaced the self-scored PRODUCT-STATUS.md. Generated from <code>docs/CHANGE-REGISTER.md</code> so this page cannot drift from the repo.</p>
    </header>
    <div class="tally">
      <div><span class="n n-crit">{crit}</span><span class="l">Critical</span></div>
      <div><span class="n n-high">{high}</span><span class="l">High</span></div>
      <div><span class="n n-med">{med}</span><span class="l">Medium</span></div>
      <div><span class="n n-fixed">{fixed}</span><span class="l">Fixed</span></div>
      <div><span class="n">{total}</span><span class="l">Total</span></div>
    </div>''')

    in_board, lanes, cur = False, [], None
    open_section = False
    while i < len(lines):
        ln = lines[i]

        if ln.startswith('## Board'):
            in_board = True
            body.append('<section id="board"><h2>Board</h2>')
            i += 1
            continue

        if in_board:
            if ln.startswith('### '):
                if cur:
                    lanes.append(cur)
                cur = {'name': ln[4:].split(' · ')[0], 'n': ln.rsplit('· ', 1)[-1], 'note': '', 'cards': []}
            elif ln.startswith('_') and cur:
                cur['note'] = ln.strip('_')
            elif ln.startswith('- ') and cur:
                em = ln[2:4].strip()
                k, _lbl = SEV.get(em, ('med', 'Medium'))
                rest = ln[2:].split(' ', 1)[1]
                rid = re.search(r'\*\*(.+?)\*\*', rest)
                txt = re.sub(r'\*\*.+?\*\*\s*', '', rest, count=1)
                chk = '✓check' in txt
                txt = txt.replace('·  ✓check', '').replace('✓check', '')
                wait = re.search(r'_waits on (.+?)_', txt)
                txt = re.sub(r'—?\s*_waits on .+?_', '', txt).strip(' —')
                cur['cards'].append((k, rid.group(1) if rid else '', txt, chk,
                                     wait.group(1) if wait else None))
            elif ln.startswith('---'):
                if cur:
                    lanes.append(cur)
                cols = []
                for L in lanes:
                    cards = ''.join(
                        f'<li class="card k-{k}"><span class="cid">{H.escape(rid)}'
                        f'{"<span class=chk>✓</span>" if chk else ""}</span>'
                        f'<span class="ctitle">{inline(t)}</span>'
                        + (f'<span class="wait">waits on {H.escape(w)}</span>' if w else '')
                        + '</li>'
                        for k, rid, t, chk, w in L['cards'])
                    cols.append(f'<section class="lane"><header class="lane-h">'
                                f'<h3>{H.escape(L["name"])}</h3><span class="lane-n">{L["n"]}</span></header>'
                                f'<p class="lane-note">{inline(L["note"])}</p><ul class="cards">{cards}</ul></section>')
                body.append(f'<div class="board">{"".join(cols)}</div></section>')
                in_board = False
                open_section = False
            i += 1
            continue

        if ln.startswith('## '):
            if open_section:
                body.append('</section>')
            body.append(f'<section><h2>{inline(ln[3:])}</h2>')
            open_section = True
            i += 1
            continue

        if ln.startswith('| ID | Sev | Item |') or ln.startswith('|---'):
            i += 1
            continue

        m2 = re.match(r'^\| ([A-Z]{2,4}-\d+) \| (.+?) \| (.+?) \|\s*$', ln)
        if m2:
            rid, sv, item = m2.groups()
            k = next((v[0] for e, v in SEV.items() if e in sv), 'med')
            lbl = next((v[1] for e, v in SEV.items() if e in sv), 'Medium')
            parts = re.split(r'\*\*(.+?)\*\*', item, maxsplit=1)
            title = parts[1] if len(parts) > 2 else item[:70]
            rest = parts[2] if len(parts) > 2 else ''
            body.append(
                f'<article class="item"><div class="item-head">'
                f'<span class="id">{rid}</span><span class="chip c-{k}">{lbl}</span>'
                f'<h3>{inline(title)}</h3></div>'
                + paras(rest)
                + '</article>')
            i += 1
            continue

        if ln.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                if not lines[i].startswith('|---'):
                    rows.append([c.strip() for c in lines[i].strip('|').split('|')])
                i += 1
            if rows:
                head = ''.join(f'<th>{inline(c)}</th>' for c in rows[0])
                trs = ''.join('<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>'
                              for r in rows[1:])
                body.append(f'<div class="scroll"><table><thead><tr>{head}</tr></thead>'
                            f'<tbody>{trs}</tbody></table></div>')
            continue

        if ln.startswith('**Decision') or ln.startswith('**Rule'):
            body.append(f'<div class="callout">{inline(ln)}</div>')
        elif ln.strip() and not ln.startswith('#') and not ln.startswith('---'):
            body.append(f'<p class="prose">{inline(ln)}</p>')
        i += 1

    if open_section:
        body.append('</section>')
    OUT.write_text(
        f'<title>LureGuard.ai — Change Register</title>\n<style>{CSS}</style>\n'
        f'<div class="wrap">{"".join(body)}</div>\n')
    print(f'rendered {OUT} ({OUT.stat().st_size // 1024} KB)')


main()
