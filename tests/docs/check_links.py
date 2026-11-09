"""Check local link targets in maintained navigation docs (not archived exports)."""
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[2]
docs = [root / 'README.md', root / 'AGENTS.md']
docs += [root / 'docs' / section / 'README.md'
         for section in ('architecture', 'development', 'security', 'operations')]
errors = []
for doc in docs:
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)', doc.read_text()):
        url = urlsplit(target)
        if url.scheme or url.netloc or not url.path:
            continue
        path = (doc.parent / unquote(url.path)).resolve()
        if not path.exists():
            errors.append(f'{doc.relative_to(root)}: missing {target}')
if errors:
    raise SystemExit('\n'.join(errors))
print(f'Local link targets passed in {len(docs)} maintained navigation documents.')
