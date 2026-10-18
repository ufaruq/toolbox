#!/usr/bin/env python3
"""Rebuild the design, PDF, Markdown and diagrams from checked-in sources."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, help='Default: docs/design/.build')
parser.add_argument('--dest', type=Path, help='Default: docs/design')
parser.add_argument('--pages', action='store_true', help='Render all PDF pages with pdftoppm for visual review')
args = parser.parse_args()
source = Path(__file__).resolve().parent
dest = (args.dest or source.parent).resolve()
build = (args.output_dir or source.parent / '.build').resolve()
build.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, str(source/'build_design.py'), '--output-dir', str(build)], check=True)
soffice = shutil.which('soffice')
if not soffice:
    raise SystemExit('Install LibreOffice and put soffice on PATH.')
docx = build/'Toolbox_User_Delegated_Connections_Design.docx'
pdf = docx.with_suffix('.pdf')
pdf.unlink(missing_ok=True)
with tempfile.TemporaryDirectory(prefix='toolbox-libreoffice-') as profile:
    subprocess.run([soffice, '-env:UserInstallation='+Path(profile).as_uri(), '--headless', '--convert-to', 'pdf', '--outdir', str(build), str(docx)], check=True)
if not pdf.is_file() or not pdf.stat().st_size:
    raise SystemExit('LibreOffice did not produce a PDF.')
subprocess.run([sys.executable, str(source/'export_markdown.py'), '--build-dir', str(build), '--dest', str(dest)], check=True)
if args.pages:
    poppler = shutil.which('pdftoppm')
    if not poppler:
        raise SystemExit('Install Poppler and put pdftoppm on PATH for --pages.')
    pages = build/'pages'
    pages.mkdir(exist_ok=True)
    for old in pages.glob('page-*.png'):
        old.unlink()
    subprocess.run([poppler, '-png', '-r', '144', str(pdf), str(pages/'page')], check=True)
print('Editable DOCX:', docx)
print('Review PDF:', dest/'user-delegated-connections.pdf')
