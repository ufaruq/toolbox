from pathlib import Path
from docx import Document
from docx.text.paragraph import Paragraph
from docx.table import Table
from docx.oxml.ns import qn
import shutil, argparse

parser=argparse.ArgumentParser(description='Export the generated DOCX to review Markdown and SVG assets')
parser.add_argument('--build-dir', type=Path, default=Path(__file__).resolve().parent.parent/'.build')
parser.add_argument('--dest', type=Path, default=Path(__file__).resolve().parent.parent)
args=parser.parse_args(); root=args.build_dir.resolve(); dest=args.dest.resolve()
(dest/'diagrams').mkdir(parents=True, exist_ok=True)
doc=Document(root/'Toolbox_User_Delegated_Connections_Design.docx')
figures=iter(['architecture','approval_sequence','oauth_sequence','read_sequence','refresh_sequence'])
parts=[]
for node in doc.element.body:
    if node.tag==qn('w:p'):
        para=Paragraph(node,doc)
        text=para.text.strip()
        if node.xpath('.//a:blip'):
            name=next(figures)
            parts.append(f'![{name.replace("_"," ")}](diagrams/{name}.svg)')
            shutil.copyfile(root/'figures'/f'{name}.svg',dest/'diagrams'/f'{name}.svg')
            continue
        if node.xpath('.//w:hyperlink'):
            vals=[]
            for el in node:
                if el.tag==qn('w:hyperlink'):
                    label=''.join(el.itertext())
                    # itertext can include the same text through multiple OOXML wrappers.
                    label=''.join(el.xpath('.//w:t/text()'))
                    vals.append(f'[{label}]({doc.part.rels[el.get(qn("r:id"))].target_ref})')
                elif el.tag==qn('w:r'):
                    vals.append(''.join(el.xpath('.//w:t/text()')))
            parts.append(''.join(vals));continue
        if not text:continue
        style=para.style.name
        if style=='Title':parts.append('# '+text.replace('\n',' '))
        elif style.startswith('Heading '):parts.append('#'*(int(style[-1])+1)+' '+text)
        elif style=='List Bullet':parts.append('- '+text)
        elif any(r.font.name=='DejaVu Sans Mono' for r in para.runs):parts.append('```text\n'+text+'\n```')
        else:parts.append(text)
    elif node.tag==qn('w:tbl'):
        table=Table(node,doc)
        rows=[]
        for row in table.rows:
            rows.append('| '+' | '.join(c.text.replace('|','\\|').replace('\n','<br>') for c in row.cells)+' |')
        rows.insert(1,'| '+' | '.join('---' for c in table.rows[0].cells)+' |')
        parts.append('\n'.join(rows))
parts.insert(1,'[PDF for page-by-page review](user-delegated-connections.pdf) · [Checks already completed](review-checks.md)')
(dest/'user-delegated-connections.md').write_text('\n\n'.join(parts)+'\n')
shutil.copyfile(root/'Toolbox_User_Delegated_Connections_Design.pdf',dest/'user-delegated-connections.pdf')
print(dest/'user-delegated-connections.md')
