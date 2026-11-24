"""Measured data -> PGFPlots tables and standalone TeX; XeLaTeX draws all plots."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
SCHEMES=("OTAC","ACL","UPROVE","CY22")
COLORS={"OTAC":"ours","ACL":"acl","UPROVE":"uprove","CY22":"cy"}
MARKERS={"OTAC":"*","ACL":"square*","UPROVE":"triangle*","CY22":"diamond*"}
LABELS={"OTAC":"This work","ACL":"ACL","UPROVE":"U-Prove","CY22":"CY22"}
OPS=("holder_issue","issuer_issue","show","verify")
TITLES=("Holder issuance","Issuer issuance","Presentation generation","Presentation verification")

PREAMBLE=r"""\documentclass[tikz,border=6pt]{standalone}
\usepackage{lmodern}
\usepackage{pgfplots}
\usepgfplotslibrary{groupplots}
\usetikzlibrary{patterns}
\pgfplotsset{compat=1.18}
\renewcommand{\familydefault}{\sfdefault}
\definecolor{ours}{RGB}{66,148,158}
\definecolor{acl}{RGB}{72,72,120}
\definecolor{uprove}{RGB}{202,143,56}
\definecolor{cy}{RGB}{136,136,136}
\pgfplotsset{paper/.style={
 font=\small, tick label style={font=\scriptsize},
 label style={font=\small}, title style={font=\small,at={(0,1.04)},anchor=south west},
 axis lines=left, axis line style={line width=.45pt,-},
 tick style={line width=.4pt}, tick align=outside,
 major tick length=2pt, grid=major, grid style={gray!15,line width=.25pt},
 scaled ticks=false, ylabel={Time (ms)},
 legend style={draw=none,fill=none,font=\scriptsize,cells={anchor=west}},
 /pgf/number format/1000 sep={},
},
barlabel/.style={nodes near coords,
 every node near coord/.append style={font=\scriptsize,yshift=5pt,text=black},
 nodes near coords={\pgfmathprintnumber[fixed,precision=1]{\pgfplotspointmeta}}},
err/.style={error bars/y dir=both,error bars/y explicit,
 error bars/error bar style={black,line width=.5pt},error bars/error mark options={rotate=90,mark size=2pt,line width=.5pt}}
}
\begin{document}
\begin{tikzpicture}
"""
END="\\end{tikzpicture}\n\\end{document}\n"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def dat(folder,name,rows):
    p=folder/"data"/(name+".dat")
    p.parent.mkdir(parents=True,exist_ok=True)
    lines=["x median minus plus"]
    for x,r in rows:
        minus=r["median"]-r["low"];plus=r["high"]-r["median"]
        if minus<0 or plus<0 or r["low"]<=0:
            raise ValueError("Invalid positive median interval")
        lines.append(f"{x:.12g} {r['median']:.12g} {minus:.12g} {plus:.12g}")
    p.write_text("\n".join(lines)+"\n",encoding="utf-8",newline="\n")
    return "data/"+p.name


def plot_table(path,style):
    return (r"\addplot+["+style+r"] table[x=x,y=median,y error minus=minus,y error plus=plus] {"+path+"};\n")


def bars(folder,name,rows,core=False):
    text=""
    for k,r in enumerate(rows):
        color=COLORS[r["scheme"]]
        style=f"ybar,mark=none,color={color},bar width=15pt,bar shift=0pt,fill={color}!85,draw={color},line width=.5pt,barlabel,err"
        if core and r["scheme"]=="CY22":
            style+=r",fill=cy!15,postaction={pattern=north east lines,pattern color=cy}"
        text+=plot_table(dat(folder,f"{name}_{r['scheme']}",[(k+1,r)]),style)
    return text


def write_tex(folder,name,body):
    (folder/(name+".tex")).write_text(PREAMBLE+body+END,encoding="utf-8",newline="\n")


def render(folder,revision):
    engine=shutil.which("xelatex")
    if not engine:
        raise RuntimeError("XeLaTeX is missing; TeX sources remain available")
    version=subprocess.check_output([engine,"--version"],text=True,errors="replace")
    files=sorted(folder.glob("figure_*.tex"));qa=[]
    import fitz
    for p in files:
        cmd=[engine,"-interaction=nonstopmode","-halt-on-error","-no-shell-escape"]
        if "MiKTeX" in version:
            cmd.append("-disable-installer")
        proc=subprocess.run(cmd+[p.name],cwd=folder,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors="replace")
        (folder/(p.stem+".compile.txt")).write_text(proc.stdout,encoding="utf-8")
        if proc.returncode:
            raise RuntimeError(proc.stdout[-5000:])
        pdf=folder/(p.stem+".pdf")
        doc=fitz.open(pdf);page=doc[0]
        if len(doc)!=1 or len(page.get_text().strip())<20:
            raise ValueError("Blank or unselectable PDF text")
        pix=page.get_pixmap(dpi=300,alpha=False)
        pix.save(folder/(p.stem+"-"+revision+".png"))
        pix.save(folder/(p.stem+".png"))
        qa.append(dict(figure=p.stem,width_mm=page.rect.width*25.4/72,height_mm=page.rect.height*25.4/72,
                       selectable_text=True,pdf_sha256=sha(pdf)))
        doc.close()
    (folder/"render_audit.json").write_text(json.dumps(dict(engine=version.splitlines()[0],renderer="XeLaTeX/PGFPlots",figures=qa),indent=2),encoding="utf-8")
    return qa


