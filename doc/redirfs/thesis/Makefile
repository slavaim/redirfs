all: thesis.ps
	gv thesis.ps

thesis.pdf: thesis.tex
	pdflatex thesis.tex
	pdflatex thesis.tex

thesis.ps: thesis.dvi
	dvips thesis.dvi -o thesis.ps

thesis.dvi: thesis.tex
	latex thesis.tex
	latex thesis.tex

clean:
	rm -f *~ *.dvi *.aux *.log *.toc *.bak *.lof
	rm -f thesis.ps thesis.pdf

