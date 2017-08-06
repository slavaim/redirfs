all: redirfs.ps redirfs.pdf

redirfs.ps: redirfs.dvi
	dvips redirfs.dvi -o redirfs.ps

redirfs.pdf: redirfs.dvi
	dvipdf redirfs.dvi redirfs.pdf

redirfs.dvi: redirfs.tex
	latex redirfs.tex
	latex redirfs.tex

.PHONY: clean

clean:
	rm -f *~ *.dvi *.aux *.log *.toc *.bak redirfs.ps redirfs.pdf
