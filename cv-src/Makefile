LATEX := pdflatex
SOURCE := cv.tex
OUTPUT := cv.pdf

.PHONY: all clean
.DELETE_ON_ERROR:

all: $(OUTPUT)

$(OUTPUT): $(SOURCE)
	$(LATEX) -interaction=nonstopmode -halt-on-error -jobname=cv $(SOURCE)
	$(LATEX) -interaction=nonstopmode -halt-on-error -jobname=cv $(SOURCE)

clean:
	$(RM) cv.aux cv.log cv.out cv.fls cv.fdb_latexmk cv.synctex.gz
