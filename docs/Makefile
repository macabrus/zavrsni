
# Izrada završnog rada

all:
	mkdir -p out/
	#cp *.tex out/
	#cp *.bst out/
	#cp *.cls out/
	#cp *.bib out/
	#cp *.tex out/
	#pdflatex --shell-escape --output-directory=./out zavrsni.tex
	latexmk -shell-escape -auxdir=./out -outdir=./out -pdf -pvc zavrsni.tex 

clean:
	rm -rf out/
