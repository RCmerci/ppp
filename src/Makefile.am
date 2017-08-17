SUBDIRS=clib
SUBDIRS+=parser

OCAMLPACKAGES = \
	-package unix,cstruct \
	-I $(top_builddir)/src/clib \
	-I $(top_builddir)/src/parser


OCAMLLINKFLAGS = \
	-linkpkg \
	pcap.cmxa \
	parser.cmx

all: main.ml
	ocamlfind $(OCAMLC) $(OCAMLFLAGS) $(OCAMLPACKAGES) $(OCAMLLINKFLAGS) \
	main.ml -o main

tmp.cmx: tmp.ml
	ocamlfind $(OCAMLC) -c $(OCAMLFLAGS) $(OCAMLPACKAGES) $(OCAMLLINKFLAGS) \
	tmp.mli
	ocamlfind $(OCAMLC) -c $(OCAMLFLAGS) $(OCAMLPACKAGES) $(OCAMLLINKFLAGS) \
	tmp.ml

clean-local:
	rm *.cm*
