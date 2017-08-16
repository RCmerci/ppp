OCAMLPPX = \
	-package ppx_cstruct

OCAMLPACKAGES = \
	-package cstruct \
	-I $(top_builddir)/src/clib


OCAMLLINKFLAGS = \
	pcap.cmxa

noinst_DATA = parser.cmx 

parser.cmx: parser.ml parser.mli
	ocamlfind $(OCAMLC) $(OCAMLPACKAGES) -c  parser.mli
	ocamlfind $(OCAMLC) -dsource $(OCAMLFLAGS) $(OCAMLPPX) $(OCAMLPACKAGES) -c  parser.ml 2> parser_gen.ml


clean-local:
	-rm *.cm*
	-rm *.o
