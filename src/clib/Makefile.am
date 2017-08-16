libppppcapdir=.
libppppcap_a_SOURCES = \
	pcap.c
libppppcap_a_CFLAGS = \
	-I$(shell $(OCAMLC) -where)

noinst_LIBRARIES = libppppcap.a
noinst_DATA = pcap.cmxa

SOURCES_ML=\
	pcap.ml

OBJECT_ML=\
	pcap.cmx

pcap.cmxa:$(SOURCES_ML) libppppcap.a
	ocamlfind $(OCAMLC) $(OCAMLFLAGS) -c $(SOURCES_ML)
	ocamlfind mklib $(OBJECT_ML) -cclib -lpcap -cclib -lppppcap -o pcap


clean-local:
	rm *.cm*
