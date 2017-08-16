AC_CHECK_TOOL([OCAMLCDOTOPT],[ocamlc.opt],[no])
if test "$OCAMLCDOTOPT" != "no"; then
   OCAMLC=ocamlopt
fi
AC_SUBST(OCAMLC)




OCAMLFLAGS=-bin-annot
AC_SUBST(OCAMLFLAGS)
