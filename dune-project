(lang dune 2.5)
(name ecec)
(version 0.1)
(source (github roddyyaga/pg_query-ocaml))
(documentation "https://roddyyaga.github.io/pg_query-ocaml/pg_query-ocaml/index.html")
(license MIT)
(authors "Roddy MacSween <github@roddymacsween.co.uk>")
(maintainers "Roddy MacSween <github@roddymacsween.co.uk>")
(generate_opam_files true)
(package
(name ecec)
(synopsis "")
(description "")
(depends
(ocaml (>= 4.07))
(dune (>= 2.0))
core
ctypes
ctypes-foreign
)
)
