/* Synthetic ELF dependency graph, not a donor graphics library. */
#ifdef R800_NAMESPACE_LEAF
int r800_namespace_leaf(void) { return 0x800; }
#elif defined(R800_NAMESPACE_BAD_SYMBOL)
/* Intentionally unresolved strong import, only in the negative fixture. */
extern int r800_namespace_missing_symbol(void);
int r800_namespace_bad(void) { return r800_namespace_missing_symbol(); }
#else
extern int r800_namespace_leaf(void);
int r800_namespace_parent(void) { return r800_namespace_leaf()+0x27; }
#endif
