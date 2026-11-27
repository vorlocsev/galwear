/* Synthetic ELF dependency graph, not a donor graphics library. */
#ifdef R800_NAMESPACE_LEAF
int r800_namespace_leaf(void) { return 0x800; }
#else
extern int r800_namespace_leaf(void);
int r800_namespace_parent(void) { return r800_namespace_leaf()+0x27; }
#endif
