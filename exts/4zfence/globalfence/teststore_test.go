package globalfence

// testStore is the one store the package's function-level tests read and
// write. In production the owner is the fence extension, which creates its
// own store at Load (docs/19 E3-4); a test that needs isolation swaps in a
// fresh one (drainSessionStore).
var testStore = NewStore()
