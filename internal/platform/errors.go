package platform

import "errors"

var ErrReparse = errors.New("reparse paths are unsupported")
var ErrNonlocal = errors.New("non-local or indirect volume mapping unsupported")
