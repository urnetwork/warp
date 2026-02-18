package warp

import (
	"log"
	"os"
)

var Out *log.Logger
var Err *log.Logger

func init() {
	Out = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
	Err = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Lshortfile)
}
