package dbg

import (
	"log"
)

type Debugger bool

func Debug(format string, args ...interface{}) {
	if dbg {
		log.Printf("[DEBUG] "+format, args...)
	}
}

var dbg Debugger = true

func Set(enable Debugger) {
	dbg = enable
}
