package Log

import (
	"log"
	"runtime"
)

// Err logs an error during runtime for better visibility in developer mode.
// It returns true if an error occurred, or false otherwise.
func Err(err error) (ok bool) {
	if err != nil {
		pc, filename, line, _ := runtime.Caller(1)
		log.Printf("[Error] in %s [%s:%d] || Error: %v \n", runtime.FuncForPC(pc).Name(), filename, line, err)
		ok = true
		return
	}
	return
}
