package easyfl

import "fmt"

// GlobalDataNoTrace does not trace
type GlobalDataNoTrace struct {
	glb interface{}
}

func NewGlobalDataNoTrace(glb interface{}) *GlobalDataNoTrace {
	return &GlobalDataNoTrace{glb}
}

func (t *GlobalDataNoTrace) Data() interface{} {
	return t.glb
}

func (t *GlobalDataNoTrace) Trace() bool {
	return false
}

func (t *GlobalDataNoTrace) PutTrace(s string) {
	panic("inconsistency: PutTrace should not be called for GlobalDataNoTrace")
}

// GlobalDataLog saves trace into the log
type GlobalDataLog struct {
	glb interface{}
	log []string
}

func NewGlobalDataLog(glb interface{}) *GlobalDataLog {
	return &GlobalDataLog{
		glb: glb,
		log: make([]string, 0),
	}
}

func (t *GlobalDataLog) Data() interface{} {
	return t.glb
}

func (t *GlobalDataLog) Trace() bool {
	return true
}

func (t *GlobalDataLog) PutTrace(s string) {
	t.log = append(t.log, s)
}

func (t *GlobalDataLog) PrintLog() {
	fmt.Printf("--- trace begin ---\n")
	for i, s := range t.log {
		fmt.Printf("%d: %s\n", i, s)
	}
	fmt.Printf("--- trace end ---\n")
}

// GlobalDataTracePrint just prints all trace messages
type GlobalDataTracePrint struct {
	glb interface{}
}

func NewGlobalDataTracePrint(glb interface{}) *GlobalDataTracePrint {
	return &GlobalDataTracePrint{
		glb: glb,
	}
}

func (t *GlobalDataTracePrint) Data() interface{} {
	return t.glb
}

func (t *GlobalDataTracePrint) Trace() bool {
	return true
}

func (t *GlobalDataTracePrint) PutTrace(s string) {
	fmt.Printf("%s\n", s)
}
