package easyfl

import "fmt"

// GlobalDataNoTrace does not trace
type GlobalDataNoTrace[T any] struct {
	glb T
	lib *Library[T]
}

func (lib *Library[T]) NewGlobalDataNoTrace(glb T) *GlobalDataNoTrace[T] {
	return &GlobalDataNoTrace[T]{lib: lib, glb: glb}
}

func (t *GlobalDataNoTrace[T]) Data() T {
	return t.glb
}

func (t *GlobalDataNoTrace[T]) Trace() bool {
	return false
}

func (t *GlobalDataNoTrace[T]) PutTrace(s string) {
	panic("inconsistency: PutTrace should not be called for GlobalDataNoTrace")
}

func (t *GlobalDataNoTrace[T]) Library() *Library[T] {
	return t.lib
}

// GlobalDataLog saves trace into the log
type GlobalDataLog[T any] struct {
	glb T
	lib *Library[T]
	log []string
}

func (lib *Library[T]) NewGlobalDataLog(glb T) *GlobalDataLog[T] {
	return &GlobalDataLog[T]{
		glb: glb,
		lib: lib,
		log: make([]string, 0),
	}
}

func (t *GlobalDataLog[T]) Data() T {
	return t.glb
}

func (t *GlobalDataLog[T]) Trace() bool {
	return true
}

func (t *GlobalDataLog[T]) PutTrace(s string) {
	t.log = append(t.log, s)
}

func (t *GlobalDataLog[T]) Library() *Library[T] {
	return t.lib
}

func (t *GlobalDataLog[T]) PrintLog() {
	fmt.Printf("--- trace begin ---\n")
	for i, s := range t.log {
		fmt.Printf("%d: %s\n", i, s)
	}
	fmt.Printf("--- trace end ---\n")
}

// GlobalDataTracePrint just prints all trace messages
type GlobalDataTracePrint[T any] struct {
	glb T
	lib *Library[T]
}

func (lib *Library[T]) NewGlobalDataTracePrint(glb T) *GlobalDataTracePrint[T] {
	return &GlobalDataTracePrint[T]{
		glb: glb,
		lib: lib,
	}
}

func (t *GlobalDataTracePrint[T]) Data() T {
	return t.glb
}

func (t *GlobalDataTracePrint[T]) Trace() bool {
	return true
}

func (t *GlobalDataTracePrint[T]) PutTrace(s string) {
	fmt.Printf("%s\n", s)
}

func (t *GlobalDataTracePrint[T]) Library() *Library[T] {
	return t.lib
}
