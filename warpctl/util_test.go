package main

import (
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestByteCount(t *testing.T) {
	assert.Equal(t, ByteCountHumanReadable(ByteCount(0)), "0b")
	assert.Equal(t, ByteCountHumanReadable(ByteCount(5*1024*1024*1024*1024)), "5tib")

	count, err := ParseByteCount("2")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(2))
	assert.Equal(t, ByteCountHumanReadable(count), "2b")

	count, err = ParseByteCount("5B")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(5))
	assert.Equal(t, ByteCountHumanReadable(count), "5b")

	count, err = ParseByteCount("123KiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(123*1024))
	assert.Equal(t, ByteCountHumanReadable(count), "123kib")

	count, err = ParseByteCount("5MiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(5*1024*1024))
	assert.Equal(t, ByteCountHumanReadable(count), "5mib")

	count, err = ParseByteCount("1.7GiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(17*1024*1024*1024)/ByteCount(10))
	assert.Equal(t, ByteCountHumanReadable(count), "1.7gib")

	count, err = ParseByteCount("13.1TiB")
	assert.Equal(t, err, nil)
	assert.Equal(t, count, ByteCount(131*1024*1024*1024*1024)/ByteCount(10))
	assert.Equal(t, ByteCountHumanReadable(count), "13.1tib")
}
