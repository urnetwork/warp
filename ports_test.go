package warp

import (
	"slices"
	"testing"

	"github.com/go-playground/assert/v2"
)

func TestExpandPorts(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"single port", "80", []int{80}},
		{"two ports", "80,443", []int{80, 443}},
		{"range", "7000-7003", []int{7000, 7001, 7002, 7003}},
		{"range single", "80-80", []int{80}},
		{"mixed", "80,7000-7002,443", []int{80, 7000, 7001, 7002, 443}},
		{"whitespace", " 80 , 443 ", []int{80, 443}},
		{"multi range", "7000-7002,7443-7445", []int{7000, 7001, 7002, 7443, 7444, 7445}},
	}
	for _, tt := range tests {
		got, err := ExpandPorts(tt.input)
		assert.Equal(t, err, nil)
		assert.Equal(t, slices.Equal(got, tt.want), true)
	}
}

func TestExpandPortsError(t *testing.T) {
	badInputs := []string{"abc", "80-", "-80", "80+5"}
	for _, input := range badInputs {
		_, err := ExpandPorts(input)
		assert.NotEqual(t, err, nil)
	}
}

func TestExpandAnyPorts(t *testing.T) {
	got, err := ExpandAnyPorts("7000-7002,80")
	assert.Equal(t, err, nil)
	assert.Equal(t, slices.Equal(got, []int{7000, 7001, 7002, 80}), true)

	got, err = ExpandAnyPorts(443)
	assert.Equal(t, err, nil)
	assert.Equal(t, slices.Equal(got, []int{443}), true)

	_, err = ExpandAnyPorts(3.14)
	assert.NotEqual(t, err, nil)
}

func TestExpandPortConfigPorts(t *testing.T) {
	tests := []struct {
		name  string
		specs []string
		want  []int
	}{
		{"single", []string{"80"}, []int{80}},
		{"plus notation", []string{"5080+3"}, []int{5080, 5081, 5082, 5083}},
		{"plus zero", []string{"80+0"}, []int{80}},
		{"range", []string{"100-103"}, []int{100, 101, 102, 103}},
		{"mixed", []string{"80", "5080+2", "100-101"}, []int{80, 5080, 5081, 5082, 100, 101}},
		{"dedup", []string{"80", "80"}, []int{80}},
		{"dedup across types", []string{"80", "79-81"}, []int{80, 79, 81}},
	}
	for _, tt := range tests {
		got := ExpandPortConfigPorts(tt.specs...)
		assert.Equal(t, slices.Equal(got, tt.want), true)
	}
}

func TestExpandPortConfigPortsPanic(t *testing.T) {
	defer func() {
		assert.NotEqual(t, recover(), nil)
	}()
	ExpandPortConfigPorts("not_a_port")
}
