package warp

import (
	"fmt"
	"strconv"
	"strings"
)

const Kib = int64(1024)
const Mib = int64(1024 * 1024)
const Gib = int64(1024 * 1024 * 1024)

func ByteCountHumanReadable(count int64) string {
	trimFloatString := func(value float64, precision int, suffix string) string {
		s := fmt.Sprintf("%."+strconv.Itoa(precision)+"f", value)
		s = strings.TrimRight(s, "0")
		s = strings.TrimRight(s, ".")
		return s + suffix
	}

	if 1024*1024*1024*1024 <= count {
		return trimFloatString(
			float64(1000*count/(1024*1024*1024*1024))/1000.0,
			2,
			"tib",
		)
	} else if 1024*1024*1024 <= count {
		return trimFloatString(
			float64(1000*count/(1024*1024*1024))/1000.0,
			2,
			"gib",
		)
	} else if 1024*1024 <= count {
		return trimFloatString(
			float64(1000*count/(1024*1024))/1000.0,
			2,
			"mib",
		)
	} else if 1024 <= count {
		return trimFloatString(
			float64(1000*count/(1024))/1000.0,
			2,
			"kib",
		)
	} else {
		return fmt.Sprintf("%db", count)
	}
}

func ParseByteCount(humanReadable string) (int64, error) {
	humanReadableLower := strings.ToLower(humanReadable)
	tibLower := "tib"
	gibLower := "gib"
	mibLower := "mib"
	kibLower := "kib"
	bLower := "b"
	if strings.HasSuffix(humanReadableLower, tibLower) {
		countFloat, err := strconv.ParseFloat(
			humanReadableLower[0:len(humanReadableLower)-len(tibLower)],
			64,
		)
		if err != nil {
			return int64(0), err
		}
		return int64(countFloat * 1024 * 1024 * 1024 * 1024), nil
	} else if strings.HasSuffix(humanReadableLower, gibLower) {
		countFloat, err := strconv.ParseFloat(
			humanReadableLower[0:len(humanReadableLower)-len(gibLower)],
			64,
		)
		if err != nil {
			return int64(0), err
		}
		return int64(countFloat * 1024 * 1024 * 1024), nil
	} else if strings.HasSuffix(humanReadableLower, mibLower) {
		countFloat, err := strconv.ParseFloat(
			humanReadableLower[0:len(humanReadableLower)-len(mibLower)],
			64,
		)
		if err != nil {
			return int64(0), err
		}
		return int64(countFloat * 1024 * 1024), nil
	} else if strings.HasSuffix(humanReadableLower, kibLower) {
		countFloat, err := strconv.ParseFloat(
			humanReadableLower[0:len(humanReadableLower)-len(kibLower)],
			64,
		)
		if err != nil {
			return int64(0), err
		}
		return int64(countFloat * 1024), nil
	} else if strings.HasSuffix(humanReadableLower, bLower) {
		countFloat, err := strconv.ParseFloat(
			humanReadableLower[0:len(humanReadableLower)-len(bLower)],
			64,
		)
		if err != nil {
			return int64(0), err
		}
		return int64(countFloat), nil
	} else {
		countInt, err := strconv.ParseInt(humanReadableLower, 10, 63)
		if err != nil {
			return int64(0), err
		}
		return int64(countInt), nil
	}
}
