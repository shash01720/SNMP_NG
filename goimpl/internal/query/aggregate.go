// Package query implements Query's recurring collection/aggregation/
// transfer pipeline (see node.asn's Query docs).
package query

import (
	"fmt"
	"math"
	"sort"

	"github.com/shashi/snmp-ng/goimpl/internal/wire"
)

// Aggregate reduces `samples` (all numeric, all the same kind by
// convention -- see collector.go, which only ever aggregates same-key
// samples) via `method`, returning a wire.RealValue. The result is always
// `real`, even when the source samples were integers, since e.g. a mean or
// percentile is inherently fractional (see node.asn's NodeValue docs on
// why `real` exists).
func Aggregate(method wire.AggregationMethod, samples []wire.NodeValue) (wire.NodeValue, error) {
	if len(samples) == 0 {
		return wire.NodeValue{}, fmt.Errorf("no samples to aggregate")
	}
	values := make([]float64, 0, len(samples))
	for _, s := range samples {
		if !s.Kind.IsNumeric() {
			return wire.NodeValue{}, fmt.Errorf("aggregation requires numeric values, got kind %d", s.Kind)
		}
		values = append(values, s.AsFloat64())
	}

	switch method.Kind {
	case wire.AggMin:
		return wire.RealValue(minOf(values)), nil
	case wire.AggMax:
		return wire.RealValue(maxOf(values)), nil
	case wire.AggMean:
		return wire.RealValue(mean(values)), nil
	case wire.AggStdDev:
		return wire.RealValue(stdDev(values)), nil
	case wire.AggPercentile:
		return wire.RealValue(percentile(values, float64(method.Percentile))), nil
	default:
		return wire.NodeValue{}, fmt.Errorf("unknown aggregation method kind %d", method.Kind)
	}
}

func minOf(v []float64) float64 {
	m := v[0]
	for _, x := range v[1:] {
		if x < m {
			m = x
		}
	}
	return m
}

func maxOf(v []float64) float64 {
	m := v[0]
	for _, x := range v[1:] {
		if x > m {
			m = x
		}
	}
	return m
}

func mean(v []float64) float64 {
	sum := 0.0
	for _, x := range v {
		sum += x
	}
	return sum / float64(len(v))
}

func stdDev(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	m := mean(v)
	sumSq := 0.0
	for _, x := range v {
		d := x - m
		sumSq += d * d
	}
	// Population standard deviation (divide by N, not N-1): a Query's
	// samples are the complete population being observed over that
	// window, not a sample drawn from a larger population.
	return math.Sqrt(sumSq / float64(len(v)))
}

// percentile uses linear interpolation between closest ranks (the same
// method as, e.g., NumPy's default and Excel's PERCENTILE.INC).
func percentile(v []float64, p float64) float64 {
	sorted := append([]float64(nil), v...)
	sort.Float64s(sorted)
	if len(sorted) == 1 {
		return sorted[0]
	}
	rank := (p / 100) * float64(len(sorted)-1)
	lo := int(math.Floor(rank))
	hi := int(math.Ceil(rank))
	if lo == hi {
		return sorted[lo]
	}
	frac := rank - float64(lo)
	return sorted[lo] + frac*(sorted[hi]-sorted[lo])
}
