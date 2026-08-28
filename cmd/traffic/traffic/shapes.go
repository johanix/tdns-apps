package traffic

import (
	"fmt"
	"math"
	"strings"
)

// ShapeFunc maps a normalized time t (0.0 to 1.0) to a normalized QPS
// fraction (0.0 to 1.0). The actual QPS is fraction * maxQPS.
type ShapeFunc func(t float64) float64

// ShapeEntry holds a shape function and its description.
type ShapeEntry struct {
	Fn   ShapeFunc
	Desc string
}

// shapeRegistry maps shape names to their implementations.
var shapeRegistry = map[string]ShapeEntry{
	"sawtooth-up": {
		Fn:   func(t float64) float64 { return t },
		Desc: "Linear rise, vertical drop",
	},
	"sawtooth-down": {
		Fn:   func(t float64) float64 { return 1 - t },
		Desc: "Vertical rise, linear drop",
	},
	"triangle": {
		Fn:   func(t float64) float64 { return 1 - math.Abs(2*t-1) },
		Desc: "Linear rise then linear drop (symmetric triangle)",
	},
	"trapezoid": {
		Fn:   trapezoid,
		Desc: "Rise, sustain at max, drop (classic ramp-up/sustain/ramp-down)",
	},
	"bowl": {
		Fn:   func(t float64) float64 { return (2*t - 1) * (2*t - 1) },
		Desc: "Parabolic bowl: high at edges, low in middle",
	},
	"arch": {
		Fn:   func(t float64) float64 { return 1 - (2*t-1)*(2*t-1) },
		Desc: "Parabolic arch: low at edges, high in middle",
	},
	"sine": {
		Fn:   func(t float64) float64 { return (1 + math.Sin(2*math.Pi*t-math.Pi/2)) / 2 },
		Desc: "Smooth sine wave (one full cycle)",
	},
}

// trapezoid implements the classic ramp-up / sustain / ramp-down shape.
// The cycle is divided into thirds: ramp-up, sustain, ramp-down.
func trapezoid(t float64) float64 {
	switch {
	case t < 1.0/3.0:
		return t * 3.0 // ramp up
	case t < 2.0/3.0:
		return 1.0 // sustain
	default:
		return (1.0 - t) * 3.0 // ramp down
	}
}

// PeaksShape returns a shape function that produces n parabolic peaks
// per cycle. Each peak is an arch (inverted parabola) within its segment.
func PeaksShape(n int) ShapeFunc {
	if n < 1 {
		n = 1
	}
	return func(t float64) float64 {
		// sin²(nπt) gives n smooth peaks across [0,1]
		s := math.Sin(float64(n) * math.Pi * t)
		return s * s
	}
}

// GetShape looks up a shape by name. For "peaks", use GetPeaksShape instead.
func GetShape(name string) (ShapeFunc, error) {
	entry, ok := shapeRegistry[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown shape %q — available: %s",
			name, AvailableShapes())
	}
	return entry.Fn, nil
}

// AvailableShapes returns a comma-separated list of shape names.
func AvailableShapes() string {
	names := make([]string, 0, len(shapeRegistry))
	for name := range shapeRegistry {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}

// ListShapes returns a formatted multi-line description of all shapes.
func ListShapes() string {
	var sb strings.Builder
	for name, entry := range shapeRegistry {
		fmt.Fprintf(&sb, "  %-15s %s\n", name, entry.Desc)
	}
	fmt.Fprintf(&sb, "  %-15s %s\n", "peaks", "Repeated parabolic peaks (use --peaks N)")
	return sb.String()
}
