package rollout

import (
	"fmt"
	"testing"
)

func TestBoundaries(t *testing.T) {
	if InCohort("dev-1", "1.0.0", 0) {
		t.Error("percent 0'da kimse kohortta olmamalı")
	}
	if !InCohort("dev-1", "1.0.0", 100) {
		t.Error("percent 100'de herkes kohortta olmalı")
	}
}

func TestDeterministic(t *testing.T) {
	a := InCohort("dev-42", "2.0.0", 50)
	for i := 0; i < 100; i++ {
		if InCohort("dev-42", "2.0.0", 50) != a {
			t.Fatal("aynı girdi için sonuç değişti (deterministik olmalı)")
		}
	}
}

func TestMonotonicWithPercent(t *testing.T) {
	// Yüzde arttıkça kohort yalnız büyümeli: bir cihaz %30'da içindeyse %60'ta da içinde.
	for i := 0; i < 500; i++ {
		id := fmt.Sprintf("dev-%d", i)
		if InCohort(id, "v", 30) && !InCohort(id, "v", 60) {
			t.Fatalf("%s %%30'da içindeyken %%60'ta dışında (monoton değil)", id)
		}
	}
}

func TestApproximateDistribution(t *testing.T) {
	const n = 10000
	const percent = 30
	in := 0
	for i := 0; i < n; i++ {
		if InCohort(fmt.Sprintf("device-%d", i), "1.4.0", percent) {
			in++
		}
	}
	ratio := float64(in) / float64(n) * 100
	if ratio < 26 || ratio > 34 { // ~%30 ± tolerans
		t.Fatalf("dağılım ~%%%d olmalıydı, %%%.1f", percent, ratio)
	}
}
