// Package rollout, OTA güncellemelerinin kademeli (canary) dağıtımını sağlar:
// bir cihazın belirli bir sürümün rollout kohortunda olup olmadığını
// DETERMİNİSTİK olarak belirler. Aynı cihaz+sürüm için sonuç sabittir; böylece
// yüzde artırıldıkça kohort yalnız BÜYÜR, cihazlar in/out arasında zıplamaz.
package rollout

import "hash/fnv"

// Bucket, cihaz+sürüm için 0..99 arası deterministik bir kova döner.
func Bucket(deviceID, version string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(deviceID))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(version))
	return int(h.Sum32() % 100)
}

// InCohort, cihazın verilen yüzdelik rollout kohortunda olup olmadığını döner.
// percent <= 0 → hiç kimse; percent >= 100 → herkes.
func InCohort(deviceID, version string, percent int) bool {
	if percent <= 0 {
		return false
	}
	if percent >= 100 {
		return true
	}
	return Bucket(deviceID, version) < percent
}
