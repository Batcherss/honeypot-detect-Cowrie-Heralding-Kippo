package modules

import (
	"fmt"
	"net"
	"time"
)

func CheckDelay(target string) (float64, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 4*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	delay := time.Since(start)
	return float64(delay.Microseconds()) / 1000.0, nil 
}

func RunDelayCheck(target string) (string, float64) {
	delay, err := CheckDelay(target)
	if err != nil {
		return fmt.Sprintf("❌ Connection error: %v", err), 0
	}

	switch {
	case delay > 1000:
		return fmt.Sprintf("🚨 HIGH delay: %.2f ms (possible sandbox/honeypot)", delay), 100
	case delay > 700:
		return fmt.Sprintf("⚠️ Suspicious delay: %.2f ms", delay), 75
	case delay > 500:
		return fmt.Sprintf("⚠️ Slightly high delay: %.2f ms", delay), 50
	case delay > 250:
		return fmt.Sprintf("📶 Normal delay: %.2f ms", delay), 25
	default:
		return fmt.Sprintf("📶 Fast response: %.2f ms", delay), 10
	}
}
