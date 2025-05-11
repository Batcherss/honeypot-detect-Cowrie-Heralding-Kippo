package modules

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand" 
	"net"
	"strings"
	"time"
)

func CheckInvalidCommand(target string) (string, float64) {
	randomDelay := getRandomDelay3(500, 3000)
	time.Sleep(randomDelay)

	conn, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(4))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection error: %v", err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	commands := []string{
		"SSH-1.99-INVALID\x00\x00\x00\x02\x0A",
		"\x00\x00\x00\x14\x06INVALID\x00\x00\x00\x00",
		"SSH-2.0-CUSTOM\x01\x02\x03\x04",
	}
	cmdIndexBig, _ := crand.Int(crand.Reader, big.NewInt(int64(len(commands))))
	cmd := commands[cmdIndexBig.Int64()]
	_, err = conn.Write([]byte(cmd))
	if err != nil {
		return fmt.Sprintf("❌ Write error: %v", err), 0
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Timeout (normal behavior)", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}

	resp := strings.TrimSpace(string(buf[:n]))

	if len(resp) == 0 {
		return "✅ No response (normal)", 10
	}

	honeypotIndicators := []struct {
		pattern    string
		confidence int
	}{
		{"cowrie", 95},
		{"kippo", 95},
		{"honssh", 90},
		{"honeypot", 85},
		{"invalid protocol", 70},
		{"unrecognized", 60},
	}

	maxConfidence := 0
	var detectedPatterns []string

	for _, indicator := range honeypotIndicators {
		if strings.Contains(strings.ToLower(resp), strings.ToLower(indicator.pattern)) {
			if indicator.confidence > maxConfidence {
				maxConfidence = indicator.confidence
			}
			detectedPatterns = append(detectedPatterns, indicator.pattern)
		}
	}

	if maxConfidence > 0 {
		return fmt.Sprintf("🚨 Detected patterns (%v): %s", strings.Join(detectedPatterns, ", "), resp),
			float64(maxConfidence)
	}

	if len(resp) > 0 {
		return fmt.Sprintf("⚠️ Unexpected response: %s", resp), 40
	}

	return "✅ Normal behavior", 10
}

func getRandomDelay3(min, max int) time.Duration {
	randNum, _ := crand.Int(crand.Reader, big.NewInt(int64(max-min)))
	return time.Duration(min+int(randNum.Int64())) * time.Millisecond
}
