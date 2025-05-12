package modules

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

var trashPayloads = [][]byte{
	[]byte("SSH-2.0-INVALID\x00\x00\x00\x02\x0A"),
	[]byte("\x00\x00\x00\x14\x06INVALID\x00\x00\x00\x00"),
	[]byte("SSH-1.99-CUSTOM\x01\x02\x03\x04"),
	[]byte("SSH-3.0-HACKNET\r\n"),
	[]byte("HELP\r\n"),
	[]byte("LOGIN root toor\r\n"),
	[]byte("SSH-1.5-0p5\x01\x01\x01"),
	[]byte("\xDE\xAD\xBE\xEF\x00\x00\x00\x01"),
	[]byte("\x00\x00\x00\x05\x15\x01\x02\x03\x04"),
	[]byte("{\"version\":\"SSH-2.0\",\"os\":\"Linux\"}\r\n"),
	[]byte("SSH-2.0-" + strings.Repeat("G", 1000)), 
}

func CheckTrash(target string) (string, float64) {
	time.Sleep(time.Duration(500+rand.Intn(1500)) * time.Millisecond)

	conn, err := net.DialTimeout("tcp", target, time.Duration(3+rand.Intn(3))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ [%s] Connection error: %v", target, err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var highestScore float64
	var finalMessage string

	for _, payload := range trashPayloads {
		start := time.Now()
		_, err = conn.Write(payload)
		if err != nil {
			continue 
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		duration := time.Since(start).Milliseconds()

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue 
			}
			continue
		}

		resp := strings.TrimSpace(string(buf[:n]))
		score, msg := analyzeResponse(resp, duration)
		if score > highestScore {
			highestScore = score
			finalMessage = msg
		}
	}

	if highestScore == 0 {
		return fmt.Sprintf("✅ [%s] No significant response (likely real SSH)", target), 10
	}
	return fmt.Sprintf("🧪 [%s] %s", target, finalMessage), highestScore
}

func analyzeResponse(resp string, duration int64) (float64, string) {
	respLower := strings.ToLower(resp)

	switch {
	case strings.HasPrefix(resp, "SSH-2.0-"):
		if isKnownHoneypot(resp) {
			return 95, fmt.Sprintf("🚨 Known honeypot banner: %s", resp)
		}
		return 70, fmt.Sprintf("⚠️ Responded with SSH banner to junk: %s", resp)
	case strings.Contains(respLower, "protocol mismatch"):
		return 50, fmt.Sprintf("⚠️ Protocol mismatch: %s", resp)
	case strings.Contains(respLower, "invalid") || strings.Contains(respLower, "error"):
		return 60, fmt.Sprintf("⚠️ Error-like response: %s", resp)
	case len(resp) == 0 && duration < 150:
		return 80, "🚨 Silent response with suspicious speed (<150ms)"
	case len(resp) > 0:
		return 65, fmt.Sprintf("⚠️ Unexpected response: %s", resp)
	default:
		return 0, ""
	}
}

func isKnownHoneypot(banner string) bool {
	signatures := []string{
		"Cowrie", "HonSSH", "HoneyPy", "Kippo", "Dionaea",
		"Amun", "Glastopf", "Honeyd", "MHN", "T-Pot",
	}
	for _, sig := range signatures {
		if strings.Contains(banner, sig) {
			return true
		}
	}
	return false
}
