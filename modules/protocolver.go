package modules

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand" 
	"net"
	"strings"
	"time"
)

func CheckProtocolVersion(target string) (string, float64) {
	time.Sleep(getRandomDelay4(1000, 3000)) 

	conn, err := net.DialTimeout("tcp", target, time.Duration(2+mrand.Intn(3))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection failed: %v", err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(4 * time.Second))
	
	clientVersions := []string{
		"SSH-1.99-OpenSSH_7.4p1",
		"SSH-1.99-Next-1.02",
		"SSH-1.99-ProSSH_0.22",
	}
	version := clientVersions[mrand.Intn(len(clientVersions))]
	conn.Write([]byte(version + "\r\n"))
	
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Timeout (normal behavior)", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}
	
	response := strings.TrimSpace(string(buf[:n]))
	honeypotIndicators := []struct {
		pattern    string
		confidence int
		message    string
	}{
		{"SSH-1.99", 100, "🚨 Accepts legacy version (Honeypot!)"},
		{"Protocol mismatch", 20, "✅ Normal: Protocol mismatch"},
		{"Invalid protocol", 20, "✅ Normal: Invalid protocol"},
		{"cowrie", 99, "☣️ Cowrie honeypot detected"},
		{"kippo", 99, "☣️ Kippo honeypot detected"},
		{"libssh", 90, "☣️ libssh honeypot detected"},
		{"OpenSSH_5.", 40, "⚠️ Old OpenSSH version"},
		{"banner", 50, "⚠️ Suspicious banner response"},
		{"bad packet length", 85, "☣️ Honeypot bad packet length error"},
		{"authentication failed", 75, "☣️ Authentication failure (possible honeypot)"},
		{"invalid command", 95, "☣️ Honeypot shell-like invalid command response"},
		{"command not found", 95, "☣️ Honeypot shell-like command not found"},
		{"protocol error", 80, "☣️ Protocol error - suspicious"},
		{"connection closed by remote host", 60, "⚠️ Connection closed abruptly"},
		{"warning: possible honeypot", 100, "🚨 Explicit honeypot warning detected"},
		{"sshguard", 90, "☣️ SSHGuard protection detected"},
		{"failed password", 70, "☣️ Failed password attempts logged"},
		{"sshscan", 90, "☣️ SSHScan tool detected (likely honeypot)"},
		{"tcpwrapped", 80, "⚠️ TCP Wrapped - often used in honeypots"},
		{"proxy", 50, "⚠️ Proxy detected (could be honeypot)"},
	}

	for _, indicator := range honeypotIndicators {
		if strings.Contains(response, indicator.pattern) {
			return fmt.Sprintf("%s: %s", indicator.message, response), float64(indicator.confidence)
		}
	}

	switch {
	case strings.Contains(response, "SSH-2.0"):
		return "✅ SSH-2.0 only (Normal)", 10
	case n == 0:
		return "✅ No response (Normal)", 10
	default:
		return fmt.Sprintf("⚠️ Unknown response: %s", response), 30
	}
}

func getRandomDelay4(min, max int) time.Duration {
	randNum, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		return time.Duration(min) * time.Millisecond
	}
	return time.Duration(min+int(randNum.Int64())) * time.Millisecond
}
