package modules

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"strings"
	"time"
)

func CheckNoneAuth(target string) (string, float64) {
	time.Sleep(getRandomDelay1(1000, 5000))

	conn, err := net.DialTimeout("tcp", target, time.Duration(3+mrand.Intn(4))*time.Second)
	if err != nil {
		return fmt.Sprintf("❌ Connection failed: %v", err), 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	serverBanner := make([]byte, 256)
	n, err := conn.Read(serverBanner)
	if err != nil || !bytes.HasPrefix(serverBanner, []byte("SSH-")) {
		return "❌ Invalid or no SSH banner received", 0
	}
	trimmedBanner := strings.TrimSpace(string(serverBanner[:n]))

	clientBanners := []string{
		"SSH-2.0-OpenSSH_8.9p1",
		"SSH-2.0-PuTTY_Release_0.76",
		"SSH-2.0-libssh-0.9.5",
	}
	banner := clientBanners[mrand.Intn(len(clientBanners))] + "\r\n"
	conn.Write([]byte(banner))

	time.Sleep(getRandomDelay1(200, 1000))

	username := randomUsername()
	usernameLen := len(username)

	packetLen := 1 + 4 + usernameLen // packet_type(1) + length(4) + username
	totalLen := packetLen + 4        // + length prefix
	packet := make([]byte, totalLen)

	packet[0] = byte((packetLen >> 24) & 0xFF)
	packet[1] = byte((packetLen >> 16) & 0xFF)
	packet[2] = byte((packetLen >> 8) & 0xFF)
	packet[3] = byte((packetLen) & 0xFF)

	packet[4] = 0x32 
	packet[5] = 0x00
	packet[6] = 0x00
	packet[7] = 0x00
	packet[8] = byte(usernameLen)

	copy(packet[9:], []byte(username))
	conn.Write(packet)

	start := time.Now()
	buf := make([]byte, 1024)
	n, err = conn.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "✅ Timeout (normal behavior)", 10
		}
		return fmt.Sprintf("✅ Connection closed (normal): %v", err), 10
	}

	response := buf[:n]

	honeypotIndicators := []struct {
		pattern    []byte
		confidence int
		message    string
	}{
		{[]byte{0x00, 0x00, 0x00, 0x34, 0x06}, 95, "🚨 Honeypot: Full protocol exchange"},
		{[]byte("cowrie"), 99, "☣️ Cowrie honeypot detected"},
		{[]byte("kippo"), 99, "☣️ Kippo honeypot detected"},
		{[]byte("honssh"), 98, "☣️ HonSSH honeypot detected"},
		{[]byte("honeypy"), 98, "☣️ HoneyPy honeypot detected"},
		{[]byte("dionaea"), 97, "☣️ Dionaea honeypot detected"},
		{[]byte("amun"), 96, "☣️ Amun honeypot detected"},
		{[]byte("glastopf"), 96, "☣️ Glastopf honeypot detected"},
		{[]byte("honeyd"), 95, "☣️ Honeyd honeypot detected"},
		{[]byte("mhn"), 94, "☣️ MHN honeypot detected"},
		{[]byte("t-pot"), 94, "☣️ T-Pot honeypot detected"},
		{[]byte("invalid"), 80, "⚠️ Unexpected: Invalid protocol response"},
		{[]byte("service not available"), 85, "⚠️ Suspicious: Service not available"},
		{[]byte("connection refused"), 70, "⚠️ Connection refused detected"},
		{[]byte("protocol mismatch"), 75, "⚠️ Protocol mismatch detected"},
		{[]byte("unknown service"), 75, "⚠️ Unknown service response"},
		{[]byte("authentication failed"), 80, "⚠️ Authentication failed suspicious"},
		{[]byte("banner"), 60, "⚠️ Suspicious banner response"},
		{[]byte("timeout"), 65, "⚠️ Timeout response"},
		{[]byte("access denied"), 85, "⚠️ Access denied suspicious"},
		{[]byte("connection reset"), 70, "⚠️ Connection reset suspicious"},
		{[]byte("reset by peer"), 70, "⚠️ Reset by peer suspicious"},
		{[]byte("no route to host"), 60, "⚠️ No route to host detected"},
		{[]byte("service temporarily unavailable"), 80, "⚠️ Service temporarily unavailable suspicious"},
		{[]byte("too many authentication failures"), 85, "⚠️ Too many authentication failures suspicious"},
		{[]byte("invalid user"), 80, "⚠️ Invalid user suspicious"},
	}

	for _, indicator := range honeypotIndicators {
		if bytes.Contains(response, indicator.pattern) {
			return fmt.Sprintf("%s (response: %x)", indicator.message, response), float64(indicator.confidence)
		}
	}

	switch {
	case n == 0:
		return "✅ No response (normal)", 5
	case response[0] == 0x05: 
		return "⚠️ Accepted 'none' auth (very suspicious)", 90
	case response[0] == 0x02: 
		return fmt.Sprintf("✅ Disconnect (normal). Banner: %s, Time: %v", trimmedBanner, elapsed), 10
	default:
		return fmt.Sprintf("⚠️ Unexpected response: %x (Banner: %s, Time: %v)", response, trimmedBanner, elapsed), 60
	}
}

func getRandomDelay1(min, max int) time.Duration {
	randNum, _ := crand.Int(crand.Reader, big.NewInt(int64(max-min)))
	return time.Duration(min+int(randNum.Int64())) * time.Millisecond
}

func randomUsername() string {
	names := []string{"admin", "root", "test", "ubuntu", "user", "guest", "notgay", "minecraft", "henry", "piterparker", "simpson", "pitergriffin"}
	return names[mrand.Intn(len(names))]
}
