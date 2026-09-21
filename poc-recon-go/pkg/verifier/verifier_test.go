package verifier

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/zaidkhan0997/POC-Recon/poc-recon-go/pkg/models"
)

func TestFingerprintProviderGoogle(t *testing.T) {
	mx := []models.MXRecord{{Host: "aspmx.l.google.com", Priority: 1}}
	provider := FingerprintProvider("example.com", mx)
	if provider.Name != "Google Workspace" {
		t.Errorf("Name = %q, want %q", provider.Name, "Google Workspace")
	}
}

func TestFingerprintProviderMicrosoft(t *testing.T) {
	mx := []models.MXRecord{{Host: "example-com.mail.protection.outlook.com", Priority: 0}}
	provider := FingerprintProvider("example.com", mx)
	if provider.Name != "Microsoft 365 / Exchange" {
		t.Errorf("Name = %q, want %q", provider.Name, "Microsoft 365 / Exchange")
	}
}

func TestFingerprintProviderStandard(t *testing.T) {
	mx := []models.MXRecord{{Host: "mail.some-random-host.net", Priority: 10}}
	provider := FingerprintProvider("some-random-host.net", mx)
	if provider.Name != "Standard / On-Premise" {
		t.Errorf("Name = %q, want %q", provider.Name, "Standard / On-Premise")
	}
}

// smtpPipe wires a net.Pipe together and returns the client-side reader/writer
// plus a way to drive scripted server-side responses in a goroutine.
func smtpPipe(t *testing.T) (*bufio.Reader, *bufio.Writer, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	return bufio.NewReader(clientConn), bufio.NewWriter(clientConn), serverConn
}

func TestReadResponseSingleLine(t *testing.T) {
	reader, _, server := smtpPipe(t)

	go func() {
		server.Write([]byte("250 OK\r\n"))
	}()

	code, msg, err := readResponse(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 250 {
		t.Errorf("code = %d, want 250", code)
	}
	if msg != "OK" {
		t.Errorf("msg = %q, want %q", msg, "OK")
	}
}

func TestReadResponseMultiLine(t *testing.T) {
	reader, _, server := smtpPipe(t)

	go func() {
		server.Write([]byte("250-Hello\r\n250-SIZE 1000\r\n250 OK\r\n"))
	}()

	code, msg, err := readResponse(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 250 {
		t.Errorf("code = %d, want 250", code)
	}
	if msg != "Hello; SIZE 1000; OK" {
		t.Errorf("msg = %q, want %q", msg, "Hello; SIZE 1000; OK")
	}
}

func TestReadResponseRejection(t *testing.T) {
	reader, _, server := smtpPipe(t)

	go func() {
		server.Write([]byte("550 User Unknown\r\n"))
	}()

	code, msg, err := readResponse(reader)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 550 {
		t.Errorf("code = %d, want 550", code)
	}
	if msg != "User Unknown" {
		t.Errorf("msg = %q, want %q", msg, "User Unknown")
	}
}

func TestSendCommandEchoesCommandAndReadsResponse(t *testing.T) {
	reader, writer, server := smtpPipe(t)

	received := make(chan string, 1)
	go func() {
		serverReader := bufio.NewReader(server)
		line, _ := serverReader.ReadString('\n')
		received <- line
		server.Write([]byte("250 OK\r\n"))
	}()

	code, msg, err := sendCommand(writer, reader, "MAIL FROM:<probe@example.com>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 250 || msg != "OK" {
		t.Errorf("got code=%d msg=%q, want code=250 msg=OK", code, msg)
	}

	select {
	case line := <-received:
		if line != "MAIL FROM:<probe@example.com>\r\n" {
			t.Errorf("server received %q, want %q", line, "MAIL FROM:<probe@example.com>\r\n")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server to receive command")
	}
}

func TestCheckPort25RefusedConnection(t *testing.T) {
	// Port 0 on loopback is never listening, so the dial must fail fast and
	// CheckPort25 must report false rather than erroring or hanging.
	if CheckPort25("127.0.0.1", 500*time.Millisecond, "") {
		t.Fatal("expected CheckPort25 to return false for a closed port")
	}
}
