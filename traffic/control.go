package traffic

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const SocketPath = "/tmp/traffic-cli.sock"

// ControlCommand is the JSON message sent over the unix socket.
type ControlCommand struct {
	Action string `json:"action"` // "run", "stop", "extend", "status"

	// For "run": new traffic parameters.
	Shape        string   `json:"shape,omitempty"`
	Peaks        int      `json:"peaks,omitempty"`
	MaxQPS       int      `json:"max_qps,omitempty"`
	Cycle        Duration `json:"cycle,omitempty"`
	Targets      []string `json:"targets,omitempty"`
	Names        []string `json:"names,omitempty"`
	RandomPrefix bool     `json:"random_prefix,omitempty"`

	// For "run": query transport (udp, tcp, both).
	Transport string `json:"transport,omitempty"`

	// For "extend": additional time.
	ExtendBy Duration `json:"extend_by,omitempty"`
}

// ControlResponse is sent back from the server.
type ControlResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// Duration wraps time.Duration for JSON marshaling.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// ServerRunning checks whether a server is listening on the socket.
func ServerRunning() bool {
	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// SendCommand sends a control command to a running server and returns the response.
func SendCommand(cmd ControlCommand) (*ControlResponse, error) {
	conn, err := net.Dial("unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("no server running (cannot connect to %s): %v", SocketPath, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	enc := json.NewEncoder(conn)
	if err := enc.Encode(cmd); err != nil {
		return nil, fmt.Errorf("sending command: %v", err)
	}

	var resp ControlResponse
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("reading response: %v", err)
	}
	return &resp, nil
}

// controlServer is the server-side state that handles incoming commands.
type controlServer struct {
	listener net.Listener

	// Channels for communicating with the run loop.
	stopCh     chan struct{}
	extendCh   chan time.Duration
	reconfigCh chan ControlCommand
}

func newControlServer(stopCh chan struct{}, extendCh chan time.Duration, reconfigCh chan ControlCommand) (*controlServer, error) {
	// Clean up stale socket.
	os.Remove(SocketPath)

	listener, err := net.Listen("unix", SocketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %v", SocketPath, err)
	}

	return &controlServer{
		listener:   listener,
		stopCh:     stopCh,
		extendCh:   extendCh,
		reconfigCh: reconfigCh,
	}, nil
}

func (cs *controlServer) serve() {
	defer cs.listener.Close()
	defer os.Remove(SocketPath)

	for {
		conn, err := cs.listener.Accept()
		if err != nil {
			return // listener closed
		}
		go cs.handleConn(conn)
	}
}

func (cs *controlServer) close() {
	cs.listener.Close()
}

func (cs *controlServer) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	var cmd ControlCommand
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&cmd); err != nil {
		log.Printf("Control: bad command: %v", err)
		return
	}

	var resp ControlResponse

	switch cmd.Action {
	case "stop":
		resp = ControlResponse{OK: true, Message: "Shutting down."}
		json.NewEncoder(conn).Encode(resp)
		close(cs.stopCh)
		return

	case "extend":
		d := time.Duration(cmd.ExtendBy)
		if d <= 0 {
			resp = ControlResponse{OK: false, Message: "extend_by must be positive"}
		} else {
			cs.extendCh <- d
			resp = ControlResponse{OK: true, Message: fmt.Sprintf("Extended by %v.", d)}
		}

	case "run":
		cs.reconfigCh <- cmd
		resp = ControlResponse{OK: true, Message: "Reconfigured."}

	case "status":
		resp = ControlResponse{OK: true, Message: "Running."}

	default:
		resp = ControlResponse{OK: false, Message: fmt.Sprintf("Unknown action: %s", cmd.Action)}
	}

	json.NewEncoder(conn).Encode(resp)
}
