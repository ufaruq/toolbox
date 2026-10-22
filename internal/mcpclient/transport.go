package mcpclient

import (
	"bufio"
	"context"
	"io"
	"mime"
	"net/http"
	"strings"
)

// The SDK's SSE limit is per event. This additional wire bound applies before
// JSON/SSE decoding, including chunked bodies and a sequence of small events.
type boundedTransport struct{ base http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > MaxBytes {
		response.Body.Close()
		return nil, ErrResultTooLarge
	}
	response.Body = &boundedBody{ReadCloser: response.Body, remaining: MaxBytes}
	media, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode == http.StatusOK && (media == "application/json" || media == "text/event-stream") {
		response.Body = &checkedBody{ReadCloser: response.Body, reader: bufio.NewReader(response.Body), sse: media == "text/event-stream"}
	}
	return response, nil
}

// Validate each bounded JSON-RPC envelope before the SDK turns schemas and
// structured content into maps/float64, which would erase duplicate keys and
// rounded numeric constraints. SSE frames are released one at a time so an open
// response stream does not hold up a completed call.
type checkedBody struct {
	io.ReadCloser
	reader  *bufio.Reader
	sse     bool
	pending []byte
	done    bool
}

func (b *checkedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(b.pending) == 0 {
		if b.done {
			return 0, io.EOF
		}
		if err := b.load(); err != nil {
			return 0, err
		}
		if len(b.pending) == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}

func (b *checkedBody) load() error {
	if !b.sse {
		data, err := io.ReadAll(b.reader)
		if err != nil {
			return err
		}
		if err = validateEnvelope(data); err != nil {
			return err
		}
		b.pending = data
		b.done = true
		return nil
	}
	var raw strings.Builder
	var data []string
	for {
		line, err := b.reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		raw.WriteString(line)
		field := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(field, "data:") {
			data = append(data, strings.TrimPrefix(field[5:], " "))
		} else if field == "data" {
			data = append(data, "")
		}
		if err == io.EOF {
			b.done = true
		}
		if field == "" || b.done {
			break
		}
	}
	if len(data) > 0 {
		if err := validateEnvelope([]byte(strings.Join(data, "\n"))); err != nil {
			return err
		}
	}
	b.pending = []byte(raw.String())
	return nil
}

func validateEnvelope(data []byte) error {
	object, err := decodeObject(data)
	if err != nil || !safeNumbers(object) {
		return ErrUnsupportedContent
	}
	return nil
}

type boundedBody struct {
	io.ReadCloser
	remaining int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.remaining == 0 {
		var extra [1]byte
		n, err := b.ReadCloser.Read(extra[:])
		if n > 0 {
			return 0, ErrResultTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// Never attach a gateway credential to redirects or server-selected URLs.
type authorizedTransport struct {
	base            http.RoundTripper
	token, endpoint string
	operation       context.Context
}

func (t authorizedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() != t.endpoint {
		return nil, ErrBinding
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(t.operation, cancel)
	if t.operation.Err() != nil {
		cancel()
	}
	r = r.Clone(ctx)
	r.Header = r.Header.Clone()
	r.Header.Set("Authorization", "Bearer "+t.token)
	response, err := t.base.RoundTrip(r)
	if err != nil {
		stop()
		cancel()
		return nil, err
	}
	response.Body = &operationBody{ReadCloser: response.Body, cancel: cancel, stop: stop}
	return response, nil
}

type operationBody struct {
	io.ReadCloser
	cancel context.CancelFunc
	stop   func() bool
}

func (b *operationBody) Close() error { err := b.ReadCloser.Close(); b.stop(); b.cancel(); return err }
