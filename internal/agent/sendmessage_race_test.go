package agent

import (
	"sync"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/llm"
)

// TestSendMessage_ConcurrentWithMessageSnapshot is a regression test
// for the data race fixed alongside the scope-guard work: the agent
// loop used to read a.messages directly when calling client.Chat,
// while SendMessage appends to a.messages (under msgMu) from the web
// chat handler on another goroutine. A concurrent append that
// reallocates the backing array mid-serialization is a data race.
//
// The fix snapshots a.messages under msgMu before handing it to the
// LLM client. This test drives the same two access patterns
// concurrently — the locked snapshot the loop now performs, and the
// locked append SendMessage performs — and must run cleanly under
// `go test -race`. It also asserts no appended message is lost.
func TestSendMessage_ConcurrentWithMessageSnapshot(t *testing.T) {
	a := &Agent{
		// Buffered events channel so emit() never blocks the
		// SendMessage goroutine during the test.
		events: make(chan Event, 4096),
	}
	a.msgMu.Lock()
	a.messages = []llm.Message{{Role: "system", Content: "sys"}}
	a.msgMu.Unlock()

	const senders = 8
	const perSender = 200

	var wg sync.WaitGroup

	// Reader goroutines mimic the loop's pre-Chat snapshot: copy the
	// slice under msgMu and iterate the copy (as doChat does).
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				a.msgMu.Lock()
				snap := make([]llm.Message, len(a.messages))
				copy(snap, a.messages)
				a.msgMu.Unlock()
				// Touch every element to surface torn reads under -race.
				total := 0
				for i := range snap {
					total += len(snap[i].Content)
				}
				_ = total
			}
		}()
	}

	// Writer goroutines append via SendMessage concurrently.
	for s := 0; s < senders; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perSender; i++ {
				if _, err := a.SendMessage("ping"); err != nil {
					t.Errorf("SendMessage returned error: %v", err)
					return
				}
			}
		}()
	}

	// Wait until all appends land, then stop the readers and join.
	want := 1 + senders*perSender
	for {
		a.msgMu.Lock()
		n := len(a.messages)
		a.msgMu.Unlock()
		if n >= want {
			break
		}
	}
	close(stop)
	wg.Wait()

	a.msgMu.Lock()
	got := len(a.messages)
	a.msgMu.Unlock()
	if got != want {
		t.Fatalf("message count = %d, want %d (appends lost under concurrency)", got, want)
	}
}
