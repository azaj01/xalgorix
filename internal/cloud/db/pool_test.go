package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// stubTx satisfies the pgx.Tx interface by embedding the interface.
// None of its methods are invoked by these tests — we only need the
// helpers to round-trip an opaque, identity-comparable value through
// the request context.
type stubTx struct {
	pgx.Tx
	id string
}

func TestWithTx_NoTxInContext(t *testing.T) {
	t.Parallel()

	tx, ok := WithTx(context.Background())
	if ok {
		t.Fatalf("WithTx(empty ctx) returned ok=true (tx=%v)", tx)
	}
	if tx != nil {
		t.Fatalf("WithTx(empty ctx) returned tx=%v, want nil", tx)
	}
}

func TestWithTx_NilContext(t *testing.T) {
	t.Parallel()

	//nolint:staticcheck // intentionally pass nil to verify defensive handling
	tx, ok := WithTx(nil)
	if ok || tx != nil {
		t.Fatalf("WithTx(nil) = (%v, %v); want (nil, false)", tx, ok)
	}
}

func TestContextWithTx_RoundTrip(t *testing.T) {
	t.Parallel()

	want := &stubTx{id: "primary"}
	ctx := ContextWithTx(context.Background(), want)

	got, ok := WithTx(ctx)
	if !ok {
		t.Fatal("WithTx returned ok=false after ContextWithTx")
	}
	if got != pgx.Tx(want) {
		t.Fatalf("WithTx returned %#v; want %#v", got, want)
	}
}

func TestContextWithTx_LatestValueWins(t *testing.T) {
	t.Parallel()

	first := &stubTx{id: "first"}
	second := &stubTx{id: "second"}

	ctx := ContextWithTx(context.Background(), first)
	ctx = ContextWithTx(ctx, second)

	got, ok := WithTx(ctx)
	if !ok {
		t.Fatal("WithTx returned ok=false on nested ContextWithTx")
	}
	stub, isStub := got.(*stubTx)
	if !isStub {
		t.Fatalf("WithTx returned %T; want *stubTx", got)
	}
	if stub.id != "second" {
		t.Fatalf("nested ContextWithTx leaked outer tx: got id=%q want id=%q", stub.id, "second")
	}
}

func TestContextWithTx_ClearsWhenNil(t *testing.T) {
	t.Parallel()

	original := &stubTx{id: "original"}
	ctx := ContextWithTx(context.Background(), original)

	cleared := ContextWithTx(ctx, nil)
	if tx, ok := WithTx(cleared); ok {
		t.Fatalf("WithTx after ContextWithTx(nil) returned ok=true (tx=%v)", tx)
	}
}

func TestWithTx_IsolatedAcrossContexts(t *testing.T) {
	t.Parallel()

	parent := context.Background()
	txA := &stubTx{id: "A"}
	txB := &stubTx{id: "B"}

	ctxA := ContextWithTx(parent, txA)
	ctxB := ContextWithTx(parent, txB)

	gotA, okA := WithTx(ctxA)
	gotB, okB := WithTx(ctxB)
	if !okA || !okB {
		t.Fatalf("expected both contexts to carry a tx; gotA=%v okA=%v gotB=%v okB=%v", gotA, okA, gotB, okB)
	}
	if gotA == gotB {
		t.Fatalf("sibling contexts shared a tx (got=%#v)", gotA)
	}
	if gotA != pgx.Tx(txA) || gotB != pgx.Tx(txB) {
		t.Fatalf("contexts crossed tx identity: gotA=%#v gotB=%#v", gotA, gotB)
	}

	// The original parent context must remain free of any tx so
	// background goroutines created from it cannot accidentally inherit
	// a sibling's transaction.
	if tx, ok := WithTx(parent); ok {
		t.Fatalf("parent context leaked tx after sibling derivation: tx=%v", tx)
	}
}

func TestBeginTx_NilPool(t *testing.T) {
	t.Parallel()

	var p *Pool
	ctx, tx, err := p.BeginTx(context.Background(), pgx.TxOptions{})
	if err == nil {
		t.Fatal("BeginTx on nil *Pool must return an error")
	}
	if tx != nil {
		t.Fatalf("BeginTx on nil *Pool returned non-nil tx=%v", tx)
	}
	if ctx == nil {
		t.Fatal("BeginTx on nil *Pool dropped the input context")
	}
}

func TestNewPool_RejectsEmptyDSN(t *testing.T) {
	t.Parallel()

	if _, err := NewPool(context.Background(), ""); err == nil {
		t.Fatal("NewPool(\"\") must return an error")
	}
}

func TestNewPool_RejectsInvalidDSN(t *testing.T) {
	t.Parallel()

	// `pgxpool.ParseConfig` fails on this DSN before any connection
	// attempt, so the test does not require a live database.
	_, err := NewPool(context.Background(), "::not a valid dsn::")
	if err == nil {
		t.Fatal("NewPool with invalid DSN must return an error")
	}
}
