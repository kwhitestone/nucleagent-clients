package admission

import "testing"

func ready(t *testing.T) (*Gate, uint64) {
	t.Helper()
	g := New()
	e := g.Connect()
	if err := g.SetBackend("codex", "verified-generation"); err != nil {
		t.Fatal(err)
	}
	if err := g.Negotiate(e, Contract); err != nil {
		t.Fatal(err)
	}
	r, err := g.Enable(true)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Ack(e, r); err != nil {
		t.Fatal(err)
	}
	return g, e
}
func TestNegotiationConsentAndAckAreRequired(t *testing.T) {
	g := New()
	e := g.Connect()
	_ = g.SetBackend("codex", "g1")
	if _, err := g.Enable(true); err == nil {
		t.Fatal("legacy core admitted")
	}
	if err := g.Negotiate(e, "legacy"); err == nil {
		t.Fatal("unknown contract admitted")
	}
	_ = g.Negotiate(e, Contract)
	if _, err := g.Enable(false); err == nil {
		t.Fatal("consent bypassed")
	}
	revision, _ := g.Enable(true)
	if _, err := g.Acquire(e, "codex", "run"); err == nil {
		t.Fatal("unacknowledged ready admitted")
	}
	_ = g.Ack(e, revision)
	if _, err := g.Acquire(e, "codex", "run"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Acquire(e, "codex", "another"); err == nil {
		t.Fatal("concurrency exceeded one")
	}
	if err := g.Finish("wrong", true, true); err == nil {
		t.Fatal("foreign generation released capacity")
	}
	g.Pause()
	if err := g.Finish("run", true, true); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Acquire(e, "codex", "next"); err == nil {
		t.Fatal("paused node admitted")
	}
}
func TestStaleSocketCannotReopenAndDriftFencesCapacity(t *testing.T) {
	g, e := ready(t)
	revision := g.Snapshot().Revision
	next := g.Connect()
	if err := g.Ack(e, revision); err == nil {
		t.Fatal("stale socket ACK accepted")
	}
	g.Disconnect(e)
	if err := g.Negotiate(next, Contract); err != nil {
		t.Fatal(err)
	}
	r, _ := g.Enable(true)
	_ = g.Ack(next, r)
	if _, err := g.Acquire(next, "codex", "job"); err != nil {
		t.Fatal(err)
	}
	if err := g.Finish("job", true, false); err == nil {
		t.Fatal("drift ignored")
	}
	if g.Snapshot().State != "unavailable" || g.Snapshot().Active != "job" {
		t.Fatal("unsafe slot released")
	}
	if _, err := g.Enable(true); err == nil {
		t.Fatal("drift bypassed by re-enable")
	}
}
