package billing

// File plans_test.go covers task 4.3 of the xalgorix-saas spec:
//
//   - LoadPlans happy path: every recognised (plan, period) pair lands in
//     the returned catalog with the supplied product ID;
//   - ProductID happy path through the same catalog;
//   - ProductID error path when the requested plan tier is missing from
//     the YAML (returns ErrPlanNotConfigured);
//   - ProductID error path when the requested period is missing under an
//     otherwise-present plan tier (returns ErrPlanNotConfigured);
//   - ProductID short-circuit for PlanFree (returns ErrFreeHasNoProduct);
//   - LoadPlans rejection of an empty document (returns ErrCatalogEmpty);
//   - LoadPlans rejection of an unknown top-level key (yaml KnownFields).
//
// Requirements: 5.2, 5.10

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeYAML writes body to a fresh file inside t.TempDir() and returns the
// path. Centralising this keeps individual test cases short.
func writeYAML(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "billing.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml fixture: %v", err)
	}
	return p
}

func TestLoadPlansHappyPath(t *testing.T) {
	t.Parallel()

	yamlBody := `
pro:
  monthly: prod_pro_monthly
  annual:  prod_pro_annual
team:
  monthly: prod_team_monthly
  annual:  prod_team_annual
enterprise:
  monthly: prod_ent_monthly
  annual:  prod_ent_annual
`
	cat, err := LoadPlans(writeYAML(t, yamlBody))
	if err != nil {
		t.Fatalf("LoadPlans: %v", err)
	}

	want := []struct {
		plan   Plan
		period Period
		id     string
	}{
		{PlanPro, PeriodMonthly, "prod_pro_monthly"},
		{PlanPro, PeriodAnnual, "prod_pro_annual"},
		{PlanTeam, PeriodMonthly, "prod_team_monthly"},
		{PlanTeam, PeriodAnnual, "prod_team_annual"},
		{PlanEnterprise, PeriodMonthly, "prod_ent_monthly"},
		{PlanEnterprise, PeriodAnnual, "prod_ent_annual"},
	}
	for _, w := range want {
		got, err := cat.ProductID(w.plan, w.period)
		if err != nil {
			t.Errorf("ProductID(%s,%s) err = %v", w.plan, w.period, err)
			continue
		}
		if got != w.id {
			t.Errorf("ProductID(%s,%s) = %q, want %q", w.plan, w.period, got, w.id)
		}
	}
}

func TestLoadPlansTrimsAndIgnoresAbsentTier(t *testing.T) {
	t.Parallel()

	// Enterprise omitted entirely, pro/annual omitted at the cell level.
	// Whitespace around product IDs is trimmed.
	yamlBody := `
pro:
  monthly: "  prod_pro_monthly  "
team:
  monthly: prod_team_monthly
  annual:  prod_team_annual
`
	cat, err := LoadPlans(writeYAML(t, yamlBody))
	if err != nil {
		t.Fatalf("LoadPlans: %v", err)
	}

	got, err := cat.ProductID(PlanPro, PeriodMonthly)
	if err != nil || got != "prod_pro_monthly" {
		t.Errorf("ProductID(pro,monthly) = (%q,%v), want (prod_pro_monthly,nil)", got, err)
	}

	// Missing period under a present tier -> ErrPlanNotConfigured.
	if _, err := cat.ProductID(PlanPro, PeriodAnnual); !errors.Is(err, ErrPlanNotConfigured) {
		t.Errorf("ProductID(pro,annual) err = %v, want errors.Is ErrPlanNotConfigured", err)
	}

	// Tier omitted entirely -> still ErrPlanNotConfigured.
	if _, err := cat.ProductID(PlanEnterprise, PeriodMonthly); !errors.Is(err, ErrPlanNotConfigured) {
		t.Errorf("ProductID(enterprise,monthly) err = %v, want errors.Is ErrPlanNotConfigured", err)
	}
}

func TestProductIDFreePlanIsRejected(t *testing.T) {
	t.Parallel()

	yamlBody := `
pro:
  monthly: prod_pro_monthly
`
	cat, err := LoadPlans(writeYAML(t, yamlBody))
	if err != nil {
		t.Fatalf("LoadPlans: %v", err)
	}
	if _, err := cat.ProductID(PlanFree, PeriodMonthly); !errors.Is(err, ErrFreeHasNoProduct) {
		t.Errorf("ProductID(free,monthly) err = %v, want errors.Is ErrFreeHasNoProduct", err)
	}
}

func TestProductIDInvalidEnums(t *testing.T) {
	t.Parallel()

	yamlBody := `
pro:
  monthly: prod_pro_monthly
`
	cat, err := LoadPlans(writeYAML(t, yamlBody))
	if err != nil {
		t.Fatalf("LoadPlans: %v", err)
	}

	if _, err := cat.ProductID(Plan("bogus"), PeriodMonthly); !errors.Is(err, ErrInvalidPlan) {
		t.Errorf("ProductID(bogus,monthly) err = %v, want errors.Is ErrInvalidPlan", err)
	}
	if _, err := cat.ProductID(PlanPro, Period("weekly")); !errors.Is(err, ErrInvalidPeriod) {
		t.Errorf("ProductID(pro,weekly) err = %v, want errors.Is ErrInvalidPeriod", err)
	}
}

func TestLoadPlansRejectsEmptyDocument(t *testing.T) {
	t.Parallel()

	// All tiers absent: the file parses but produces zero entries.
	if _, err := LoadPlans(writeYAML(t, "")); !errors.Is(err, ErrCatalogEmpty) {
		t.Errorf("LoadPlans(empty) err = %v, want errors.Is ErrCatalogEmpty", err)
	}
}

func TestLoadPlansRejectsUnknownKey(t *testing.T) {
	t.Parallel()

	// `enterprize` is a typo. Strict decoding (KnownFields(true)) catches
	// this before the rest of the catalog masks the missing tier.
	yamlBody := `
pro:
  monthly: prod_pro_monthly
enterprize:
  monthly: prod_ent_monthly
`
	_, err := LoadPlans(writeYAML(t, yamlBody))
	if err == nil {
		t.Fatal("LoadPlans accepted unknown top-level key, want error")
	}
}

func TestLoadPlansRejectsBlankProductID(t *testing.T) {
	t.Parallel()

	yamlBody := `
pro:
  monthly: ""
`
	_, err := LoadPlans(writeYAML(t, yamlBody))
	if !errors.Is(err, ErrInvalidPeriod) {
		t.Errorf("LoadPlans(blank id) err = %v, want errors.Is ErrInvalidPeriod", err)
	}
}

func TestLoadPlansRejectsMissingPath(t *testing.T) {
	t.Parallel()

	if _, err := LoadPlans(""); err == nil {
		t.Fatal("LoadPlans(\"\") returned nil error, want error")
	}

	// Nonexistent file should wrap os.ErrNotExist so callers can
	// branch on it (e.g. fall back to a default at boot).
	missing := filepath.Join(t.TempDir(), "absent.yaml")
	if _, err := LoadPlans(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("LoadPlans(missing) err = %v, want errors.Is os.ErrNotExist", err)
	}
}

func TestPlanAndPeriodIsValid(t *testing.T) {
	t.Parallel()

	for _, p := range []Plan{PlanFree, PlanPro, PlanTeam, PlanEnterprise} {
		if !p.IsValid() {
			t.Errorf("Plan(%q).IsValid() = false, want true", p)
		}
	}
	if Plan("free ").IsValid() {
		t.Error("Plan with trailing space should not be valid")
	}
	for _, p := range []Period{PeriodMonthly, PeriodAnnual} {
		if !p.IsValid() {
			t.Errorf("Period(%q).IsValid() = false, want true", p)
		}
	}
	if Period("annually").IsValid() {
		t.Error("unknown period accepted")
	}
}
