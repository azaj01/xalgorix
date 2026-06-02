package billing

// File plans.go implements task 4.3 of the xalgorix-saas spec: the
// plan-to-product mapping table populated at deploy time. Dodo Payments
// product IDs differ per region (us-east-1 vs eu-west-1) and per
// environment (test_mode vs live_mode), so they are kept out of the Go
// source and read from a YAML overlay at boot:
//
//   infra/k8s/overlays/<region>/billing.yaml
//
// The YAML shape is documented in the design's "Pricing and Plans" table
// and matches the task brief:
//
//   pro:
//     monthly: prod_xxx
//     annual:  prod_yyy
//   team:
//     monthly: prod_aaa
//     annual:  prod_bbb
//   enterprise:
//     monthly: prod_ccc
//     annual:  prod_ddd
//
// Free is intentionally absent — Free has no Dodo product because it has
// no monthly bill — so Plan(free) is rejected by ProductID with
// ErrFreeHasNoProduct rather than being silently mapped to "".
//
// Requirements: 5.2, 5.10
//
// Design references:
//   - Components and Interfaces → internal/cloud/billing → plans.go
//   - Pricing and Plans table in requirements.md
//   - Checkout flow snippet in design.md ("metadata = {org_id, account_id}")

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plan is the enum of customer-facing plan tiers. Values are the canonical
// lower-case strings used by the database CHECK constraint
// (organizations.plan IN ('free','pro','team','enterprise')) and by the
// public API. Keeping this as a string-typed enum lets callers persist or
// log a Plan without an extra translation layer.
type Plan string

// Plan values. The order mirrors the pricing table in requirements.md.
const (
	PlanFree       Plan = "free"
	PlanPro        Plan = "pro"
	PlanTeam       Plan = "team"
	PlanEnterprise Plan = "enterprise"
)

// IsValid reports whether p is one of the four canonical Plan values.
// Loaders and HTTP request decoders use this to reject unknown plans
// before they reach the catalog.
func (p Plan) IsValid() bool {
	switch p {
	case PlanFree, PlanPro, PlanTeam, PlanEnterprise:
		return true
	default:
		return false
	}
}

// Period is the enum of billing cadences supported by Dodo subscriptions.
// As with Plan, the underlying string matches the database CHECK
// constraint (subscriptions.period IN ('monthly','annual')).
type Period string

// Period values.
const (
	PeriodMonthly Period = "monthly"
	PeriodAnnual  Period = "annual"
)

// IsValid reports whether p is one of the two canonical Period values.
func (p Period) IsValid() bool {
	switch p {
	case PeriodMonthly, PeriodAnnual:
		return true
	default:
		return false
	}
}

// Sentinel errors. Wrapped with %w so callers can use errors.Is to
// branch on the failure mode without parsing message strings.
var (
	// ErrInvalidPlan is returned by ProductID when the caller supplies
	// a Plan value outside the canonical set. LoadPlans also returns
	// this error when the YAML contains an unknown top-level key.
	ErrInvalidPlan = errors.New("billing: invalid plan")
	// ErrInvalidPeriod is returned by ProductID when the caller
	// supplies a Period outside the canonical set, and by LoadPlans
	// when an unknown nested key is encountered.
	ErrInvalidPeriod = errors.New("billing: invalid period")
	// ErrFreeHasNoProduct is returned by ProductID when called with
	// PlanFree. The Free plan is fulfilled by the platform itself and
	// therefore has no Dodo product to checkout against.
	ErrFreeHasNoProduct = errors.New("billing: free plan has no Dodo product")
	// ErrPlanNotConfigured is returned by ProductID when the catalog
	// is missing an entry for the supplied (plan, period) pair. This
	// is the failure mode an operator hits if they edit the overlay
	// YAML to remove a row that the application still references.
	ErrPlanNotConfigured = errors.New("billing: plan/period combination is not configured")
	// ErrCatalogEmpty is returned by LoadPlans when the YAML parses
	// into a structure that contains no usable entries. Catching this
	// at boot prevents silently shipping a build where every checkout
	// would fail with ErrPlanNotConfigured.
	ErrCatalogEmpty = errors.New("billing: plan catalog is empty")
)

// PlanCatalog is the immutable plan-to-product lookup table produced by
// LoadPlans. The keying scheme is "<plan>:<period>" (for example
// "pro:annual") which keeps the lookup as a single map operation and
// keeps the field name aligned with the task brief.
//
// The struct is intentionally opaque: callers go through ProductID rather
// than poking at entries directly so the lookup contract (validation +
// sentinel errors) stays centralised.
type PlanCatalog struct {
	entries map[string]string
}

// catalogKey builds the canonical "<plan>:<period>" lookup key. Centralised
// so LoadPlans and ProductID cannot drift.
func catalogKey(plan Plan, period Period) string {
	return string(plan) + ":" + string(period)
}

// planYAML is the on-disk shape of one plan tier inside billing.yaml.
// Pointer-typed strings let us tell "set to empty" from "absent": an
// absent field unmarshals to nil and is treated as ErrPlanNotConfigured,
// while a present-but-empty field is rejected during validation.
type planYAML struct {
	Monthly *string `yaml:"monthly"`
	Annual  *string `yaml:"annual"`
}

// catalogYAML is the top-level shape of billing.yaml. Free is omitted on
// purpose; see the package-level comment.
type catalogYAML struct {
	Pro        *planYAML `yaml:"pro"`
	Team       *planYAML `yaml:"team"`
	Enterprise *planYAML `yaml:"enterprise"`
}

// LoadPlans reads the YAML overlay at yamlPath and returns a populated
// PlanCatalog. The function uses strict decoding (KnownFields(true)) so
// typos in the overlay surface as load-time errors instead of silently
// missing entries at runtime.
//
// LoadPlans returns:
//
//   - the parsed *PlanCatalog and nil on success;
//   - a wrapped os error when the file cannot be read;
//   - a wrapped yaml decoder error when the file does not parse;
//   - ErrInvalidPlan / ErrInvalidPeriod when a recognised tier carries
//     an empty product ID, mirroring the DB CHECK constraints;
//   - ErrCatalogEmpty when no entries were populated at all.
func LoadPlans(yamlPath string) (*PlanCatalog, error) {
	if strings.TrimSpace(yamlPath) == "" {
		return nil, fmt.Errorf("billing: yamlPath is required")
	}

	raw, err := os.ReadFile(yamlPath)
	if err != nil {
		// Wrap with %w so callers can use errors.Is(err, os.ErrNotExist)
		// to distinguish "ops forgot to ship the overlay" from
		// "file is malformed".
		return nil, fmt.Errorf("billing: read plan catalog %q: %w", yamlPath, err)
	}

	// Strict decoding: any unknown top-level or nested key is an error.
	// This is the cheapest defence against silently dropping a typo'd
	// entry like `enterprize: { ... }`.
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)

	var doc catalogYAML
	if err := dec.Decode(&doc); err != nil {
		// yaml.v3 returns io.EOF on a document that contains no
		// nodes (e.g. an empty file or a file consisting only of
		// comments). That is the same observable state as "every
		// tier omitted", so we surface ErrCatalogEmpty rather than
		// a confusing decoder error.
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: %s", ErrCatalogEmpty, yamlPath)
		}
		return nil, fmt.Errorf("billing: decode plan catalog %q: %w", yamlPath, err)
	}

	cat := &PlanCatalog{entries: make(map[string]string, 6)}
	type tier struct {
		plan Plan
		body *planYAML
	}
	for _, t := range []tier{
		{PlanPro, doc.Pro},
		{PlanTeam, doc.Team},
		{PlanEnterprise, doc.Enterprise},
	} {
		if t.body == nil {
			// Absent tier is permitted (not every region has to
			// offer Enterprise on day one) but it must not
			// produce a silent map miss; ProductID will return
			// ErrPlanNotConfigured for any unset (plan, period).
			continue
		}
		if err := addEntry(cat.entries, t.plan, PeriodMonthly, t.body.Monthly, yamlPath); err != nil {
			return nil, err
		}
		if err := addEntry(cat.entries, t.plan, PeriodAnnual, t.body.Annual, yamlPath); err != nil {
			return nil, err
		}
	}

	if len(cat.entries) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrCatalogEmpty, yamlPath)
	}
	return cat, nil
}

// addEntry validates one (plan, period) cell and inserts it into the map.
// A nil ptr means the operator did not supply a value for that cell, which
// is permissible (the cell is simply absent from the catalog). A pointer
// to an empty or whitespace-only string is rejected — it almost always
// means the YAML editor left a placeholder behind.
func addEntry(entries map[string]string, plan Plan, period Period, ptr *string, yamlPath string) error {
	if ptr == nil {
		return nil
	}
	id := strings.TrimSpace(*ptr)
	if id == "" {
		return fmt.Errorf("%w: %s product id for %s/%s is empty",
			ErrInvalidPeriod, yamlPath, plan, period)
	}
	entries[catalogKey(plan, period)] = id
	return nil
}

// ProductID looks up the Dodo product identifier for the supplied
// (plan, period) pair. It returns:
//
//   - the product ID and nil on success;
//   - ErrFreeHasNoProduct when plan == PlanFree;
//   - ErrInvalidPlan / ErrInvalidPeriod when either argument is outside
//     the canonical enum values;
//   - ErrPlanNotConfigured when the catalog has no entry for an
//     otherwise-valid pair (for example, an overlay that omits
//     enterprise/annual).
//
// The method is read-only and safe for use by concurrent goroutines.
func (c *PlanCatalog) ProductID(plan Plan, period Period) (string, error) {
	if c == nil {
		return "", ErrCatalogEmpty
	}
	if plan == PlanFree {
		return "", ErrFreeHasNoProduct
	}
	if !plan.IsValid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPlan, string(plan))
	}
	if !period.IsValid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPeriod, string(period))
	}
	id, ok := c.entries[catalogKey(plan, period)]
	if !ok {
		return "", fmt.Errorf("%w: %s/%s", ErrPlanNotConfigured, plan, period)
	}
	return id, nil
}
