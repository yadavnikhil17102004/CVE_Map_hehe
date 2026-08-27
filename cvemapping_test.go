package main

import "testing"

func TestFindStrictCVEIDs(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{
			name: "truncated repo name, full id in description",
			text: "HORKimhab/CVE-2026-442_ Proof-of-concept for CVE-2026-44289",
			want: []string{"CVE-2026-44289"},
		},
		{
			name: "no cve in text",
			text: "random-security-tool no identifier here",
			want: nil,
		},
		{
			name: "short suffix rejected",
			text: "exploit for CVE-2026-442 only three digits",
			want: nil,
		},
		{
			name: "multi cve bundle",
			text: "bundle CVE-2021-22681 and CVE-2021-22682 in one repo",
			want: []string{"CVE-2021-22681", "CVE-2021-22682"},
		},
		{
			name: "case insensitive",
			text: "cve-2024-12345 in lowercase",
			want: []string{"CVE-2024-12345"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findStrictCVEIDs(tt.text)
			if len(got) != len(tt.want) {
				t.Fatalf("findStrictCVEIDs() len = %d, want %d (%v)", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("findStrictCVEIDs()[%d] = %q, want %q (full: %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}

func TestFindStrictCVEIDsNeverReturnsTruncatedBucketKey(t *testing.T) {
	text := "CVE-2026-442_ mentions CVE-2026-44289"
	for _, id := range findStrictCVEIDs(text) {
		if id == "CVE-2026-442" {
			t.Fatalf("must not emit truncated bucket key CVE-2026-442; got %v", findStrictCVEIDs(text))
		}
	}
}

func TestMappingBucketForOther(t *testing.T) {
	search := "CVE-2026-442_ PoC for CVE-2026-44289"
	inferred := findStrictCVEIDs(search)
	got := mappingBucketForOther(search, "2026", inferred)
	if got != "truncated" {
		t.Fatalf("expected truncated, got %q", got)
	}
}

func TestP1aMetadataDescriptionOnlyCVE(t *testing.T) {
	repo := &GitHubRepository{
		ID:          1318671575,
		Name:        "cip-security-poc",
		FullName:    "pcrosby-1990/cip-security-poc",
		Description: "mapping for CVE-2021-22681 in Rockwell",
	}
	inferred := findStrictCVEIDs(repoSearchText(repo))
	bucketKeys := findStrictCVEIDs(repoIdentityText(repo))
	if len(bucketKeys) != 0 {
		t.Fatalf("expected no identity bucket keys, got %v", bucketKeys)
	}
	if len(inferred) != 1 || inferred[0] != "CVE-2021-22681" {
		t.Fatalf("unexpected inferred: %v", inferred)
	}
	meta := toCVERepository(repo, "OTHER-2026", mappingBucketForOther(repoSearchText(repo), "2026", inferred), inferred)
	if meta.MappingParentCVEID != "OTHER-2026" || meta.MappingBucket != "other" {
		t.Fatalf("unexpected mapping metadata: parent=%q bucket=%q", meta.MappingParentCVEID, meta.MappingBucket)
	}
	if len(meta.InferredCVEIDs) != 1 || meta.InferredCVEIDs[0] != "CVE-2021-22681" {
		t.Fatalf("unexpected inferred on struct: %v", meta.InferredCVEIDs)
	}
}

func TestP1aMetadataStrictIdentityBucket(t *testing.T) {
	repo := &GitHubRepository{
		ID:          1,
		Name:        "CVE-2026-44289-poc",
		FullName:    "user/CVE-2026-44289-poc",
		Description: "PoC for CVE-2026-44289",
	}
	bucketKeys := findStrictCVEIDs(repoIdentityText(repo))
	if len(bucketKeys) != 1 || bucketKeys[0] != "CVE-2026-44289" {
		t.Fatalf("expected strict identity bucket CVE-2026-44289, got %v", bucketKeys)
	}
	inferred := findStrictCVEIDs(repoSearchText(repo))
	meta := toCVERepository(repo, bucketKeys[0], "strict", inferred)
	if meta.MappingBucket != "strict" || meta.MappingParentCVEID != "CVE-2026-44289" {
		t.Fatalf("unexpected strict metadata: %+v", meta)
	}
}
