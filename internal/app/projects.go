package app

import (
	"errors"
	"strings"

	"github.com/cowsecurity/emudhraslop/internal/config"
	"github.com/cowsecurity/emudhraslop/internal/discovery"
	"github.com/cowsecurity/emudhraslop/internal/model"
)

// Explicit project roots avoid a recursive scan of user-controlled filesystems.
// The bound limits discovery work; reaching it is an error, never a silent skip.
const maxProjects = 16

type projectPaths []string

func (p *projectPaths) String() string { return strings.Join(*p, ", ") }
func (p *projectPaths) Set(value string) error {
	if len(*p) >= maxProjects || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("invalid project path or too many projects")
	}
	*p = append(*p, value)
	return nil
}

func loadProjectTargets(manifest string, projects []string) ([]model.Target, model.Coverage, error) {
	targets, coverage, err := loadTargets(manifest)
	if err != nil || len(projects) == 0 {
		return targets, coverage, err
	}
	coverage.Scope = "managed-and-project-clients"
	coverage.Complete = false
	seen := make(map[string]bool, len(targets))
	seenIDs := make(map[string]bool, len(targets))
	seenExclusions := make(map[string]bool, len(coverage.Exclusions))
	key := func(t model.Target) string { return t.Kind + "\x00" + t.Client + "\x00" + t.Executable }
	for _, target := range targets {
		seen[key(target)] = true
		seenIDs[target.ID] = true
	}
	for i, exclusion := range coverage.Exclusions {
		coverage.Exclusions[i] = strings.ReplaceAll(exclusion, "virtual environments absent from PATH", "virtual environments outside PATH and selected project directories")
		seenExclusions[coverage.Exclusions[i]] = true
	}
	for _, project := range projects {
		additional, context, err := discovery.Project(project)
		if err != nil {
			return nil, coverage, err
		}
		coverage.Warnings = append(coverage.Warnings, context.Warnings...)
		for _, exclusion := range context.Exclusions {
			if !seenExclusions[exclusion] {
				coverage.Exclusions = append(coverage.Exclusions, exclusion)
				seenExclusions[exclusion] = true
			}
		}
		for _, target := range additional {
			if seen[key(target)] || seenIDs[target.ID] {
				continue
			}
			if len(targets) >= config.MaxTargets {
				return nil, coverage, errors.New("too many discovered clients; split projects into separate scans")
			}
			seen[key(target)] = true
			seenIDs[target.ID] = true
			targets = append(targets, target)
		}
	}
	return targets, coverage, nil
}
