package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/stephnos/policygate/internal/policy"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "-h", "--help", "help":
		usage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "policyctl: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `policyctl — offline policy evaluation

Usage:
  policyctl check -f <pod.yaml> -p <policies/>

Flags:
`)
	flag.CommandLine.SetOutput(os.Stderr)
	flag.PrintDefaults()
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	policyPath := fs.String("p", "policies/", "policy bundle file or directory")
	filePath := fs.String("f", "", "pod manifest YAML (required)")
	jsonOut := fs.Bool("json", false, "emit violations as JSON")
	_ = fs.Parse(args)

	if *filePath == "" {
		fmt.Fprintln(os.Stderr, "policyctl check: -f pod manifest is required")
		return 2
	}

	bundle, err := loadPolicy(*policyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyctl: load policy: %v\n", err)
		return 1
	}

	pod, nsLabels, err := loadPod(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policyctl: load pod: %v\n", err)
		return 1
	}

	eval := policy.NewEvaluator(bundle)
	violations := eval.EvaluatePod(pod, policy.NamespaceContext{Labels: nsLabels})

	if len(violations) == 0 {
		if *jsonOut {
			fmt.Println("[]")
		}
		return 0
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(violations)
	} else {
		fmt.Println(policy.FormatDenial(violations))
	}
	return 1
}

func loadPolicy(path string) (*policy.PolicyBundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return policy.LoadBundleDir(path)
	}
	return policy.LoadBundle(path)
}

func loadPod(path string) (*corev1.Pod, map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	var pod corev1.Pod
	if err := yaml.Unmarshal(data, &pod); err != nil {
		return nil, nil, err
	}

	nsLabels := map[string]string{}
	if v, ok := doc["metadata"].(map[string]any); ok {
		if ann, ok := v["annotations"].(map[string]any); ok {
			if raw, ok := ann["policygate.io/namespace-labels"]; ok {
				if s, ok := raw.(string); ok && s != "" {
					_ = json.Unmarshal([]byte(s), &nsLabels)
				}
			}
		}
	}
	return &pod, nsLabels, nil
}
