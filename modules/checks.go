package modules

type CheckResult struct {
	Name    string
	Details string
	Score   int
}

func RunChecks(ip string) []CheckResult {
	var results []CheckResult

	text, score := RunDelayCheck(ip)
	results = append(results, CheckResult{
		Name:    "DELAY",
		Details: text,
		Score:   int(score),
	})

	text, score = CheckBanner(ip)
	results = append(results, CheckResult{
		Name:    "BANNER",
		Details: text,
		Score:   int(score),
	})

	text, score = CheckTrash(ip)
	results = append(results, CheckResult{
		Name:    "TRASH SEND",
		Details: text,
		Score:   int(score),
	})

	text, score = CheckInvalidCommand(ip)
	results = append(results, CheckResult{
		Name:    "INVALID COMMAND",
		Details: text,
		Score:   int(score),
	})

	text, score = CheckDisconnect(ip)
	results = append(results, CheckResult{
		Name:    "UNEXPECTED DISCONNECT",
		Details: text,
		Score:   int(score),
	})

	text, score = CheckHelp(ip)
	results = append(results, CheckResult{
		Name:    `COMMAND "HELP" CHECK`,
		Details: text,
		Score:   int(score),
	})

	text, score = CheckNoneAuth(ip)
	results = append(results, CheckResult{
		Name:    `NONE AUTH`,
		Details: text,
		Score:   int(score),
	})

	text, score = CheckProtocolVersion(ip)
	results = append(results, CheckResult{
		Name:    `PROTOCOL PROBE`,
		Details: text,
		Score:   int(score),
	})

	return results
}
