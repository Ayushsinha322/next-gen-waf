package main

import "github.com/sentinel-waf/plugin-sdk-go"

//export evaluate
func evaluate() {
	sentinel.Log("Hello from Go plugin!")

	ua := sentinel.GetReqHeader("user-agent")
	if ua == "" {
		sentinel.Log("No User-Agent header — suspicious")
		sentinel.AddScore(2)
	} else if sentinel.Contains(ua, "sqlmap") {
		sentinel.Log("SQLMap detected in User-Agent")
		sentinel.SetDecision(sentinel.DecisionBlock)
	}

	sentinel.SetResponseHeader("X-Sentinel-Plugin", "hello-world-go/v0.1.0")
}

func main() {}