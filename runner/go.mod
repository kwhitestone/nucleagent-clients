module nucleagent-desktop-runner

go 1.26.1

require golang.org/x/sys v0.46.0

require (
	github.com/gorilla/websocket v1.5.3
	github.com/nucleagent/nucleagent-shared v0.0.0-20261002053529-3eea90f36e84
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/nucleagent/nucleagent-shared => github.com/kwhitestone/nucleagent-shared v0.0.0-20261002053529-3eea90f36e84
