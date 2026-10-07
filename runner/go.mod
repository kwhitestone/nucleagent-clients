module nucleagent-desktop-runner

go 1.26.1

require golang.org/x/sys v0.46.0

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/gorilla/websocket v1.5.3
	github.com/nucleagent/nucleagent-shared v0.0.0-20261007130850-837cff729777
)

require github.com/google/uuid v1.6.0 // indirect

replace github.com/nucleagent/nucleagent-shared => github.com/kwhitestone/nucleagent-shared v0.0.0-20261007130850-837cff729777
