package installer

import "fmt"

// unitTemplate is the systemd unit of the service. The server runs in
// the foreground and is restarted by systemd, with the file descriptor
// limit the DNS listeners need.
const unitTemplate = `[Unit]
Description=mdns — self-hosted DNS service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s serve --config %s
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// renderUnit renders the systemd unit for the installed binary and
// config paths, with a trailing newline.
func renderUnit(binaryPath, configPath string) string {
	return fmt.Sprintf(unitTemplate, binaryPath, configPath)
}
