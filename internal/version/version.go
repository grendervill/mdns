package version

var Version = "dev" // переопределяется -ldflags "-X mydns/internal/version.Version=..."

func String() string { return Version }
