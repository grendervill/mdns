package app

import "mydns/internal/stats"

// CollectorForTests exposes the cumulative statistics collector to the
// external test package, which asserts that the running pipeline feeds
// it and that a runtime rebuild does not reset it. The production
// accessor arrives with the stats API.
func (a *App) CollectorForTests() *stats.Collector { return a.collector }
