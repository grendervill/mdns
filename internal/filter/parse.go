package filter

import (
	"bufio"
	"io"
	"strings"

	"mydns/internal/dnsname"
)

// maxRuleLine is the longest list line considered; longer lines are
// counted as skipped so one pathological row cannot bloat parsing.
const maxRuleLine = 1 << 20

// hostIPs are the loopback/zero addresses a hosts-format line may use
// to point a domain away.
var hostIPs = map[string]bool{
	"0.0.0.0":   true,
	"127.0.0.1": true,
	"::":        true,
	"::1":       true,
}

// Parsed is the result of parsing one list.
type Parsed struct {
	Block   []string // unique blocked domains, in first-seen order
	Except  []string // unique exceptions (@@), in first-seen order
	Applied int      // accepted rules (unique)
	Skipped int      // rejected lines (cosmetics, modifiers, junk, oversize)
}

// Parse reads one block list and classifies every line independently:
// adblock subsets (||domain^ and @@ exceptions), hosts lines
// (0.0.0.0/127.0.0.1/::/::1 + domain), plain domains, comments and
// everything else from junk to cosmetic rules (skipped with a count).
func Parse(r io.Reader) (Parsed, error) {
	var out Parsed
	seenBlock := map[string]bool{}
	seenExcept := map[string]bool{}

	addBlock := func(d string) {
		if seenBlock[d] {
			return
		}
		seenBlock[d] = true
		out.Block = append(out.Block, d)
		out.Applied++
	}
	addExcept := func(d string) {
		if seenExcept[d] {
			return
		}
		seenExcept[d] = true
		out.Except = append(out.Except, d)
		out.Applied++
	}

	parseLine := func(raw string) {
		line := strings.TrimSpace(raw)
		if line == "" {
			return
		}
		if len(line) > maxRuleLine {
			out.Skipped++
			return
		}
		if strings.HasPrefix(line, "!") {
			return // comment
		}
		if strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "##") || strings.HasPrefix(line, "#@#") || strings.HasPrefix(line, "#?#") {
				out.Skipped++ // cosmetic rule: meaningless in DNS
				return
			}
			return // comment
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i]) // inline comment
			if line == "" {
				return
			}
		}
		if strings.Contains(line, "$") {
			out.Skipped++ // adblock modifiers are not supported
			return
		}

		body := line
		except := false
		if strings.HasPrefix(body, "@@") {
			except = true
			body = body[2:]
		}

		if strings.HasPrefix(body, "||") {
			if !strings.HasSuffix(body, "^") {
				out.Skipped++
				return
			}
			d := dnsname.Normalize(strings.TrimSuffix(body[2:], "^"))
			if !dnsname.Valid(d) {
				out.Skipped++
				return
			}
			if except {
				addExcept(d)
			} else {
				addBlock(d)
			}
			return
		}
		if except {
			d := dnsname.Normalize(body)
			if !dnsname.Valid(d) {
				out.Skipped++
				return
			}
			addExcept(d)
			return
		}
		if strings.ContainsAny(line, "|*/") {
			out.Skipped++ // adblock/path leftovers
			return
		}

		fields := strings.Fields(line)
		if len(fields) == 2 && hostIPs[fields[0]] {
			d := dnsname.Normalize(fields[1])
			if !dnsname.Valid(d) {
				out.Skipped++
				return
			}
			addBlock(d)
			return
		}
		if len(fields) == 1 {
			if d := dnsname.Normalize(fields[0]); dnsname.Valid(d) {
				addBlock(d)
				return
			}
		}
		out.Skipped++
	}

	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			parseLine(line)
		}
		if err != nil {
			if err == io.EOF {
				return out, nil
			}
			return out, err
		}
	}
}
