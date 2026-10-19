package filter

import "slices"

// CatalogEntry is one known block list. Category is "ads"
// (advertising/tracking), "combined" (combined security/privacy lists)
// or "regional" (lists scoped to one country or language).
type CatalogEntry struct {
	ID          string
	Name        string
	URL         string
	Category    string
	Description string
}

// catalogEntries is the built-in list catalog. URLs are verified
// against their hosts when this list changes.
var catalogEntries = []CatalogEntry{
	{
		ID:          "adguard-dns-filter",
		Name:        "AdGuard DNS filter",
		URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
		Category:    "ads",
		Description: "AdGuard's DNS-tuned ad and tracker list; the recommended default.",
	},
	{
		ID:          "adguard-base",
		Name:        "AdGuard Base filter",
		URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
		Category:    "ads",
		Description: "AdGuard's main ad-blocking list, broader than the DNS filter.",
	},
	{
		ID:          "ublock-filters",
		Name:        "uBlock Origin filters",
		URL:         "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt",
		Category:    "ads",
		Description: "Default uBlock Origin list; DNS-relevant rules are applied, cosmetic ones skipped.",
	},
	{
		ID:          "easylist",
		Name:        "EasyList",
		URL:         "https://easylist.to/easylist/easylist.txt",
		Category:    "ads",
		Description: "The classic EasyList; only its domain rules apply to DNS.",
	},
	{
		ID:          "peter-lowe",
		Name:        "Peter Lowe's ad servers",
		URL:         "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0",
		Category:    "ads",
		Description: "Long-running, conservative tracker list.",
	},
	{
		ID:          "oisd-small",
		Name:        "OISD Small",
		URL:         "https://small.oisd.nl/",
		Category:    "combined",
		Description: "Moderate set with a very low false-positive rate.",
	},
	{
		ID:          "oisd-full",
		Name:        "OISD Full",
		URL:         "https://big.oisd.nl/",
		Category:    "combined",
		Description: "Large curated set; stricter blocking.",
	},
	{
		ID:          "hagezi-pro",
		Name:        "HaGeZi Pro",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
		Category:    "combined",
		Description: "Balanced multi-purpose list from hagezi/dns-blocklists.",
	},
	{
		ID:          "hagezi-proplus",
		Name:        "HaGeZi Pro++",
		URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
		Category:    "combined",
		Description: "Stricter hagezi tier with a slight false-positive risk.",
	},
	{
		ID:          "stevenblack-unified",
		Name:        "Steven Black Unified",
		URL:         "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
		Category:    "combined",
		Description: "The classic unified hosts file (ads, trackers, malware).",
	},
	{
		ID:          "1hosts-lite",
		Name:        "1Hosts Lite",
		URL:         "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt",
		Category:    "combined",
		Description: "Lightweight, family-suitable combined list.",
	},

	{
		ID:          "ruadlist",
		Name:        "RU AdList",
		URL:         "https://easylist-downloads.adblockplus.org/advblock.txt",
		Category:    "regional",
		Description: "Ads and trackers for RU, UA, UZ, KZ; the proper list (an include-only uBO variant exists and must not be used).",
	},
	{
		ID:          "adguard-ukrainian",
		Name:        "AdGuard Ukrainian",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/23.txt",
		Category:    "regional",
		Description: "AdGuard's Ukrainian list; ads and trackers on regional sites.",
	},
	{
		ID:          "easylist-germany",
		Name:        "EasyList Germany",
		URL:         "https://easylist.to/easylistgermany/easylistgermany.txt",
		Category:    "regional",
		Description: "EasyList's German supplement; only its domain rules apply to DNS.",
	},
	{
		ID:          "adguard-french",
		Name:        "AdGuard Français",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/16.txt",
		Category:    "regional",
		Description: "AdGuard's French list; ads and trackers on regional sites.",
	},
	{
		ID:          "easylist-italy",
		Name:        "EasyList Italy",
		URL:         "https://easylist-downloads.adblockplus.org/easylistitaly.txt",
		Category:    "regional",
		Description: "EasyList's Italian supplement; only its domain rules apply to DNS.",
	},
	{
		ID:          "adguard-dutch",
		Name:        "AdGuard Dutch",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/8.txt",
		Category:    "regional",
		Description: "AdGuard's Dutch list; ads and trackers on regional sites.",
	},
	{
		ID:          "polish-filters",
		Name:        "Oficjalne Polskie Filtry (uBO)",
		URL:         "https://raw.githubusercontent.com/MajkiIT/polish-ads-filter/master/polish-adblock-filters/adblock.txt",
		Category:    "regional",
		Description: "The official Polish ad and tracker filters for uBlock Origin.",
	},
	{
		ID:          "certpl-warning",
		Name:        "CERT.PL Warning List",
		URL:         "https://hole.cert.pl/domains/v2/domains_ublock.txt",
		Category:    "regional",
		Description: "Polish CERT phishing/malware domains; domain-only rules.",
	},
	{
		ID:          "adguard-turkish",
		Name:        "AdGuard Turkish",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/13.txt",
		Category:    "regional",
		Description: "AdGuard's Turkish list; ads and trackers on regional sites.",
	},
	{
		ID:          "adguard-chinese",
		Name:        "AdGuard Chinese (中文)",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/224.txt",
		Category:    "regional",
		Description: "AdGuard's Chinese list; ads and trackers on regional sites.",
	},
	{
		ID:          "adguard-japanese",
		Name:        "AdGuard Japanese",
		URL:         "https://filters.adtidy.org/extension/ublock/filters/7.txt",
		Category:    "regional",
		Description: "AdGuard's Japanese list; ads and trackers on regional sites.",
	},
	{
		ID:          "easylist-hebrew",
		Name:        "EasyList Hebrew",
		URL:         "https://raw.githubusercontent.com/easylist/EasyListHebrew/master/EasyListHebrew.txt",
		Category:    "regional",
		Description: "EasyList's Hebrew list; only its domain rules apply to DNS.",
	},
	{
		ID:          "abpindo",
		Name:        "ABPindo",
		URL:         "https://raw.githubusercontent.com/ABPindo/indonesianadblockrules/master/subscriptions/abpindo.txt",
		Category:    "regional",
		Description: "Indonesian ad-blocking rules from the ABPindo project.",
	},
	{
		ID:          "indianlist",
		Name:        "IndianList",
		URL:         "https://easylist-downloads.adblockplus.org/indianlist.txt",
		Category:    "regional",
		Description: "EasyList's Indian supplement; only its domain rules apply to DNS.",
	},
}

// catalogPresets maps preset names to catalog IDs. "basic" is the
// recommended middle ground; "strict" is the maximum useful blocking.
var catalogPresets = map[string][]string{
	"basic":  {"adguard-dns-filter", "oisd-small"},
	"strict": {"adguard-base", "ublock-filters", "oisd-full", "hagezi-proplus"},
}

// Catalog returns the built-in list catalog.
func Catalog() []CatalogEntry {
	return slices.Clone(catalogEntries)
}

// EntryByID looks a catalog entry up by its ID.
func EntryByID(id string) (CatalogEntry, bool) {
	for _, e := range catalogEntries {
		if e.ID == id {
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// Preset returns the catalog IDs of a named preset ("basic" or
// "strict").
func Preset(name string) ([]string, bool) {
	ids, ok := catalogPresets[name]
	if !ok {
		return nil, false
	}
	return slices.Clone(ids), true
}
