// Current file is largely based on github.com/google/webrisk/cmd/wrlookup
// Check aforementioned file's header for Copyright details.
package main

import (
    "flag"
    "fmt"
    "encoding/json"
    "github.com/google/webrisk"
    "os"
)

const usage = `gwebrisk: lookup URLs in Google's Web Risk

gwebrisk will check a list of URLs against Google's Web Risk API. gwebrisk
reads necessary parameters, namely Google API key, local database and a list
of URLs from a json configuration file. gwebrisk prints unsafe URLs to stdout
accompanied with the type of threat they are classified.

Example configuration (json format):
 {
     "apikey": "secretapikeygoeshere",
     "database: "/path/to/webrisk/client/database",
     "urls: [
            "www.site.gr",
            "badbadsite.com"
     ]
 }


Exit codes (bitwise OR of following codes):
  0  if and only if all URLs were looked up and are safe.
  1  if at least one URL is not safe.
  2  if at least one URL lookup failed.
  4  if the input was invalid.

Usage: %s -config /path/to/config.json (optional argument)

`

// Exit codes
const (
    codeSafe = (1 << iota) / 2 // Sequence of 0, 1, 2, 4, 8, etc...
    codeUnsafe
    codeFailed
    codeInvalid
)

// Default WebriskClient parameters
const (
    DefaultServerURL = "webrisk.googleapis.com"
)

// Config holds .json configuration
type Config struct {
    APIKey   string `json:"apikey"`
    Database string `json:"database"`
    URLList  []string `json:"urls"`

}

var (
    configFlag = flag.String("config", "/etc/gwebrisk/config.json", "`FILE` to load config from")
    cfg Config
)

// ParseConfig parses a .json configuration file
func ParseConfig(filename string) (Config, error) {
    cfg := Config{}
    f, err := os.Open(filename)
    if err != nil {
        return cfg, err
    }
    defer f.Close()

    dec := json.NewDecoder(f)
    dec.UseNumber()
    return cfg, dec.Decode(&cfg)
}

func main() {
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, usage, os.Args[0])
        flag.PrintDefaults()
    }
    flag.Parse()
    if *configFlag == "" {
        fmt.Fprintln(os.Stderr, "No -config specified")
        os.Exit(codeInvalid)
    }

    cfg, err := ParseConfig(*configFlag)

    sb, err := webrisk.NewWebriskClient(webrisk.Config{
        APIKey:    cfg.APIKey,
        DBPath:    cfg.Database,
        Logger:    os.Stderr,
        ServerURL: DefaultServerURL,
    })
    if err != nil {
        fmt.Fprintln(os.Stderr, "Unable to initialize Web Risk client: ", err)
        os.Exit(codeInvalid)
    }

    code := codeSafe

    threats, err := sb.LookupURLs(cfg.URLList)
    if err != nil {
        fmt.Fprintln(os.Stdout, "Unknown threats:", threats)
        fmt.Fprintln(os.Stderr, "Lookup error:", err)
        code |= codeFailed
    } else {
        for i, threat := range threats {
            if len(threat) != 0 {
                fmt.Fprintln(os.Stdout, cfg.URLList[i], " is unsafe:", threat)
                code |= codeUnsafe
            }
        }
    }
    os.Exit(code)
}
