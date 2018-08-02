package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"strings"

	flag "github.com/spf13/pflag"
)

const (
	// GfwlistURL raw url
	GfwlistURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
	// TldsURL raw url
	TldsURL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
)

var (
	input, output, proxy string
	userRule             string
	precise              bool
)

func parseArgs() {
	flag.StringVarP(&input, "input", "i", "./", "path to gfwlist")
	flag.StringVarP(&output, "file", "f", "./", "path to output pac")
	flag.StringVarP(&proxy, "proxy", "p", "", "the proxy parameter in the pac file, \nfor example, \"SOCKS5 127.0.0.1:1080;\"")
	flag.StringVarP(&userRule, "user-rule", "", "", "user rule file, which will be appended to\n gfwlist")
	flag.BoolVarP(&precise, "precise", "", false, "use adblock plus algorithm instead of O(1)\n lookup")
	flag.Parse()
}

func decodeGfwlist(content string) string {
	if strings.Contains(content, ".") {
		return content
	}
	bytes, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		panic(err.Error())
	}
	return string(bytes)
}

func getHostname(something string) string {
	if !strings.HasPrefix(something, "http:") {
		something = "http://" + something
	}
	u, err := url.Parse(something)
	if err != nil {
		log.Println(err.Error())
		return ""
	}
	return u.Hostname()
}

func addDomainToSet(s []string, something string) {
	hostName := getHostname(something)
	if hostName != "" {
		s = append(s, hostName)
	}
}

func combineLists(content string, userRule string) []string {
	buf, err := ioutil.ReadFile("resources/builtin.txt")
	if err != nil {
		panic(err.Error())
	}
	builtinRules := strings.Split(string(buf), "/n")
	gfwlist := strings.Split(content, "/n")
	gfwlist = append(gfwlist, builtinRules...)

	if userRule != "" {
		userRule := strings.Split(userRule, "/n")
		gfwlist = append(gfwlist, userRule...)
	}
	return gfwlist
}

func parseGfwlist(gfwlist []string) []string {
	var domains []string
	for _, line := range gfwlist {
		if strings.Index(line, ".*") >= 0 {
			continue
		} else if strings.Index(line, "*") >= 0 {
			line = strings.Replace(line, "*", "/", -1)
		}
		if strings.HasPrefix(line, "||") {
			line = strings.TrimLeft(line, "||")
		} else if strings.HasPrefix(line, "|") {
			line = strings.TrimLeft(line, "|")
		} else if strings.HasPrefix(line, ".") {
			line = strings.TrimLeft(line, ".")
		}
		if strings.HasPrefix(line, "!") {
			continue
		} else if strings.HasPrefix(line, "[") {
			continue
		} else if strings.HasPrefix(line, "@") {
			continue
		}
		addDomainToSet(domains, line)
	}
	return domains
}

func reduceDomains(domains []string) []string {
	buf, err := ioutil.ReadFile("resources/tld.txt")
	if err != nil {
		panic(err.Error())
	}
	tlds := strings.Split(string(buf), "/n")
	var newDomains []string
	for _, domain := range domains {
		domainParts := strings.Split(domain, ".")
		var lastRootDomain string
		for i := range domainParts {
			rootDomain := strings.Join(domainParts[len(domainParts)-i-1:], ".")
			if i == 0 {
				if !contains(tlds, rootDomain) {
					break
				}
			}
			lastRootDomain = rootDomain
			if contains(tlds, rootDomain) {
				continue
			} else {
				break
			}
		}
		if lastRootDomain != "" {
			newDomains = append(newDomains, lastRootDomain)
		}
	}
	return newDomains
}

func contains(s []string, e string) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func generatePacFast(domains []string, proxy string) string {
	buf, err := ioutil.ReadFile("resources/proxy.pac")
	if err != nil {
		panic(err.Error())
	}
	proxyContent := string(buf)
	var domainsMap map[string]int
	for _, domain := range domains {
		domainsMap[domain] = 1
	}
	bytes, err := json.Marshal(proxy)
	if err != nil {
		panic(err.Error())
	}
	proxyJs := string(bytes)
	bytes, err = json.Marshal(domainsMap)
	if err != nil {
		panic(err.Error())
	}
	domainsMapJs := string(bytes)
	proxyContent = strings.Replace(proxyContent, "__PROXY__", proxyJs, -1)
	proxyContent = strings.Replace(proxyContent, "__DOMAINS__", domainsMapJs, -1)
	return proxyContent
}

func generatePacPrecise(rules []string, proxy string) string {
	grepRule := func(rule string) string {
		if rule != "" {
			if strings.HasPrefix(rule, "!") {
				return ""
			}
			if strings.HasPrefix(rule, "[") {
				return ""
			}
		}
		return ""
	}
	filter := func(f func(r string) string, s []string) []string {
		var res []string
		for _, v := range s {
			if f(v) != "" {
				res = append(res, v)
			}
			continue
		}
		return res
	}
	buf, err := ioutil.ReadFile("resources/abp.js")
	if err != nil {
		panic(err.Error())
	}
	proxyContent := string(buf)
	rules = filter(grepRule, rules)
	bytes, err := json.Marshal(proxy)
	if err != nil {
		panic(err.Error())
	}
	proxyJs := string(bytes)
	bytes, err = json.Marshal(rules)
	if err != nil {
		panic(err.Error())
	}
	rulesJs := string(bytes)
	proxyContent = strings.Replace(proxyContent, "__PROXY__", proxyJs, -1)
	proxyContent = strings.Replace(proxyContent, "__RULES__", rulesJs, -1)
	return proxyContent
}

func main() {
	parseArgs()
	fmt.Printf("%v %T", input, input)
}
