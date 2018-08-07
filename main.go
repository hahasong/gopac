package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"./lib/json"

	flag "github.com/spf13/pflag"
)

const (
	// GfwlistURL raw url
	GfwlistURL = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
	// TldsURL raw url. or https://publicsuffix.org/list/effective_tld_names.dat
	TldsURL = "https://publicsuffix.org/list/public_suffix_list.dat"
)

var (
	input, output, proxy string
	userRule             string
	precise, tld         bool
)

func parseArgs() {
	flag.StringVarP(&input, "input", "i", "", "path to gfwlist")
	flag.StringVarP(&output, "file", "f", "proxy.pac", "path to output pac")
	flag.StringVarP(&proxy, "proxy", "p", "SOCKS5 127.0.0.1:1080; SOCKS 127.0.0.1:1080; DIRECT", "the proxy parameter in the pac file, \nfor example, \"SOCKS5 127.0.0.1:1080;\"")
	flag.StringVarP(&userRule, "user-rule", "", "", "user rule file, which will be appended to\n gfwlist")
	flag.BoolVarP(&precise, "precise", "", false, "use adblock plus algorithm instead of O(1)\n lookup")
	flag.BoolVarP(&tld, "tld", "", false, "force updating tld list, best no more than\n once per month")
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
	if !strings.HasPrefix(something, "http:") && !strings.HasPrefix(something, "https:") {
		something = "http://" + something
	}
	u, err := url.Parse(something)
	if err != nil {
		log.Println(err.Error())
		return ""
	}
	return u.Hostname()
}

func addDomainToSet(s *[]string, something string) {
	hostName := getHostname(something)
	if hostName != "" {
		*s = append(*s, hostName)
	}
}

func combineLists(content string, userRule string) []string {
	buf, err := ioutil.ReadFile("resources/builtin.txt")
	if err != nil {
		panic(err.Error())
	}
	builtinRules := strings.Split(string(buf), "\n")
	gfwlist := strings.Split(content, "\n")
	gfwlist = append(gfwlist, builtinRules...)

	if userRule != "" {
		userRule := strings.Split(userRule, "\n")
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
			line = strings.TrimPrefix(line, "||")
		} else if strings.HasPrefix(line, "|") {
			line = strings.TrimPrefix(line, "|")
		} else if strings.HasPrefix(line, ".") {
			line = strings.TrimPrefix(line, ".")
		}
		if strings.HasPrefix(line, "!") {
			continue
		} else if strings.HasPrefix(line, "[") {
			continue
		} else if strings.HasPrefix(line, "@") {
			continue
		}
		addDomainToSet(&domains, line)
	}
	return domains
}

func reduceDomains(domains []string) []string {
	tlds := getTldList()
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
	domainsMap := map[string]int{}
	for _, domain := range domains {
		domainsMap[domain] = 1
	}
	bytes, err := json.Marshal(proxy)
	if err != nil {
		panic(err.Error())
	}
	proxyJs := string(bytes)
	bytes, err = json.MarshalIndent(domainsMap, "", "    ")
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
			return rule
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
	bytes, err = json.MarshalIndent(rules, "", "    ")
	if err != nil {
		panic(err.Error())
	}
	rulesJs := string(bytes)
	proxyContent = strings.Replace(proxyContent, "__PROXY__", proxyJs, -1)
	proxyContent = strings.Replace(proxyContent, "__RULES__", rulesJs, -1)
	return proxyContent
}

func checkError(err error) {
	if err != nil {
		panic(err.Error())
	}
}

func getTldList() []string {
	filepath := "resources/public_suffix_list.dat"
	if _, err := os.Stat(filepath); os.IsNotExist(err) || tld {
		out, err := os.Create(filepath)
		checkError(err)
		defer out.Close()

		fmt.Printf("Downloading TLD list from %s\n", TldsURL)
		res, err := http.Get(TldsURL)
		checkError(err)
		defer res.Body.Close()

		_, err = io.Copy(out, res.Body)
		checkError(err)
	}
	buf, err := ioutil.ReadFile(filepath)
	checkError(err)
	var list []string
	tlds := strings.Split(string(buf), "\n")
	for _, line := range tlds {
		if len([]rune(line)) < 1 || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "*.") {
			line = strings.TrimLeft(line, "*.")
		}
		if strings.HasPrefix(line, "!") {
			continue
		}
		list = append(list, line)
	}
	err = ioutil.WriteFile("resources/tld.txt", []byte(strings.Join(list, "\n")), 0644)
	checkError(err)
	return list
}

func main() {
	parseArgs()
	t1 := time.Now()
	var content, pacContent string
	if input != "" {
		buf, err := ioutil.ReadFile(input)
		checkError(err)
		content = string(buf)
	} else {
		fmt.Printf("Downloading gfwlist from %s\n", GfwlistURL)
		res, err := http.Get(GfwlistURL)
		checkError(err)
		data, err := ioutil.ReadAll(res.Body)
		checkError(err)
		content = string(data)
	}

	if userRule != "" {
		u, err := url.Parse(userRule)
		if err != nil {
			log.Println(err.Error())
		}
		if u.Scheme == "" || u.Opaque == "" {
			buf, err := ioutil.ReadFile(userRule)
			checkError(err)
			userRule = string(buf)
		} else {
			fmt.Printf("Downloading user rules file from %s\n", userRule)
			res, err := http.Get(userRule)
			checkError(err)
			data, err := ioutil.ReadAll(res.Body)
			checkError(err)
			userRule = string(data)
		}
	}
	content = decodeGfwlist(content)
	gfwlist := combineLists(content, userRule)
	if precise {
		pacContent = generatePacPrecise(gfwlist, proxy)
	} else {
		domains := parseGfwlist(gfwlist)
		domains = reduceDomains(domains)
		pacContent = generatePacFast(domains, proxy)
	}
	err := ioutil.WriteFile(output, []byte(pacContent), 0644)
	checkError(err)
	elapsed := time.Since(t1)
	fmt.Printf("Generate %s successful in %s\n", output, elapsed)
}
