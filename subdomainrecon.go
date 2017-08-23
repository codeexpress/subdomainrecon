package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	xmlpath "gopkg.in/xmlpath.v2"
)

const Version = "1.0.0"

const (
	UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.96 Safari/537.36"
)

type searchEngineAttributes struct {
	baseUrl string
	xpath   string
	regex   string
}

var (
	// logger variables
	Trace   *log.Logger
	Info    *log.Logger
	Warning *log.Logger
	Error   *log.Logger

	//argument flags
	domainPtr     *string
	outputFilePtr *string
	logPtr        *int

	// application variables
	searchEngines = map[string]searchEngineAttributes{
		"Google": {
			baseUrl: "https://www.google.com/search?num=100",
			xpath:   "//*[@id='rso']/div/div/div[*]/div/div/h3/a/@href",
			regex:   "^(?:https?://)?(?:[^@\n]+@)?([^:/\n]+)",
		},
		"Yahoo": {
			baseUrl: "https://search.yahoo.com/search?n=100",
			xpath:   "//*[@id='web']/ol/li[*]/div/div/div/span",
			regex:   "^(?:https?://)?(?:[^@\n]+@)?([^:/\n]+)",
		},
		"Bing": {
			baseUrl: "https://www.bing.com/search?count=100",
			xpath:   "//*[@id='b_results']/li[*]/h2/a/@href",
			regex:   "^(?:https?://)?(?:[^@\n]+@)?([^:/\n]+)",
		},
	}
)

// properties of a subdomain
type properties struct {
	ip     string
	source []string
}

var Subdomains map[string]properties

func main() {
	domain := initFlags()

	initLogger()

	logIt("Searching subdomains for domain: "+domain+" ... ", 1, true)

	Subdomains = make(map[string]properties) // init global map

	// Method 1: Fetch from virustotal
	subDomainsFromVirusTotal(domain)

	// Method 2: Fetch from search engine (google, yahoo, bing) results
	subDomainsFromSearchEngines(domain)

	displaySubdomains()
}

func subDomainsFromVirusTotal(domain string) {
	url := "https://virustotal.com/en/domain/" + domain + "/information/"

	logIt("Fetching from Virus Total...", 1, true)

	xpath := "//*[@id='observed-subdomains']/div"
	regex := ""
	subdomains := extractSubDomainsFromUrl(url, xpath, regex)

	logIt(subdomains, 1)
	merge(subdomains, "Virus Total")

	// // If virusTotal brings up a captcha, it is in the following xpath
	// xpath := "/html/body/p"
	// path := xmlpath.MustCompile(xpath)
	// pHtml, _ := path.String(html)
	// // if pHtml contains word captch, we got a captcha screen
	// if strings.Contains(pHtml, "captcha") {
	// 	fmt.Println("VirusTotal presented a captcha screen. Click here to get around this error.")
	// 	return subdomains
	// }
}

func subDomainsFromSearchEngines(domain string) {
	// run the scraping algorithm for each searchengine
	for searchEngineName, attributes := range searchEngines {
		url := attributes.baseUrl + "&q=site:" + domain + "+-site:www." + domain

		logIt("Fetching from "+searchEngineName+": ROUND I", 1)
		subdomains := extractSubDomainsFromUrl(url, attributes.xpath, attributes.regex)

		logIt("First round of "+searchEngineName+" search returned "+
			strconv.Itoa(len(subdomains))+" subdomains", 1)
		/* Trial 2:
		   After a first run, second run is done with a bunch of common subdomains negated
		   in the query so that we can get more uncommon ones as well
		*/
		if len(subdomains) != 0 {
			mostCommon := getMostCommon(subdomains)
			count := 0
			exclusion := ""
			for _, sd := range mostCommon {
				count += 1
				if sd != domain {
					exclusion += "+-site:" + sd
				}
				if count >= 20 { //exclude only 20 or the query will become too long
					break
				}
			}
			fullUrl := url + exclusion

			logIt("Fetching from "+searchEngineName+": ROUND II", 1)

			newsubdomains := extractSubDomainsFromUrl(fullUrl, attributes.xpath, attributes.regex)

			logIt("Second round of "+searchEngineName+" search returned "+
				strconv.Itoa(len(newsubdomains))+" subdomains", 1)

			for sd, num := range newsubdomains {
				subdomains[sd] = num // add new subdomains found to the first map
			}
		}
		merge(subdomains, searchEngineName)
	} // end for range searchengines
} // end func subDomainsFromSearchEngines

/* Params:
   url   - URL of the page listing subdomains
   xpath - the xpath(s) in html document where to find the URL/subdomain
   regex - the regex to be applied to the URL string found at xpath to extract subdomain name
   returns:
   a map[string]int of subdomains along with number of occurance
*/
func extractSubDomainsFromUrl(
	url string,
	xpath string,
	regex string) map[string]int {

	var sd string
	subdomains := make(map[string]int)

	logIt("Fetch from URL: "+url, 1)
	parsedHtml := fetchUrl(url) // returns a xmlpath.Node object
	path := xmlpath.MustCompile(xpath)
	iter := path.Iter(parsedHtml)

	subDomainRegex := regexp.MustCompile(regex)
	for iter.Next() {
		link := strings.TrimSpace(iter.Node().String())
		if link == "" {
			continue
		}
		logIt("Link Fetched: "+link, 2)
		if regex != "" {
			sd = subDomainRegex.FindStringSubmatch(link)[1]
		} else {
			sd = link
		}
		logIt("Extracted subdomain: "+sd, 2)
		subdomains[sd]++
	}
	return subdomains
}

// does a HTTP GET and returns the HTML body for that URL
func fetchUrl(url string) *xmlpath.Node {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	req.Header.Add("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	html, _ := ioutil.ReadAll(resp.Body)
	htmlStr := string(html)
	logIt(htmlStr, 3)
	parsedHtml, err := xmlpath.ParseHTML(strings.NewReader(htmlStr))
	if err != nil {
		panic(err)
	}
	return parsedHtml
}

/* Returns subdomains sorted from most occuring to least
   params:
   subdomains - a map of subdomains and their counts
   return:
   mostcommon - a slice of strings from most common items to least
*/
func getMostCommon(subdomains map[string]int) []string {
	var mostCommon []string
	reverseMap := map[int][]string{}
	var nums []int
	for sd, num := range subdomains {
		reverseMap[num] = append(reverseMap[num], sd)
	}
	for num := range reverseMap {
		nums = append(nums, num)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(nums)))

	for _, num := range nums {
		for _, sd := range reverseMap[num] {
			mostCommon = append(mostCommon, sd)
		}
	}
	return mostCommon
}

/*
  Display the subdomains in a legible manner
*/
func displaySubdomains() {
	logIt(Subdomains, 1)
	fmt.Printf("%-50s%-40s\n", "Subdomain", "Source")
	fmt.Println("=============================================================")
	for subdomain, attributes := range Subdomains {
		fmt.Printf("%-50s%v\n", subdomain, strings.Join(attributes.source, ", "))
	}
}

/* Add the new subdomains found to the global subdomains map
   params:
    newSubdomains - new subdomains found via some source
   return:
    none. Global subdomain map is modified
*/
func merge(newSubdomains map[string]int, source string) {
	newCount := 0
	for sd, _ := range newSubdomains {
		if sdProperties, ok := Subdomains[sd]; ok { // if this sd exists in the global map
			sdProperties.source = append(sdProperties.source, source)
			Subdomains[sd] = sdProperties
		} else {
			newCount += 1
			Subdomains[sd] = properties{source: []string{source}}
		}
	}
	logIt("Total subdomains discovered via "+source+": "+strconv.Itoa(len(newSubdomains))+". New: "+strconv.Itoa(newCount), 1, true)
}

/* Parse command line flage and initiaize the global flag variables */
func initFlags() string {

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "---------------------------------------------------------")
		fmt.Fprintln(os.Stderr, "Usage:   $ subdomainrecon -d <domain-name> [-o <filename.extension>] [-l 1]")
		fmt.Fprintln(os.Stderr, "Example: $ subdomainrecon -d example.org -o subdomains.json")
		fmt.Fprintln(os.Stderr, "---------------------------------------------------------\nFlags:")
		flag.PrintDefaults()
	}

	domainPtr = flag.String("d", "",
		`TLD Domain Name. eg. 'example.org'. Do NOT enter subdomains like 'ftp.example.org'`)

	outputFilePtr = flag.String("o", "",
		`Name of output file. eg. 'subdomains.json' The format can be on of json|html|txt|csv.
     Enter -o subdomains.json,html,csv to generate 3 output files in those 3 formats`)

	logPtr = flag.Int("l", 0,
		`Debug mode. This will create a verbose log file (run.log) with all request/responses.
                 -l 1 [least verbose]. -l 3 [max verbose]`)

	flag.Parse()

	// make sure domain name is of a form of a TLD eg. "example.com"
	tldRegex, _ := regexp.Compile("^([\\w-]+.[\\w-]+)$")
	domain := tldRegex.FindString(*domainPtr)

	if domain == "" {
		fmt.Println("Invalid domain, please use a TLD domain name with a -d flag")
		flag.Usage()
		os.Exit(0)
	}

	if *logPtr > 0 {
		fmt.Println("Logging to file run.log")
	}

	if *outputFilePtr == "" {
		fmt.Printf("No output file specified, ouputing to %s.txt\n", *domainPtr)
	} else {
		// CHECK:: Need to extract the format and set default format etc. here
		fmt.Printf("Outputing to %s.txt\n", *outputFilePtr)
	}

	return domain
} // end func initFlags

// Initializing the logger and customizing prefix
// Example logger: https://www.goinggo.net/2013/11/using-log-package-in-go.html
// Custom logger prefix: http://stackoverflow.com/a/26153081
func initLogger() {
	f, err := os.OpenFile("run.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	Info = log.New(f, "", 0)
	Info.SetPrefix("[" + time.Now().Format("02-Jan-2006 15:04:05 MST") + "]: ")
}

// Logs to log file
// takes generic object and then based on the type of object,
// logs is in appropriate style.
func logIt(val interface{}, level int, console ...bool) {
	// if console is passed, print to stdout as well
	if len(console) != 0 {
		fmt.Println(val)
	}

	// log only if the log level specified at the command line (logPtr)
	// is greater than the log significance (leve) of this log entry
	if *logPtr >= level {
		v := reflect.ValueOf(val)
		switch v.Kind() {
		case reflect.Map:
			str, _ := json.MarshalIndent(val, "", "  ")
			Info.Println(string(str))
		default:
			Info.Println(val)
		}
	}
}
