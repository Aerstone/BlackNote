package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"html/template"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var resourceDir = flag.String("r", "./resources", "Directory to pull resources from")
var templateFile = flag.String("t", "./templates/index.html", "Template for index page")
var disableHTTPS = flag.Bool("I", false, "Disable TLS")
var tlsCert = flag.String("c", "./server.crt", "TLS crt file")
var tlsKey = flag.String("k", "./server.key", "TLS crt key file")
var listenAddress = flag.String("l", ":8443", "Listening string (format in $IP:$PORT)")
var logOut = flag.String("o", "", "File to log to, empty means STDOUT")
var logSyslog = flag.Bool("q", false, "Log to syslog as well")
var baseURL = flag.String("b", "/", "Base URL to use for the application")
var sqlitePath = flag.String("s", "./blacknote.db", "Path for sqlite storage")
var logger *log.Logger
var syslogger *log.Logger
var db *sql.DB

// Variables for template generation in BlackNote
type Paste struct {
	BaseURL    string
	Ciphertext string
	Type       string
	Home       string
}

// Initialize database based on the sqlitePath command flag or ./blacknote.db
// and fix permissions
func initDB(path string) error {
	var err error
	db, err = sql.Open("sqlite3", path)
	if err != nil || db == nil {
		return err
	}
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS pastes(Id TEXT NOT NULL PRIMARY KEY, Ciphertext TEXT NOT NULL, InsertTime DATETIME)")
	if err != nil {
		return err
	}
	err = os.Chmod(path, 0600)
	if err != nil {
		return err
	}
	return nil
}

// Insert a new paste into the database, This is unsafe to call directly
// (always ensure that validation happens before calling this function)
func insertDB(id, ciphertext string) error {
	stmt, err := db.Prepare("INSERT INTO pastes(Id, Ciphertext, InsertTime) values(?,?,CURRENT_TIMESTAMP)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(id, ciphertext)
	if err != nil {
		return err
	}
	return nil
}

// Retrieve a new paste from the database. This is unsafe to call directly
// (always ensure that validation happens before calling this function)
func getPasteDB(id string) (string, error) {
	var ct string
	rows, err := db.Query("SELECT Ciphertext FROM pastes WHERE Id = ?", id)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&ct)
		if err != nil || ct == "" {
			return "", errors.New("paste could not be retrieved from the database")
		}
		return ct, nil
	}
	return "", err
}

// Remove a paste from the database. This is unsafe to call directly
// (always ensure that validation happens before calling this function)
func delPasteDB(id string) error {
	stmt, err := db.Prepare("DELETE FROM pastes WHERE Id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	r, err := stmt.Exec(id)
	if err != nil {
		return err
	}
	res, err := r.RowsAffected()
	if err != nil || res < 1 {
		return errors.New("could not delete from database")
	}
	return err
}

// Log error messages
func logError(ef error) {
	logger.Print(ef.Error)
	if *logSyslog {
		syslogger.Print(ef.Error)
	}
}

// Log informational messages
func logMessage(st string) {
	logger.Print(st)
	if *logSyslog {
		syslogger.Print(st)
	}
}

// Generate a unique identifier for a paste. Uses a 16 byte CSPRNG rand
// (similar to UUIDv4) that is hashed and truncated. Eventually this should be
// a UUID.
func genUID() string {
	b := make([]byte, 16) //TODO rate limit to prevent exhaustion?
	_, err := rand.Read(b)
	if err != nil {
		logError(err)
		panic("Could not get random!")
	}
	c := sha256.Sum256(b)
	return hex.EncodeToString(c[:16])
}

func getTemplate(w http.ResponseWriter, page string) *template.Template {
    var validPage = regexp.MustCompile("[^A-Za-z0-9]")
    m := validPage.MatchString(page)
    if m == true {
        http.Error(w, "An error occured", 500)
        logMessage(fmt.Sprintf("Render received an invalid file name: %s\n", page))
        page = "notfound"
    }

    t, err := template.ParseFiles("templates/"+page+".html","templates/base.html")
	if err != nil {
		logError(err)
	}
    return t
}

// Render page
func renderCiphertext(w http.ResponseWriter, page string, ciphertext string){
    var t = getTemplate(w, page)
    var home = ""
    if *baseURL != "" {
        home = *baseURL
    }
    var err = t.ExecuteTemplate(w, "base", Paste{BaseURL: *baseURL, Type: "notfound", Home: home, Ciphertext: ciphertext})
	if err != nil {
		logError(err)
	}
}

func render(w http.ResponseWriter, page string){
    var t = getTemplate(w, page)
    var home = ""
    if *baseURL != "" {
        home = *baseURL
    }
	var err = t.ExecuteTemplate(w, "base", Paste{BaseURL: *baseURL, Home: home})
	if err != nil {
		logError(err)
	}
}

// Handler for creating a paste (the index)
func createHandler(w http.ResponseWriter, r *http.Request) {
	if strings.TrimPrefix(r.URL.Path, *baseURL) != "/" {
		errorHandler(w, r, http.StatusNotFound)
		return
	}
    render(w, "create")
}

// Handler for creating a paste (the index)
func infoHandler(w http.ResponseWriter, r *http.Request) {
	if strings.TrimPrefix(r.URL.Path, *baseURL) != "/i" {
		errorHandler(w, r, http.StatusNotFound)
		return
	}
    render(w, "info")
}

// Validation regexes for paths and URL compatible base64
var validPath = regexp.MustCompile("^.*" + *baseURL + "s/[A-Fa-f0-9]{32}$")
var validBase64 = regexp.MustCompile("^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}==|[A-Za-z0-9-_]{3}=)?$")

// Handler for all errors
func errorHandler(w http.ResponseWriter, r *http.Request, status int) {
	w.WriteHeader(status)
	if status == http.StatusNotFound {
        render(w, "notfound")
	}
}

// Handler for generating a paste and viewing the paste based on HTTP methods.
// A GET request with a UID following the /s/ path will retrieve a paste from
// the database. A POST with the 'ciphertext' variable set will be validated,
// a UID will be generated, inserted into the database.
func secretHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		for _, c := range r.Form["ciphertext"] {
			if validBase64.MatchString(c) == false {
				http.Error(w, "Not valid ciphertext", 500)
				logMessage(fmt.Sprintf("Invalid ciphertext from %s\n", r.RemoteAddr))
				return
			}
			uid := genUID()
			err := insertDB(uid, c)
			logMessage("created paste " + uid + " from " + r.RemoteAddr)
			if err != nil {
				logError(err)
			}
			fmt.Fprintf(w, uid)
		}
	default:
		m := validPath.MatchString(r.URL.Path)
		if m == false {
			errorHandler(w, r, http.StatusNotFound)
			logMessage(fmt.Sprintf("Invalid path from %s\n", r.RemoteAddr))
			return
		}
		id := strings.Split(r.URL.Path, "/s/")[1]
		paste, err := getPasteDB(id)
		if err != nil {
			logError(err)
		} else {
			logMessage("retrieved paste " + id + " from " + r.RemoteAddr)
			delPasteDB(id)
			logMessage("deleted paste " + id)
			if err != nil {
				logError(err)
			}

            renderCiphertext(w, "read", string(paste))
		}
	}
}

func main() {
	flag.Parse()
	if *logOut == "" {
		logger = log.New(os.Stderr, "blacknote: ", log.Lshortfile|log.LstdFlags)
	} else {
		logfile, err := os.OpenFile(*logOut, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
		logger = log.New(logfile, "blacknote: ", log.Lshortfile|log.LstdFlags)
	}
	if *logSyslog {
		var err error
		syslogger, err = syslog.NewLogger(syslog.LOG_INFO, log.LstdFlags)
		if err != nil {
			panic(err)
		}
	}
	err := initDB(*sqlitePath)
	if err != nil {
		panic(err)
	}
	*baseURL = strings.TrimSuffix(*baseURL, "/")
	logMessage("initialized")
	http.HandleFunc(*baseURL+"/", createHandler)
	http.HandleFunc(*baseURL+"/i", infoHandler)
	http.HandleFunc(*baseURL+"/s/", secretHandler)
	http.Handle(*baseURL+"/r/", http.StripPrefix(*baseURL+"/r/", http.FileServer(http.Dir(*resourceDir))))
	if *disableHTTPS {
		err := http.ListenAndServe(*listenAddress, nil)
		logMessage("running in insecure mode")
		if err != nil {
			logError(err)
		}
	} else {
		err := http.ListenAndServeTLS(*listenAddress, *tlsCert, *tlsKey, nil)
		if err != nil {
			logError(err)
		}
	}
}
