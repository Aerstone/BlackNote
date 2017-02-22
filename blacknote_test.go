package main

import (
	"os"
	"regexp"
	"testing"
)

func init() {

}

func TestValidPath(t *testing.T) {
	gtests := []string{"/s/8b7b1ab80027dedd3a5203e4c3be6775",
		"blacknote/s/8b7b1ab80027dedd3a5203e4c3be6775",
		"blacknote/a/b/c/d/s/8b7b1ab80027dedd3a5203e4c3be6775",
	}
	btests := []string{"/s/8b7b1ab8002",
		"/s/8b7b1ab80027dedd3a5203e4c3be6775a",
		"/s/8b7b1ab80027dedd3a5203e4c3be6775/",
		"/s/8b7b1ab80027dedd3a5203e4c3be6775/a",
		"blacknote/s/8b7b1ab80027dedd!a5203e4c3be6775",
	}
	for _, gt := range gtests {
		if !regexp.MustCompile("^.*s/[A-Fa-f0-9]{32}$").MatchString(gt) {
			t.Error("test failed for good path check of ", gt)
		}
	}
	for _, bt := range btests {
		if regexp.MustCompile("^.*s/[A-Fa-f0-9]{32}$").MatchString(bt) {
			t.Error("test failed for bad path check of ", bt)
		}
	}
}

func TestValidBase64(t *testing.T) {
	var pairs = []string{
		// RFC 4648 examples
		"",
		"Zg==",
		"Zm8=",
		"Zm9v",
		"Zm9vYg==",
		"Zm9vYmE=",
		"Zm9vYmFy",
	}
	for _, tp := range pairs {
		if !regexp.MustCompile("^(?:[A-Za-z0-9-_]{4})*(?:[A-Za-z0-9-_]{2}==|[A-Za-z0-9-_]{3}=)?$").MatchString(tp) {
			t.Error("valid test for base64 failed: ", tp)
		}
	}
}

func TestGenUID(t *testing.T) {
	tuid := genUID()
	if !regexp.MustCompile("^[A-Fa-f0-9]{32}$").MatchString(tuid) {
		t.Error("expected", "only hex characters of length 32", "got", tuid)
	}
}

func TestDB(t *testing.T) {
	err := initDB("./test.db")
	if err != nil {
		t.Error("database could not be initialized:", err)
	}
	err = insertDB("8b7b1ab80027dedd3a5203e4c3be6775a", "Zm9vYmE=")
	if err != nil {
		t.Error("database could not be inserted into:", err)
	}
	tv, err := getPasteDB("8b7b1ab80027dedd3a5203e4c3be6775a")
	if err != nil {
		t.Error("database info could not be retrieved:", err)
	}
	if tv != "Zm9vYmE=" {
		t.Error("database retrieved incorrect information:", err)
	}
	err = delPasteDB("8b7b1ab80027dedd3a5203e4c3be6775a")
	if err != nil {
		t.Error("database info could not be deleted:", err)
	}
	err = os.Remove("./test.db")
	if err != nil {
		t.Error("database could not be removed:", err)
	}
	err = insertDB("8b7b1ab80027dedd3a5203e4c3be6775a", "Zm9vYmE=")
	if err == nil {
		t.Error("database could not be inserted into:", err)
	}
	tv, err = getPasteDB("8b7b1ab80027dedd3a5203e4c3be6775a")
	if err == nil && tv != "" {
		t.Error("database info could not be retrieved:", err)
	}
	err = delPasteDB("8b7b1ab80027dedd3a5203e4c3be6775a")
	if err == nil {
		t.Error("database info could not be deleted:", err)
	}
}
