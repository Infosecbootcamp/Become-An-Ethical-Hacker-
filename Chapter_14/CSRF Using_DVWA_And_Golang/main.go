package main

import(
"fmt"
"net/http"
"log"
"html/template"


)


type pageData struct {
	pageTitle string
}

// check if you have anything else listening on 8000

func main() {
	http.HandleFunc("/", homepage)
	err := http.ListenAndServeTLS(":8000","csrfapp.crt","csrfapp.key", nil)
	if err != nil {
	   log.Fatal("can't start TLS site!")
	}

}

func homepage(w http.ResponseWriter, req *http.Request) {
	pd := pageData {
	   pageTitle: "home page",
	}
	buildpage(w, "templates/homepage.html", pd)	

}

func buildpage(w http.ResponseWriter, templateName string, pd pageData) {
	tmpl, err := template.ParseFiles(templateName)
	if err != nil {
	   fmt.Println("could not parse template named %s", templateName)
	}
	err = tmpl.Execute(w, pd)
	if err != nil {
	   fmt.Println("could not parse template named %s", templateName)
	}

}
