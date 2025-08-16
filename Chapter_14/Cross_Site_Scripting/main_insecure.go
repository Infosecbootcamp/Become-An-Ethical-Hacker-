package main

import (
	"log"
	"net/http"
	"text/template"
)

var page = `<html>
<head>
<title>Insecure Site Yall!</title>
</head>
<body>
   <h1>Put anything here I won't escape it!</h1>
   <h2> Your Input </h2>
   {{.Input}}
  <form action="/" method="post">
      Your Input:<input type="text" name="test_form">
      <input type="submit" value="Submit">
  </form>
</body>
</html>`

type pageData struct {
	pageTitle string
	Input     string
}

// create path handler for main page

func homePageHandler(w http.ResponseWriter, r *http.Request) {
	var userInput = &pageData{
		Input:     r.FormValue("test_form"),
		pageTitle: "beh",
	}
	emptyTemplate := template.New("beh_css")
	newTemplate, err := emptyTemplate.Parse(page)
	if err != nil {
		panic("error reading template data!")
	}
	err = newTemplate.Execute(w, userInput)
	if err != nil {
		panic("error reading template data!")
	}
}
func main() {
  // try to start TLS site if not then serve up non TLS on 8080
	http.HandleFunc("/", homePageHandler)
	err := http.ListenAndServeTLS(":8000", "csrfapp.crt", "csrfapp.key", nil)

	if err != nil {
		log.Print("can't start TLS site!")
		http.ListenAndServe(":8080", nil)
	}

}
