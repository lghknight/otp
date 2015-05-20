// otp auto demo

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/gorilla/mux"
	"github.com/wheelcomplex/otp"
)

func authAPI(req *http.Request) map[string]interface{} {
	res := make(map[string]interface{})
	res["code"] = 0
	o := new(otp.OTPzc)
	if req.ParseForm() != nil {
		res["code"] = -1
		return res
	}
	if req.FormValue("user") == "" || req.FormValue("passwd") == "" || req.FormValue("code") == "" {
		res["code"] = -2
	}
	a, err := o.OTPAuth(req.FormValue("user"), "passwd", req.FormValue("code"), otp.C200) //暂时写成C200，可用请求参数指定
	if err != nil {
		res["code"] = a
		res["msg"] = err.Error()
	}
	//log.Println("Code=",a)
	return res
}

func OTPAuthHandler(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
			w.WriteHeader(500)
			return
		}
	}()
	var response map[string]interface{}
	var jsonpCallback string
	if _, ok := req.URL.Query()["$callback"]; ok {
		jsonpCallback = req.URL.Query()["$callback"][0]
	}

	if req.URL.Path == "/otp/auth" {
		response = authAPI(req)
	} else if req.URL.Path == "/otp/sync" {
		//response = otp.SyncAPI(req)
	}
	bytes, e := json.Marshal(response)
	if e != nil {
		http.Error(w, "Error marshalling JSON", http.StatusInternalServerError)
		return
	}
	if jsonpCallback != "" {
		fmt.Fprintf(w, jsonpCallback+"("+string(bytes)+")")
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	}
}

func main() {
	var dbfile = flag.String("db", "seed.db", "seed db file")
	flag.Parse()
	if len(*dbfile) == 0 {
		log.Println("Usage: demo -db <seed db file>")
		os.Exit(1)
	}
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
		//panic后持久化数据
		otp.SeedSave(*dbfile)
	}()
	runtime.GOMAXPROCS(runtime.NumCPU() - 1)

	go func() {
		log.Println(http.ListenAndServe(":6060", nil))
	}()

	otp.SeedOpen(*dbfile)

	log.SetFlags(log.Lshortfile | log.LstdFlags)
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signalChannel
		switch sig {
		case os.Interrupt:
			otp.SeedSave(*dbfile)
			os.Exit(-9)
			//处理一些收尾工作，如auth信息写入存储
		}
	}()
	router := mux.NewRouter()
	router.PathPrefix("/otp/").HandlerFunc(OTPAuthHandler)
	http.Handle("/", router)
	err := http.ListenAndServe("0.0.0.0:22288", nil)
	if err != nil {
		log.Println(err.Error())
	}
}
