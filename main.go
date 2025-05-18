package main

import (
	"flag"

	"github.com/coffeeforyou/vbasig/vbaproject"
)

func main() {
	officeFilePath := flag.String("f", "", "file to sign (.xlsm, .docm, .pptm)")
	certPath := flag.String("c", "", "certificate for signing (.crt)")
	keyPath := flag.String("s", "", "private key for signing (.key)")
	caPath := flag.String("i", "", "(optional) issuing certificate (.pem)")
	flag.Parse()
	if *officeFilePath == "" || *certPath == "" || *keyPath == "" {
		flag.Usage()
		return
	}
	so := vbaproject.SignOptions{
		IncludeV1:    false,
		IncludeAgile: false,
		IncludeV3:    true}
	vbaproject.SignVbaProject(*officeFilePath, *certPath, *keyPath, *caPath, so)
}
