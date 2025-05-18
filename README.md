# vbasig - Signing VBA in Golang  
This project can be used as a module to experiment with VBA signatures or to sign VBA projects for the most common Microsoft Office applications (Excel, Word, PowerPoint). It should be seen as a (working) proof of concept, and the code could still benefit from a number of improvements (refactoring, unit tests etc.).  
  
## Usage ##  
As command line tool:  
<pre>
Usage of vbasig.exe:
  -c string
        certificate for signing (.crt)
  -f string
        file to sign (.xlsm, .docm, .pptm)
  -i string
        (optional) issuing certificate (.pem)
  -s string
        private key for signing (.key)
</pre>
As import:
```go
package main

import (
	"github.com/coffeeforyou/vbasig/vbaproject"
)

func main() {
	so := vbaproject.SignOptions{
		IncludeV1:    true, // add 'legacy' signature
		IncludeAgile: true, // add agile signature
		IncludeV3:    true, // add V3 signature
	}
	vbaproject.SignVbaProject("./Book1.xlsm", "./mycert.crt", "mykey.key", "myca.pem", so)
}
```
## Dependencies ##  
The code relies on github.com/richardlehane/mscfb to parse the OLE/CFB file format of vbaProject.bin. A fork of github.com/mozilla-services/pkcs7 has been included with modifications required for VBA code signing (e.g., bringing back MD5).
