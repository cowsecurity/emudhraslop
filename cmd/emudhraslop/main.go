package main

import (
	"github.com/cowsecurity/emudhraslop/internal/app"
	"os"
)

func main() { os.Exit(app.Run(os.Args[1:], os.Stdout, os.Stderr)) }
