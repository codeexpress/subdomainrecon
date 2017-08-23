all:
	GOOS=windows GOARCH=386 go build -o binaries/subdomainrecon-x86.exe subdomainrecon.go
	GOOS=windows GOARCH=amd64 go build -o binaries/subdomainrecon-x64.exe subdomainrecon.go
	GOOS=linux GOARCH=386 go build  -o binaries/subdomainrecon-x86 subdomainrecon.go
	GOOS=linux GOARCH=amd64 go build -o binaries/subdomainrecon-x64 subdomainrecon.go


