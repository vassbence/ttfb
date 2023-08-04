build: lambda/main.go
	cd lambda && GOOS=linux GOARCH=amd64 go build -o ../build/lambda main.go

deploy: build
	cd infrastructure && terraform apply --auto-approve

destroy:
	cd infrastructure &&  terraform destroy --auto-approve