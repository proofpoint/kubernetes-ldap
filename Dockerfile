FROM golang:1.8.0
WORKDIR /go/src/github.com/rajatjindal83/kubernetes-ldap/

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/kubernetes-ldap .

WORKDIR /opt/
RUN cp /go/src/github.com/rajatjindal83/kubernetes-ldap/bin/kubernetes-ldap .
ENTRYPOINT ["./kubernetes-ldap"]
