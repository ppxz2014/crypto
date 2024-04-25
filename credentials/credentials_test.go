package credentials

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"testing"

	"github.com/ppxz2014/crypto/credentials/echo"
	"github.com/ppxz2014/crypto/tls"
	"github.com/ppxz2014/crypto/x509"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

const (
	port    = ":50051"
	address = "localhost:50051"
)

var end chan bool

type server struct{}

func (s *server) Echo(ctx context.Context, req *echo.EchoRequest) (*echo.EchoResponse, error) {
	return &echo.EchoResponse{Result: req.Req}, nil
}

const caServerCrt = "testdata/gm/server/ca.crt"
const serverCrt = "testdata/gm/server/server.crt"
const serverKey = "testdata/gm/server/server.key"

const caClientCert = "testdata/gm/client/ca.crt"
const clientCrt = "testdata/gm/client/client.crt"
const clientKey = "testdata/gm/client/client.key"

func serverRun() {
	cert, err := tls.LoadX509KeyPair(serverCrt, serverKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(caClientCert)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)

	lis, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("fail to listen: %v", err)
	}

	creds := NewTLS(&tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates:       []tls.Certificate{cert},
		ClientCAs:          certPool,
	})
	s := grpc.NewServer(grpc.Creds(creds))
	echo.RegisterEchoServer(s, &server{})
	err = s.Serve(lis)
	if err != nil {
		log.Fatalf("Serve: %v", err)
	}
}

func clientRun() {
	cert, err := tls.LoadX509KeyPair(clientCrt, clientKey)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	cacert, err := ioutil.ReadFile(caServerCrt)
	if err != nil {
		log.Fatal(err)
	}
	certPool.AppendCertsFromPEM(cacert)
	creds := NewTLS(&tls.Config{
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "test.example.com",
		Certificates:       []tls.Certificate{cert},
		RootCAs:            certPool,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	})

	conn, err := grpc.Dial(address, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("cannot to connect: %v", err)
	}
	defer conn.Close()
	c := echo.NewEchoClient(conn)
	echoTest(c)
	end <- true
}

func echoTest(c echo.EchoClient) {
	r, err := c.Echo(context.Background(), &echo.EchoRequest{Req: "hello"})
	if err != nil {
		log.Fatalf("failed to echo: %v", err)
	}
	fmt.Printf("%s\n", r.Result)
}

func Test(t *testing.T) {
	end = make(chan bool, 64)
	go serverRun()
	go clientRun()
	<-end
}
