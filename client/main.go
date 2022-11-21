package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"

	"cloud.google.com/go/pubsub"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const ()

var (
	projectID = flag.String("projectID", "fabled-ray-104117", "ProjectID")
)

func main() {

	flag.Parse()
	ctx := context.Background()

	pemServerCA, err := ioutil.ReadFile("../certs/tls-ca-chain.pem")
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		panic(err)
	}

	config := &tls.Config{
		RootCAs:    certPool,
		ServerName: "pubsub.googleapis.com",
	}

	tlsCredentials := credentials.NewTLS(config)

	client, err := pubsub.NewClient(ctx, *projectID, option.WithEndpoint("localhost:8081"), option.WithGRPCDialOption(
		grpc.WithTransportCredentials(tlsCredentials),
	))
	if err != nil {
		panic(err)
	}
	defer client.Close()

	//ctx = metadata.AppendToOutgoingContext(ctx, "x-goog-allowed-resources", allow)

	it := client.Topics(ctx)
	for {
		topic, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			panic(err)
		}
		fmt.Printf("%v\n", topic.ID())
	}

}
