package CallPredict

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"testing"
	"time"
)

////protoc --go_out=plugins=grpc:. service.proto


func TestCallPredict(t *testing.T){
	conn, err := grpc.Dial(":50051",grpc.WithInsecure(),
		grpc.WithBlock())
	if err!=nil{
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := NewPredictFlowClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(),
		time.Second)
	defer cancel()
	r, err := c.Predict(ctx,&Request{
		Duration:               0,
		ProtocolType:           "tcp",
		Service:                0,
		Flag:                   0,
		SrcBytes:               0,
		DstBytes:               0,
		Land:                   0,
		WrongFragment:          0,
		Urgent:                 0,
		Host:                   0,
		NumFailedLogins:        0,
		LoggedIn:               0,
		NumCompromised:         0,
		RootShell:              0,
		SuAttempted:            0,
		NumRoot:                0,
		NumFileCreations:       0,
		NumShells:              0,
		NumAccessFiles:         0,
		NumOutboundCmds:        0,
		IsHotLogin:             0,
		IsGuestLogin:           0,
		Count:                  0,
		SrvCount:               0,
		SErrorRate:             0,
		SrvSErrorRate:          0,
		RErrorRate:             0,
		SrvRErrorRate:          0,
		SameSrvRate:            0,
		DiffSrvRate:            0,
		SrvDiffHostRate:        0,
		DstHostCount:           0,
		DstHostSrvCount:        0,
		DstHostSameSrvRate:     0,
		DstHostDiffSrvRate:     0,
		DstHostSameSrcPortRate: 0,
		DstHostSrvDiffHostRate: 0,
		DstHostSErrorRate:      0,
		DstHostSrvSErrorRate:   0,
		DstHostRErrorRate:      0,
		DstHostSrvRErrorRate:   0,
	})
	if err!=nil{
		log.Fatalf("could not greet: %v",err)
	}

	log.Printf("predict:%d", r.Label)

}