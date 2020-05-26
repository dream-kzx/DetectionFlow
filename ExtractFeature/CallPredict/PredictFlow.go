package CallPredict

import (
	"FlowDetection/flowFeature"
	"context"
	"google.golang.org/grpc"
	"log"
	"time"
)

type PredictFlow struct {
	conn   *grpc.ClientConn
	client PredictFlowClient
}

func NewPredictFlow(address string) *PredictFlow {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	client := NewPredictFlowClient(conn)
	return &PredictFlow{
		conn:   conn,
		client: client,
	}
}

func (p *PredictFlow) Predict(feature *flowFeature.FlowFeature) uint32 {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Second)
	defer cancel()
	request := flowFeatureToRequest(feature)
	label, err := p.client.Predict(ctx, request)
	if err != nil {
		log.Fatalf("could not greet: %v", err)
	}
	// log.Printf("predict:%d", label.Label)
	return label.Label
}

func (p *PredictFlow) close() {
	defer p.conn.Close()
}

func flowFeatureToRequest(feature *flowFeature.FlowFeature) *Request {
	return &Request{
		Duration:               uint32(feature.Duration),
		ProtocolType:           feature.ProtocolType,
		Service:                uint32(feature.Service),
		Flag:                   feature.Flag,
		SrcBytes:               uint32(feature.SrcBytes),
		DstBytes:               uint32(feature.DstBytes),
		Land:                   uint32(feature.Land),
		WrongFragment:          uint32(feature.WrongFragment),
		Urgent:                 uint32(feature.Urgent),
		Host:                   uint32(feature.Host),
		NumFailedLogins:        uint32(feature.NumFailedLogins),
		LoggedIn:               uint32(feature.LoggedIn),
		NumCompromised:         uint32(feature.NumCompromised),
		RootShell:              uint32(feature.RootShell),
		SuAttempted:            uint32(feature.SuAttempted),
		NumRoot:                uint32(feature.NumRoot),
		NumFileCreations:       uint32(feature.NumFileCreations),
		NumShells:              uint32(feature.NumShells),
		NumAccessFiles:         uint32(feature.NumAccessFiles),
		NumOutboundCmds:        uint32(feature.NumOutboundCmds),
		IsHotLogin:             uint32(feature.IsHotLogin),
		IsGuestLogin:           uint32(feature.IsGuestLogin),
		Count:                  uint32(feature.Count),
		SrvCount:               uint32(feature.SrvCount),
		SErrorRate:             feature.SErrorRate,
		SrvSErrorRate:          feature.SrvSErrorRate,
		RErrorRate:             feature.RErrorRate,
		SrvRErrorRate:          feature.SrvRErrorRate,
		SameSrvRate:            feature.SameSrvRate,
		DiffSrvRate:            feature.DiffSrvRate,
		SrvDiffHostRate:        feature.SrvDiffHostRate,
		DstHostCount:           uint32(feature.DstHostCount),
		DstHostSrvCount:        uint32(feature.DstHostSrvCount),
		DstHostSameSrvRate:     feature.DstHostSameSrvRate,
		DstHostDiffSrvRate:     feature.DstHostDiffSrvRate,
		DstHostSameSrcPortRate: feature.DstHostSameSrcPortRate,
		DstHostSrvDiffHostRate: feature.DstHostSrvDiffHostRate,
		DstHostSErrorRate:      feature.DstHostSErrorRate,
		DstHostSrvSErrorRate:   feature.DstHostSrvSErrorRate,
		DstHostRErrorRate:      feature.DstHostRErrorRate,
		DstHostSrvRErrorRate:   feature.DstHostSrvRErrorRate,
	}
}
