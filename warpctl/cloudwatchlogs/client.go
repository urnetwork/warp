package cloudwatchlogs

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Client struct {
	outLog *log.Logger
	errLog *log.Logger
	cl *cloudwatchlogs.Client
	stsClient *sts.Client
}

const deploymentBlocksTableName = "deployment-blocks"

func NewClient(outLog *log.Logger, errLog *log.Logger) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-west-1"))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config, %v", err)
	}

	cl := cloudwatchlogs.NewFromConfig(cfg)

	stsClient := sts.NewFromConfig(cfg)

	return &Client{
		outLog: outLog,
		errLog: errLog,
		cl: cl,
		stsClient: stsClient,
	}, nil

}

func (c *Client) accountId(ctx context.Context) (string, error) {
	idOut, err := c.stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}

	return *idOut.Account, nil
}

func (c *Client) LiveTail(ctx context.Context, env string, service string, blocks []string, query string) error {
	accountId, err := c.accountId(ctx)
	if err != nil {
		return err
	}
	var filterPattern *string
	if 0 < len(query) {
		filterPattern = aws.String(fmt.Sprintf("%q", query))
	}
	var logStreamNames []string
	if 0 < len(blocks) {
		logStreamNames = blocks
	}
	out, err := c.cl.StartLiveTail(ctx, &cloudwatchlogs.StartLiveTailInput{
		LogGroupIdentifiers: []string{
			fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s-%s", "us-west-1", accountId, env, service),
		},
		LogStreamNames: logStreamNames,
		LogEventFilterPattern: filterPattern,
	})
	if err != nil {
		return err
	}

	stream := out.GetStream()
	defer stream.Close()
	events := stream.Events()
	for {
		select {
		case <- ctx.Done():
			return nil
		case event, ok := <- events:
			if !ok {
				return nil
			}
			switch v := event.(type) {
			case *types.StartLiveTailResponseStreamMemberSessionUpdate:
				for _, e := range v.Value.SessionResults {
					c.outLog.Printf("[%s][%s]%s\n", *e.LogStreamName, time.UnixMilli(*e.Timestamp), *e.Message)
				}

			}
		}
	}

	return nil
}

func (c *Client) Search(ctx context.Context, env string, service string, blocks []string, query string, since time.Duration) error {
	accountId, err := c.accountId(ctx)
	if err != nil {
		return err
	}
	var filterPattern *string
	if 0 < len(query) {
		filterPattern = aws.String(fmt.Sprintf("%q", query))
	}
	var logStreamNames []string
	if 0 < len(blocks) {
		logStreamNames = blocks
	}
	out, err := c.cl.FilterLogEvents(ctx, &cloudwatchlogs.FilterLogEventsInput{
		LogGroupIdentifier: aws.String(fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s-%s", "us-west-1", accountId, env, service)),
		LogStreamNames: logStreamNames,
		FilterPattern: filterPattern,
		Interleaved: aws.Bool(true),
		StartTime: aws.Int64(time.Now().Add(-since).UnixMilli()),
	})
	if err != nil {
		return err
	}

	for _, e := range out.Events {
		c.outLog.Printf("[%s][%s]%s\n", *e.LogStreamName, time.UnixMilli(*e.Timestamp), *e.Message)
	}
	return nil
}
