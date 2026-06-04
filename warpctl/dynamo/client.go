package dynamo

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type Client struct {
	cl *dynamodb.Client
}

const deploymentBlocksTableName = "deployment-blocks"

func NewClient() (*Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("us-west-1"))
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config, %v", err)
	}

	cl := dynamodb.NewFromConfig(cfg)

	return &Client{cl: cl}, nil

}

func (c *Client) UpdateVersion(ctx context.Context, env, service, block, version string) error {

	_, err := c.cl.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(deploymentBlocksTableName),
		Item: map[string]types.AttributeValue{
			"env-service-block": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s-%s-%s", env, service, block)},
			"version":           &types.AttributeValueMemberS{Value: version},
		},
	})

	if err != nil {
		return fmt.Errorf("unable to update version: %w", err)
	}

	return nil
}

func (c *Client) GetLatestVersion(ctx context.Context, env, service, block string) (string, error) {
	out, err := c.cl.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(deploymentBlocksTableName),
		Key: map[string]types.AttributeValue{
			"env-service-block": &types.AttributeValueMemberS{Value: fmt.Sprintf("%s-%s-%s", env, service, block)},
		},
	})

	if err != nil {
		return "", fmt.Errorf("unable to get version: %w", err)
	}

	if out.Item == nil {
		return "", nil
	}

	val, ok := out.Item["version"]
	if !ok {
		return "", fmt.Errorf("version attribute missing for %s-%s-%s", env, service, block)
	}
	s, ok := val.(*types.AttributeValueMemberS)
	if !ok {
		return "", fmt.Errorf("version attribute is not a string for %s-%s-%s", env, service, block)
	}
	return s.Value, nil
}
