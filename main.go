// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/fatih/structs"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
	"github.com/nlopes/slack"
)

type authResult struct {
	policies []string
	user     *slack.User
}

type slackConfig struct {
	Token string `json:"token"`
}

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type SlackPlugin struct {
	*framework.Backend
}

func Backend(c *logical.BackendConfig) *SlackPlugin {
	var b SlackPlugin

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"token": {
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},
			{
				Pattern: "config",
				Fields: map[string]*framework.FieldSchema{
					"token": &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Slack OAuth access token for your Slack application.",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
					logical.ReadOperation:   b.pathConfigRead,
				},
			},
		},
	}

	return &b
}

func (b *SlackPlugin) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	token := d.Get("token").(string)

	creds, err := b.authenticateUser(ctx, req, token)
	if err != nil {
		if err, ok := err.(logical.HTTPCodedError); ok {
			return nil, err
		}
		return nil, err
	}

	// Compose the response
	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"slack_token": token,
			},
			Policies: creds.policies,
			Metadata: map[string]string{
				"slack_user_id":        creds.user.ID,
				"slack_user_name":      creds.user.Name,
				"slack_user_real_name": creds.user.RealName,
			},
			DisplayName: creds.user.Name,
			LeaseOptions: logical.LeaseOptions{
				TTL:       30 * time.Second,
				MaxTTL:    60 * time.Minute,
				Renewable: true,
			},
		},
	}, nil
}

// TODO: Still needs to be implemented
func (b *SlackPlugin) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
}

func (b *SlackPlugin) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: structs.New(config).Map(),
	}
	return resp, nil
}

func (b *SlackPlugin) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	token := data.Get("token").(string)

	entry, err := logical.StorageEntryJSON("config", &slackConfig{
		Token: token,
	})
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *SlackPlugin) Config(ctx context.Context, s logical.Storage) (*slackConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil || len(entry.Value) == 0 {
		return nil, errors.New("no configuration in storage")
	}

	var result slackConfig
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *SlackPlugin) authenticateUser(ctx context.Context, req *logical.Request, token string) (*authResult, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	client := slack.New(token, slack.OptionDebug(true))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.AuthTestContext(ctx)
	if err != nil {
		return nil, err
	}

	client = slack.New(config.Token, slack.OptionDebug(true))

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	user, err := client.GetUserInfoContext(ctx, resp.UserID)
	if err != nil {
		return nil, err
	}

	return &authResult{
		policies: []string{"default"},
		user:     user,
	}, nil
}
