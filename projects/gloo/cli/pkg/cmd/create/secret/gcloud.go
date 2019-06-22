package secret

import (
	"context"
	"fmt"

	"github.com/solo-io/gloo/pkg/cliutil"
	"github.com/solo-io/gloo/projects/gloo/cli/pkg/argsutils"
	"github.com/solo-io/gloo/projects/gloo/cli/pkg/cmd/options"
	"github.com/solo-io/gloo/projects/gloo/cli/pkg/common"
	"github.com/solo-io/gloo/projects/gloo/cli/pkg/helpers"
	gloov1 "github.com/solo-io/gloo/projects/gloo/pkg/api/v1"
	"github.com/solo-io/solo-kit/pkg/api/v1/clients"
	"github.com/solo-io/solo-kit/pkg/api/v1/resources/core"
	"github.com/spf13/cobra"
)

var (
	flagDefaultGcloudAccessKey = ""
	flagDefaultGcloudJsonKey = ""
)

func gcloudCmd(opts *options.Options) *cobra.Command {
	input := &opts.Create.InputSecret.GcloudSecret
	cmd := &cobra.Command{
		Use:   "gcloud",
		Short: `Create an Gcloud secret with the given name`,
		Long:  `Create an Gcloud secret with the given name`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := argsutils.MetadataArgsParse(opts, args); err != nil {
				return err
			}
			if opts.Top.Interactive {
				// and gather any missing args that are available through interactive mode
				if err := GcloudSecretArgsInteractive(&opts.Metadata, input); err != nil {
					return err
				}
			}
			// create the secret
			if err := createGcloudSecret(opts.Top.Ctx, opts.Metadata, *input, opts.Create.DryRun); err != nil {
				return err
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&input.AccessKey, "access-key", flagDefaultGcloudAccessKey, "gcloud access key")
	flags.StringVar(&input.JsonKey, "json-key", flagDefaultGcloudJsonKey, "gcloud json key")

	return cmd
}

const (
	gcloudPromptAccessKey = "Enter Gcloud Access Key ID (leave empty to read credentials from ~/.gcloud/credentials): "
	gcloudPromptJsonKey = "Enter Gcloud Json Key"
)

func GcloudSecretArgsInteractive(meta *core.Metadata, input *options.GcloudSecret) error {
	if err := cliutil.GetStringInput(gcloudPromptAccessKey, &input.AccessKey); err != nil {
		return err
	}
	if err := cliutil.GetStringInput(gcloudPromptJsonKey, &input.JsonKey); err != nil {
		return err
	}

	return nil
}

func createGcloudSecret(ctx context.Context, meta core.Metadata, input options.GcloudSecret, dryRun bool) error {
	secret := &gloov1.Secret{
		Metadata: meta,
		Kind: &gloov1.Secret_Gcloud{
			Gcloud: &gloov1.GcloudSecret{
				AccessKey: input.AccessKey,
				JsonKey: input.JsonKey,
			},
		},
	}

	if dryRun {
		return common.PrintKubeSecret(ctx, secret)
	}

	secretClient := helpers.MustSecretClient()
	if _, err := secretClient.Write(secret, clients.WriteOpts{Ctx: ctx}); err != nil {
		return err
	}

	fmt.Printf("Created Gcloud secret [%v] in namespace [%v]\n", meta.Name, meta.Namespace)

	return nil
}
