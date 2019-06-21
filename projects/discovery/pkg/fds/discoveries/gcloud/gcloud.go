package gcloud

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"time"
	"unicode/utf8"
        "net/http"

        "golang.org/x/oauth2"
        "golang.org/x/oauth2/google"
        "google.golang.org/api/cloudfunctions/v1beta2"
	"github.com/pkg/errors"
	"github.com/solo-io/gloo/projects/discovery/pkg/fds"
	v1 "github.com/solo-io/gloo/projects/gloo/pkg/api/v1"
	"github.com/solo-io/gloo/projects/gloo/pkg/api/v1/plugins"
	gloogcloud "github.com/solo-io/gloo/projects/gloo/pkg/api/v1/plugins/gcloud"
	"github.com/solo-io/go-utils/contextutils"
)

const (
	// expected map identifiers for secrets
	gcloudAccessKey = "access_key"
	gcloudJsonKey = "json_key"
        // v1beta2: https://cloud.google.com/functions/docs/reference/rest/v1beta2/projects.locations.functions
        statusReady = "READY"
        // v1 status: https://cloud.google.com/functions/docs/reference/rest/v1/projects.locations.functions
        statusActive = "ACTIVE"
)

type GcloudGfuncFunctionDiscoveryFactory struct {
	PollingTime time.Duration
}

func (f *GcloudGfuncFunctionDiscoveryFactory) NewFunctionDiscovery(u *v1.Upstream) fds.UpstreamFunctionDiscovery {
	return &GcloudGfuncFunctionDiscovery{
		timetowait: f.PollingTime,
		upstream:   u,
	}
}

type GcloudGfuncFunctionDiscovery struct {
	timetowait time.Duration
	upstream   *v1.Upstream
}

func (f *GcloudGfuncFunctionDiscovery) IsFunctional() bool {
	_, ok := f.upstream.UpstreamSpec.UpstreamType.(*v1.UpstreamSpec_Gcloud)
	return ok
}

func (f *GcloudGfuncFunctionDiscovery) DetectType(ctx context.Context, url *url.URL) (*plugins.ServiceSpec, error) {
	return nil, nil
}

// TODO: how to handle changes in secret or upstream (like the upstream ref)?
// perhaps the in param for the upstream should be a function? in func() *v1.Upstream
func (f *GcloudGfuncFunctionDiscovery) DetectFunctions(ctx context.Context, url *url.URL, dependencies func() fds.Dependencies, updatecb func(fds.UpstreamMutator) error) error {
	for {
		// TODO: get backoff values from config?
		err := contextutils.NewExponentioalBackoff(contextutils.ExponentioalBackoff{}).Backoff(ctx, func(ctx context.Context) error {
			newfunctions, err := f.DetectFunctionsOnce(ctx, dependencies().Secrets)

			if err != nil {
				return err
			}

			// sort for idempotency
			sort.Slice(newfunctions, func(i, j int) bool {
				return newfunctions[i].LogicalName < newfunctions[j].LogicalName
			})

			// TODO(yuval-k): only update functions if newfunctions != oldfunctions
			// no need to constantly write to storage

			err = updatecb(func(out *v1.Upstream) error {
				// TODO(yuval-k): this should never happen. but it did. add logs?
				if out == nil {
					return errors.New("nil upstream")
				}
				if out.UpstreamSpec == nil {
					return errors.New("nil upstream spec")
				}

				if out.UpstreamSpec.UpstreamType == nil {
					return errors.New("nil upstream type")
				}

				gcloudspec, ok := out.UpstreamSpec.UpstreamType.(*v1.UpstreamSpec_Gcloud)
				if !ok {
					return errors.New("not gcloud upstream")
				}
				gcloudspec.Gcloud.GfuncFunctions = newfunctions
				return nil
			})

			if err != nil {
				return errors.Wrap(err, "unable to update upstream")
			}
			return nil

		})
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// ignore other erros as we would like to continue forever.
		}

		// sleep so we are not hogging
		if err := contextutils.Sleep(ctx, f.timetowait); err != nil {
			return err
		}
	}
}

func (f *GcloudGfuncFunctionDiscovery) DetectFunctionsOnce(ctx context.Context, secrets v1.SecretList) ([]*gloogcloud.GfuncFunctionSpec, error) {
	in := f.upstream
	gcloudspec, ok := in.UpstreamSpec.UpstreamType.(*v1.UpstreamSpec_Gcloud)

	if !ok {
		return nil, errors.New("not a gfunc upstream spec")
	}
	gfuncSpec := gcloudspec.Gcloud
	gcloudSecrets, err := secrets.Find(gfuncSpec.SecretRef.Namespace, gfuncSpec.SecretRef.Name)
	if err != nil {
		return nil, errors.Wrapf(err, "secrets not found for secret ref %v", gfuncSpec.SecretRef)
	}

	gcloudSecret, ok := gcloudSecrets.Kind.(*v1.Secret_Gcloud)
	if !ok {
		return nil, errors.Errorf("provided secret is not an gcloud secret")
	}
	accessKey := gcloudSecret.Gcloud.AccessKey
	if accessKey != "" && !utf8.Valid([]byte(accessKey)) {
		return nil, errors.Errorf("%s not a valid string", gcloudAccessKey)
	}

        jsonKey := gcloudSecret.Gcloud.JsonKey
        if jsonKey != "" && !utf8.Valid([]byte(jsonKey)) {
                return nil, errors.Errorf("%s not a valid string", gcloudJsonKey)
        }

        client, err := newGoogleClient(ctx, jsonKey)
        if err != nil {
                return nil, errors.Wrap(err, "creating google oauth2 client")
        }

        gcf, err := cloudfunctions.New(client)
        if err != nil {
                return nil, errors.Wrap(err, "creating gcf client")
        }

        locationID := "-" // all locations
        parent := fmt.Sprintf("projects/%s/locations/%s", gfuncSpec.ProjectId, locationID)
        listCall := gcf.Projects.Locations.Functions.List(parent)
        var results []*cloudfunctions.CloudFunction
        if err := listCall.Pages(ctx, func(response *cloudfunctions.ListFunctionsResponse) error {
                for _, result := range response.Functions {
                        // TODO: document that we currently only support https trigger funcs
                        if ((result.Status == statusReady) || (result.Status == statusActive)) && result.HttpsTrigger != nil {
                                results = append(results, result)
                        }
                }
                return nil
        }); err != nil {
                return nil, errors.Wrap(err, "unable to get list of GCF functions")
        }

        return convertGfuncsToFunctionSpec(results), nil
}

func convertGfuncsToFunctionSpec(results []*cloudfunctions.CloudFunction) []*gloogcloud.GfuncFunctionSpec {
        var newfunctions []*gloogcloud.GfuncFunctionSpec
        for _, gFunc := range results {
               newfunctions = append(newfunctions, &gloogcloud.GfuncFunctionSpec{
                        GfuncFunctionName: gFunc.Name,
                        Url:               gFunc.HttpsTrigger.Url,
                        })
        }
        return newfunctions
}

func newGoogleClient(ctx context.Context, jsonKey string) (*http.Client, error) {
        jwtConfig, err := google.JWTConfigFromJSON([]byte(jsonKey), cloudfunctions.CloudPlatformScope)
        if err != nil {
                return nil, errors.Wrap(err, "creating jwt config from service account JSON key file ")
        }
        return oauth2.NewClient(ctx, jwtConfig.TokenSource(ctx)), nil
}

