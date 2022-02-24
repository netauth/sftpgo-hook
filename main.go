package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/go-hclog"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netauth/netauth/pkg/netauth"
)

var (
	cfgfile = pflag.String("config", "", "Config file to use")
	verbose = pflag.Bool("verbose", false, "Show logs")
)

type userFilters struct {
	DeniedLoginMethods []string `json:"denied_login_methods,omitempty"`
}

type minimalSFTPGoUser struct {
	Status      int                 `json:"status,omitempty"`
	Username    string              `json:"username"`
	HomeDir     string              `json:"home_dir,omitempty"`
	UID         int                 `json:"uid,omitempty"`
	GID         int                 `json:"gid,omitempty"`
	Permissions map[string][]string `json:"permissions"`
	Filters     userFilters         `json:"filters"`
}

func dumpUser(u minimalSFTPGoUser) {
	resp, _ := json.Marshal(u)
	fmt.Printf("%v\n", string(resp))
}

// doAuth fetches all the required informatino from the environment
// and then runs various queries to the netauth server to determine if
// the user should be allowed.  Checks in order are: entity is extant,
// unlocked, member of an optional group, has presented a valid public
// key, has presented a valid password.
//
// In a single pass only one authentication method (pubkey or
// password) will be checked.  This is to facilitate multi-call auth
// per the sftpgo spec.
func doAuth(c *netauth.Client) {
	ctx := context.Background()

	// Fish things out of the environment
	username := os.Getenv("SFTPGO_AUTHD_USERNAME")
	password := os.Getenv("SFTPGO_AUTHD_PASSWORD")
	publickey := os.Getenv("SFTPGO_AUTHD_PUBLIC_KEY")
	requireGroup := os.Getenv("SFTPGO_NETAUTH_REQUIREGROUP")

	entity, err := c.EntityInfo(ctx, username)
	if status.Code(err) != codes.OK || entity.GetMeta().GetLocked() {
		dumpUser(minimalSFTPGoUser{})
		return
	}

	if len(requireGroup) > 0 {
		groups, err := c.EntityGroups(ctx, username)
		if status.Code(err) != codes.OK {
			dumpUser(minimalSFTPGoUser{})
			return
		}
		set := make(map[string]struct{}, len(groups))
		for _, group := range groups {
			set[group.GetName()] = struct{}{}
		}
		if _, ok := set[requireGroup]; !ok {
			dumpUser(minimalSFTPGoUser{})
			return
		}
	}

	if len(publickey) > 0 {
		keys, err := c.EntityKeys(ctx, username, "READ", "SSH", "")
		if status.Code(err) != codes.OK {
			dumpUser(minimalSFTPGoUser{})
			return
		}
		found := false
		for _, k := range keys["SSH"] {
			if k == publickey {
				found = true
				break
			}
		}
		if !found {
			dumpUser(minimalSFTPGoUser{})
			return
		}
	} else {
		err := c.AuthEntity(ctx, username, password)
		if status.Code(err) != codes.OK {
			dumpUser(minimalSFTPGoUser{})
			return
		}
	}

	u := minimalSFTPGoUser{
		Status:      1,
		Username:    username,
		UID:         int(entity.GetNumber()),
		HomeDir:     filepath.Join(os.Getenv("SFTPGO_NETAUTH_HOMEDIR"), username),
		Permissions: map[string][]string{"/": []string{"*"}},
	}
	dumpUser(u)
}

func main() {
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	if *cfgfile != "" {
		viper.SetConfigFile(*cfgfile)
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.netauth")
		viper.AddConfigPath("/etc/netauth/")
	}
	if err := viper.ReadInConfig(); err != nil {
		fmt.Println("Error reading config:", err)
		dumpUser(minimalSFTPGoUser{})
		os.Exit(1)
	}

	// Shut off all the logging
	if !*verbose {
		hclog.SetDefault(hclog.NewNullLogger())
	}
	l := hclog.L().Named("netkeys")

	c, err := netauth.New()
	if err != nil {
		l.Warn("Error during client initialization:", "error", err)
		dumpUser(minimalSFTPGoUser{})
		os.Exit(1)
	}

	// Set the service ID
	c.SetServiceName("sftpgo")

	doAuth(c)
}
