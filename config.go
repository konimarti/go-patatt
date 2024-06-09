package patatt

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// config options:
//
// config loaded from "get_main_config(section)"
//
//
// * validate
// 	- trimbody
// 	- keyringsrc
//
// * others
//	- ssh-keygen-bin
//	- gpg-bin
//
// * usercfg "get_config_from_git(user\..)"
//	- email
//	- signingkey
//
// * gprcfg "get_config_from_git(gpg\..)"
//	- program
//

type Config struct {
	Identity   string
	SigningKey string
	Selector   string
	Keyringsrc []string
	Params     map[string]string
}

func (c Config) Algo() string {
	algo, _, ok := strings.Cut(c.SigningKey, ":")
	if ok {
		return strings.ToLower(algo)
	}
	return ""
}

func (c Config) Keydata() string {
	a, key, ok := strings.Cut(c.SigningKey, ":")
	if !ok {
		Debugf("could not split the key '%s'\n", c.SigningKey)
		return ""
	}

	if n(a) != "ed25519" {
		Infof("using key: %s\n", key)
		return key
	}

	// process ed25519 further
	keysrc := ""
	identifier := key[8:]
	if exists(identifier) {
		keysrc = identifier
	} else {
		// try datadir/private/%s.key
		dir := getDataDir()
		skey := filepath.Join(dir, "private", identifier+".key")
		if exists(skey) {
			keysrc = skey
		} else {
			// try .git/%s.key
			gtdir := GitTopLevel("")
			skey = filepath.Join(gtdir, ".git", identifier+".key")
			if exists(skey) {
				keysrc = skey
			}
		}
	}

	if keysrc == "" {
		panic(fmt.Errorf("config error: could not find the key matching %s", identifier))
	}

	Infof("N: Using ed25519 key: %s\n", keysrc)

	keycontent, err := os.ReadFile(keysrc)
	if err != nil {
		panic(err)
	}

	return string(keycontent)
}

func GitTopLevel(s string) string {
	var gitArgs []string
	if s != "" {
		gitArgs = append(gitArgs, "--git-dir", s)
	}
	gitArgs = append(gitArgs, "rev-parse", "--show-toplevel")
	cmd := exec.Command("git", gitArgs...)
	output, err := cmd.Output()
	if err != nil {
		Debugf("failed to get git top level: %v", err)
		return ""
	}

	return string(bytes.TrimSpace(output))
}

const (
	id string = "identity"
	sk string = "signingkey"
	em string = "email"
	sl string = "selector"
	kr string = "keyringsrc"
)

func NewConfig(section string) Config {

	// get_main_config(section)
	// 1) get_config_from_git("patatt\..*", section)
	// 	args = 'config', '-z', '--get-regexp', regexp

	m := GitConfig("patatt\\..*", "patatt", section)
	u := GitConfig("user\\..*", "user", section)
	for k, v := range u {
		if _, ok := m[n(k)]; ok {
			// keep config from first git config call
			Infof("ignoring %s\n", k)
			continue
		}
		m[n(k)] = v
	}

	c := Config{
		Identity:   m[id],
		SigningKey: m[sk],
		Selector:   m[sl],
		// Keyringsrc: []string{}, // TODO: how to parse this from conifg?
		Params: m,
	}

	if c.Identity == "" && u[em] != "" {
		Infof("N: Using identity %s defined by user.email\n", u[em])
		c.Identity = u[em]
	}

	if c.SigningKey == "" && u[sk] != "" {
		c.SigningKey = "openpgp:" + u[sk]
		Infof("N: Using pgp key %s defined by user.signingkey\n", u[sk])
		Infof("N: Override by setting patatt.signingkey\n")

	}
	if c.SigningKey == "" {
		Debugf("config %v\n", c)
		Criticalf("E: pattat.signingkey is not set\n")
	}
	if strings.Index(c.SigningKey, ":") < 0 {
		Infof("N: fixing key be prepending 'openpgp'\n")
		c.SigningKey = "openpgp:" + c.SigningKey
	}

	c.Keyringsrc = append(c.Keyringsrc, "ref:::.keys", "ref:::.local-keys", "ref::refs/meta/keyring:")

	// TODO: set binary paths for gpg/ssh?

	return c
}

// GitConig returns a map of the key value pair of the git config.
// If a section name is provided, only the section keys are returned.
//
// [branch "main"]
//
//	email = me@localhost
//
// turns into
//
//	branch.main.email=me@localhost
func GitConfig(regexp, main, sec string) map[string]string {
	m := make(map[string]string)

	// git config -z --get-regexp "user\..*" | tr "\000\n" "\n="
	cmd := exec.Command("git", "config", "-z", "--get-regexp", regexp)
	Debugf("Running: %s\n", strings.Join(cmd.Args, " "))
	output, err := cmd.Output()
	if err != nil {
		Debugf("git-config failed with %v\n", err)
		return m
	}
	if ExitCode(cmd) > 0 {
		Debugf("git-config failed with exit code %v\n", ExitCode(cmd))
		return m
	}

	// split by \x00
	parts := strings.Split(string(output), string([]byte{0}))
	for _, part := range parts {
		// split key off after first \n
		key, value, ok := strings.Cut(part, "\n")
		if ok {
			k := strings.TrimPrefix(n(key), main+".")
			if sec != "" {
				k = strings.TrimPrefix(k, sec+".")
			}
			m[k] = strings.TrimSpace(value)
		}
	}

	Infof("returning: %v\n", m)

	return m
}
