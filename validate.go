package patatt

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	NoKeyErr      = errors.New("no key error")
	ValidationErr = errors.New("validation error")
)

type Algo int

const (
	NONE Algo = iota
	ED25519
	OPENPGP
	OPENSSH
)

type Result int

const (
	None Result = 1 << iota
	Valid
	NoSignature
	NoKey
	Error
	BadSignature
)

type Attestation struct {
	Result   Result
	Identity string
	SignTime string
	KeySrc   string
	Algo     string
	Err      error
}

func newAttestation(sig Devsig) Attestation {
	a := Attestation{
		Result:   None,
		Algo:     sig.Get("a"),
		Identity: sig.Get("i"),
		SignTime: sig.Get("t"),
	}
	return a

}

func Validate(m *Message, c Config) []Attestation {
	if !m.Signed {
		Debugf("message is not signed")
		return []Attestation{{
			Result: NoSignature,
			Err:    errors.New("no signatures found"),
		},
		}
	}

	trim := n(c.Params["trimbody"]) == "true"
	srcs := c.Keyringsrc

	attests := make([]Attestation, 0)

	// find all identities for which we have public keys
	for _, ds := range m.Sigs {

		a := newAttestation(ds)
		s := ds.Get("s")

		algo, err := ds.Algo()
		if err != nil {
			a.Result = Error
			a.Err = err
			attests = append(attests, a)
			continue
		}

		var pkey, keysrc string
		for _, src := range srcs {

			p, k, err := getPublicKey(src, algo, a.Identity, s)
			if err != nil {
				Debugf("getPublicKey for source=%s returned:"+
					" %v\n", src, err)
				continue
			}

			pkey, keysrc = p, k
			break
		}

		if pkey == "" && (algo == "ed25519" || algo == "openssh") {
			a.Result = NoKey
			a.Err = fmt.Errorf("%s/%s no matching %s key found", a.Identity, s, algo)
			attests = append(attests, a)
			continue
		}

		signkey, signtime, err := m.Validate(a.Identity, pkey, trim)

		if keysrc == "" {
			// Default keyring used
			keysrc = "(default keyring)"
			if signkey != "" {
				keysrc += "/" + signkey
			}
		}

		if err == nil {
			a.Result = Valid
			a.SignTime = signtime
			a.KeySrc = keysrc
		} else if errors.Is(err, NoKeyErr) {
			a.Result = NoKey
			a.Err = fmt.Errorf("%s/%s no matching openpgp key found", a.Identity, s)
		} else if errors.Is(err, ValidationErr) {
			a.Result = BadSignature
			if keysrc == "" {
				a.Err = fmt.Errorf("failed to validate using default keyring (err: %w)", err)
			} else {
				a.Err = fmt.Errorf("failed to validate using %s (err: %w)", keysrc, err)
			}
		} else {
			a.Err = err
		}

		attests = append(attests, a)
	}

	return attests
}

func publicKeyPath(keytype, identity, selector string) (string, error) {
	local, domain, ok := strings.Cut(identity, "@")
	if !ok {
		return "", fmt.Errorf("identity must inlcude both local an domain parts: %s\n", identity)
	}
	return filepath.Join(n(keytype), n(domain), n(local), n(selector)), nil
}

func getPublicKey(source string, keytype string, identity, selector string) (pubkey, keysrc string, reterr error) {
	keypath, err := publicKeyPath(keytype, identity, selector)
	if err != nil {
		reterr = err
		return
	}
	Infof("keypath: %s\n", keypath)

	//source = ref:refs/heads/someref:in-repo/path ?
	if strings.HasPrefix(source, "ref:") {
		parts := strings.SplitN(source, ":", 4)
		if len(parts) != 4 {
			reterr = fmt.Errorf("Invalid ref, must have at least "+
				"3 colons: %s\n", source)
			return
		}
		repo, ref, sub := n(parts[1]), n(parts[2]), n(parts[3])
		if repo != "" {
			repo = GitTopLevel("")
			if repo == "" {
				reterr = fmt.Errorf("Not in a git tree, so cannot use a ref:: source: %s\n", source)
				return
			}
		}

		// TODO: expand path for 'repo' ? check for $vars?

		gittop := filepath.Join(repo, ".git")
		if !exists(gittop) {
			gittop = repo
		}

		if ref == "" {
			cmd := exec.Command("git", "--git-dir", gittop, "symbolic-ref", "HEAD")
			output, err := cmd.Output()
			if err != nil {
				reterr = err
				return
			}
			if ExitCode(cmd) == 0 {
				ref = string(output)
			}
		}
		if ref == "" {
			reterr = fmt.Errorf("%w: could not figure out current ref in %s", KeyErr, gittop)
			return
		}

		subpath := filepath.Join(sub, keypath)

		keysrc = fmt.Sprintf("%s:%s", ref, subpath)
		args := []string{"--git-dir", gittop, "show", keysrc}
		cmd := exec.Command("git", args...)
		output, err := cmd.Output()
		if err != nil {
			Debugf("git-show: %v\n", err)
			reterr = fmt.Errorf("git-show: %w", err)
			return
		}
		// not implemented: follow one level of symlinks ... line 854
		if ExitCode(cmd) == 0 {
			return string(output), fmt.Sprintf("ref:%s:%s", gittop, keysrc), nil
		}

		// does it exist on disk but hasn't been committed yet
		fullpath := filepath.Join(repo, subpath)
		if exists(fullpath) {
			output, err := os.ReadFile(fullpath)
			if err != nil {
				reterr = err
				return
			}
			return string(output), fullpath, nil
		}
		reterr = fmt.Errorf("could not find %s in %s:%s", subpath, gittop, ref)
		return
	}

	// so it's a disk path, then

	// TODO: expand ~ and env vars
	fullpath := filepath.Join(source, keypath)
	if exists(fullpath) {
		output, err := os.ReadFile(fullpath)
		if err != nil {
			reterr = err
			return
		}
		return string(output), fullpath, nil
	}

	reterr = fmt.Errorf("could not find %s", fullpath)
	return
}
