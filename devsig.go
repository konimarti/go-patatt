package patatt

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	DevsigHdr string = "X-Developer-Signature"
	DevkeyHdr string = "X-Developer-Key"
)

var (
	reqHdrs = []string{"from", "subject"}
	optHdrs = []string{"message-id"}
)

type Devsig struct {
	Hdata      map[string]string
	Hval       string
	Headervals []string
	BodyHash   string
}

func NewDevsig(hval string) Devsig {
	hval = canonicalize(hval)
	hdata := map[string]string{
		"v": "1",
	}
	pairs := strings.Split(hval, ";")
	for _, pair := range pairs {
		left, right, found := strings.Cut(pair, "=")
		if !found {
			if strings.TrimSpace(pair) != "" {
				Debugf("ignoring weird header: '%s'\n", pair)
			}
			continue
		}
		hdata[n(left)] = delWSP(n(right))
	}

	return Devsig{Hdata: hdata, Hval: hval}
}

func (ds *Devsig) Get(key string) string {
	return ds.Hdata[key]
}

func (ds *Devsig) Set(key, value string) {
	ds.Hdata[key] = value
}

func (ds *Devsig) Algo() (string, error) {
	return strings.ToLower(ds.Hdata["a"]), nil

	// a := strings.ToLower(ds.Hdata["a"])
	// switch {
	// case strings.HasPrefix(a, "ed25519"):
	// 	return ED25519, nil
	// case strings.HasPrefix(a, "openpgp"):
	// 	return OPENPGP, nil
	// case strings.HasPrefix(a, "openssh"):
	// 	return OPENSSH, nil
	// default:
	// 	return NONE, fmt.Errorf("%s/%s unknown algorithm: %s",
	// 		ds.Hdata["i"], ds.Hdata["s"], ds.Hdata["a"])
	//
	// }
}

// TODO: extract mode into its own types
func (ds *Devsig) SetHeaders(headers mail.Header, mode string) error {
	allhdrs := make(map[string]struct{})
	for h := range headers {
		allhdrs[n(h)] = struct{}{}
	}

	var signlist []string
	switch mode {
	case "sign":
		// make sure reqHdrs is a subset of allhdrs
		for _, req := range reqHdrs {
			if _, ok := allhdrs[req]; !ok {
				return fmt.Errorf("%w: The following "+
					"required headers not present: %s",
					SigningErr, req)
			}
			signlist = append(signlist, req)
		}
		// add optional headers that are actually present
		for _, opt := range optHdrs {
			if _, ok := allhdrs[opt]; !ok {
				continue
			}
			signlist = append(signlist, opt)
		}
		ds.Hdata["h"] = strings.Join(signlist, ":")
	case "validate":
		hfield := ds.Get("h")
		for _, req := range reqHdrs {
			if !strings.Contains(strings.ToLower(hfield),
				strings.ToLower(req)) {
				return fmt.Errorf("%w: The following required "+
					"headers not signed: %s", ValidationErr, req)
			}
		}
		signlist = strings.Split(hfield, ":")
		for i, s := range signlist {
			signlist[i] = n(s)
		}
	default:
		return fmt.Errorf("mode %s not implemented yet", mode)
	}

	for _, shname := range signlist {
		if _, ok := allhdrs[shname]; !ok {
			continue
		}
		ds.Headervals = append(ds.Headervals,
			fmt.Sprintf("%s:%s", shname, canonicalize(headers.Get(shname))))
	}

	return nil
}

func (ds *Devsig) SetBody(bodyArg []byte, maxlen int) error {
	if maxlen > len(bodyArg) {
		return fmt.Errorf("maxlen is larger than payload")
	}
	body := make([]byte, maxlen)
	copy(body, bodyArg)
	ds.Set("l", strconv.Itoa(len(body)))

	digest := sha256.Sum256(body)
	ds.BodyHash = base64.StdEncoding.EncodeToString(digest[:])

	return nil
}

func (ds *Devsig) sanityCheck() error {
	if _, ok := ds.Hdata["a"]; !ok {
		return errors.New("Must set 'a' field first")
	}
	if len(ds.BodyHash) == 0 {
		return errors.New("Must use SetBody first")
	}
	if len(ds.Headervals) == 0 {
		return errors.New("Must use SetHeaders first")
	}
	return nil
}

func (ds *Devsig) Validate(pubkey string) (string, string, error) {
	if err := ds.sanityCheck(); err != nil {
		return "", "", err
	}

	if _, ok := ds.Hdata["b"]; !ok {
		return "", "", errors.New("Missing 'b=' value")
	}

	if n(ds.Get("bh")) != n(ds.BodyHash) {
		return "", "", fmt.Errorf("%w: Body content validation failed",
			ValidationErr)
	}

	hash := sha256.New()
	for _, s := range ds.Headervals {
		hash.Write([]byte(s))
	}

	left, right, found := strings.Cut(ds.Hval, "b=")
	if !found {
		return "", "", errors.New("could not split b= field")
	}
	dshdr := left + "b="
	bdata := delWSP(right)

	devSig := fmt.Sprintf("%s:%s", n(DevsigHdr), dshdr)
	hash.Write([]byte(devSig))

	vdigest := string(hash.Sum(nil))

	// TODO: implement other algos
	var (
		signkey, signtime, sdigest string
		err                        error
	)

	a := n(ds.Get("a"))

	switch {
	case strings.HasPrefix(a, "ed25519"):
		// FIXME: WIP .. line 305
		// pk := ed25519.PublicKey([]byte(pubkey))
		// if ed25519.Verify(pk, []byte(bdata), nil) {
		// 	return "", "", nil
		// } else {
		// 	return "", "", ValidationErr
		// }
	case strings.HasPrefix(a, "openssh"):
		return "", "", errors.New(a + " not implemented")
	case strings.HasPrefix(a, "openpgp"):
		sdigest, signkey, signtime, err = ds.openpgpValidate(bdata, pubkey)
		if err != nil {
			return "", "", err
		}
		if sdigest != vdigest {
			return "", "", fmt.Errorf("%w: Header validation failed",
				ValidationErr)
		}
	default:
		if a == "" {
			a = "(none)"
		}
		return "", "", fmt.Errorf("%w: Unknown algorithm: %s", ValidationErr, a)
	}

	return signkey, signtime, nil
}

func (ds *Devsig) openpgpValidate(sigdata, pubkey string) (sdigest string, signkey string, signtime string, reterr error) {
	bsigdata, err := base64.StdEncoding.DecodeString(sigdata)
	if err != nil {
		reterr = err
		return
	}

	if pubkey != "" {
		// TODO: resuing cached keyring or importing into new keyring
		// see lines 396-413
		panic("keyring not implemented yet")
	} else {
		Debugf("veriying using default keyring")
		cmd := exec.Command("gpg", append(DefaultGPGArgs(),
			"--verify", "--output", "-", "--status-fd=2")...)
		digest, stderr := CommandIO(cmd, bytes.NewReader(bsigdata))

		err := cmd.Run()
		if err != nil {
			reterr = err
			return
		}
		if ExitCode(cmd) > 0 {
			if bytes.Contains(stderr.Bytes(), []byte("[GNUPG:] NO_PUBKEY")) {
				reterr = NoKeyErr
			} else {
				reterr = ValidationErr
			}
			return
		}

		sdigest = digest.String()

		var ok bool
		signkey, signtime, ok = parseOpenpgpOutput(stderr.String())
		if !ok {
			reterr = ValidationErr
		}
	}

	return
}

var (
	gpgGoodSig  = regexp.MustCompile(`\[GNUPG:\] GOODSIG ([0-9A-F]+)\s+(.*)`)
	gpgValidSig = regexp.MustCompile(`\[GNUPG:\] VALIDSIG ([0-9A-F]+) (\d{4}-\d{2}-\d{2}) (\d+)`)
)

func parseOpenpgpOutput(payload string) (signkey, signtime string, ok bool) {
	Debugf("GNUPG status:\n\t%s\n", strings.ReplaceAll(payload, "\n", "\n\t"))

	gs := gpgGoodSig.FindStringSubmatch(payload)
	good := len(gs) > 0

	vs := gpgValidSig.FindStringSubmatch(payload)
	valid := len(vs) > 0
	if len(vs) >= 3 {
		signkey = vs[1]
		signtime = vs[3]
	}

	ok = good && valid
	return
}

var order = []string{"v", "a", "t", "l", "i", "s", "h", "bh"}

func (ds *Devsig) Sign(keyinfo string) (string, string, error) {
	if err := ds.sanityCheck(); err != nil {
		return "", "", err
	}

	ds.Set("bh", ds.BodyHash)

	hparts := make([]string, 0)
	for _, k := range order {
		v := ds.Get(k)
		if v != "" {
			hparts = append(hparts, fmt.Sprintf("%s=%s", k, v))
		}
	}
	hparts = append(hparts, "b=")
	dshval := strings.Join(hparts, "; ")

	hash := sha256.New()
	hash.Write([]byte(strings.Join(ds.Headervals, "")))
	hash.Write([]byte(n(DevsigHdr) + ":" + dshval))
	digest := hash.Sum(nil)

	var (
		bval, pkinfo string
		err          error
	)

	a := ds.Get("a")

	switch {
	case strings.HasPrefix(a, "ed25519"):
		fallthrough
	case strings.HasPrefix(a, "openssh"):
		return "", "", errors.New(a + " not implemented yet")
	case strings.HasPrefix(a, "openpgp"):
		bval, pkinfo, err = ds.openpgpSign(string(digest), keyinfo)
		if err != nil {
			return "", "", err
		}
	default:
		if a == "" {
			a = "(none)"
		}
		return "", "", fmt.Errorf("Unknown a=%s", a)
	}

	return dshval + bval, pkinfo, nil
}

func (ds *Devsig) openpgpSign(payload, keyid string) (bdata string, keyfp string, reterr error) {

	// TODO: don't hardcode gpp binary (config?)

	cmd := exec.Command(
		"gpg", append(DefaultGPGArgs(), "-s", "-u", keyid)...)

	out, outErr := CommandIO(cmd, strings.NewReader(payload))

	err := cmd.Run()
	if err != nil || ExitCode(cmd) > 0 {
		reterr = fmt.Errorf("%w: failed to PGP sign:\n"+
			"\tExit Code: %d\n"+
			"\tError    : %v\n"+
			"\tErrOutput: %s\n",
			SigningErr, ExitCode(cmd), err, outErr)
		return
	}

	bdata = base64.StdEncoding.EncodeToString(out.Bytes())

	// now get the fingerprint of this keyid
	cmd = exec.Command("gpg", "--with-colons", "--fingerprint", keyid)

	output, err := cmd.CombinedOutput()
	if err != nil || ExitCode(cmd) > 0 {
		reterr = fmt.Errorf("%w: failed to get PGP fingerprint:\n"+
			"\tExit Code: %d\n"+
			"\tError    : %v\n"+
			"\tErrOutput: %s\n",
			SigningErr, ExitCode(cmd), err, output)
		return
	}

	pkid := ""
	scanner := bufio.NewScanner(
		strings.NewReader(string(output)),
	)

	for scanner.Scan() {
		text := scanner.Text()
		parts := strings.Fields(strings.ReplaceAll(text, ":", " "))

		if strings.HasPrefix(n(text), "pub:") {
			pkid = parts[4]
		} else if strings.HasPrefix(n(text), "fpr:") && pkid != "" {
			if strings.Contains(parts[1], pkid) {
				keyfp = parts[1]
				break
			}
		}
	}

	return
}
