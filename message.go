package patatt

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	Headers       mail.Header
	Body          []byte
	RawMessage    []byte
	Signed        bool
	CanonHeader   mail.Header
	CanonBody     []byte
	CanonIdentity string
	Sigs          []Devsig
}

func NewMessage(r io.Reader) (*Message, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("could not read message: %w", err)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("Not a valid RFC2822 message: %w", err)
	}

	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, err
	}

	sigs := make([]Devsig, 0)
	devSigHeader := strings.ToLower(DevsigHdr)
	for h, values := range msg.Header {
		if strings.ToLower(h) == devSigHeader {
			for _, value := range values {
				sigs = append(sigs, NewDevsig(value))
			}
		}
	}

	fromList, err := msg.Header.AddressList("From")
	if err != nil {
		return nil, err
	}
	if len(fromList) > 0 {
		fromid := fromList[0].Address
		for i := range sigs {
			if sigs[i].Get("i") == "" {
				sigs[i].Set("i", fromid)
			}
		}
	}

	m := Message{
		Headers:    msg.Header,
		Body:       body,
		RawMessage: raw,
		Signed:     len(sigs) > 0,
		Sigs:       sigs,
	}
	return &m, nil
}

func (m *Message) gitCanonicalize() error {
	if len(m.CanonBody) > 0 {
		return nil
	}

	dir, err := os.MkdirTemp("", ".git_mailinfo-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	mf := filepath.Join(dir, "m")
	pf := filepath.Join(dir, "p")

	// run git mailinfo
	cmd := exec.Command("git", "mailinfo", "--encoding=utf-8", "--no-scissors", mf, pf)
	cmd.Dir = dir
	cmd.Stdin = bytes.NewReader(bytes.ReplaceAll(m.RawMessage, []byte(crlf), []byte(lf)))

	i, err := cmd.Output()
	if err != nil {
		return err
	}

	if code := ExitCode(cmd); code > 0 {
		return fmt.Errorf("FAILED: Failed running git-mailinfo: %d", code)
	}

	mbytes, err := os.ReadFile(mf)
	if err != nil {
		return err
	}
	pbytes, err := os.ReadFile(pf)
	if err != nil {
		return err
	}

	reader := io.MultiReader(
		NewCRLFReader(bytes.NewReader(mbytes)),
		NewCRLFReader(bytes.NewReader(pbytes)),
	)
	m.CanonBody, err = io.ReadAll(reader)
	if err != nil {
		return err
	}

	// trim all excess blank lines at the end
	m.CanonBody = bytes.Trim(m.CanonBody, crlf)
	m.CanonBody = append(m.CanonBody, crlf...)

	hr := textproto.NewReader(bufio.NewReader(bytes.NewReader(i)))
	ihdr, err := hr.ReadMIMEHeader()
	if err != nil {
		return err
	}

	m.CanonIdentity = ihdr.Get("email")
	m.CanonHeader = make(mail.Header)
	for hkey, hval := range m.Headers {
		if strings.ToLower(hkey) == "from" {
			from := mail.Address{Name: ihdr.Get("author"),
				Address: m.CanonIdentity}
			hval = []string{fmt.Sprintf("%s <%s>", from.Name, from.Address)}
		}
		if strings.ToLower(hkey) == "subject" {
			hval = []string{ihdr.Get("subject")}
		}
		m.CanonHeader[hkey] = hval
	}

	return nil
}

func (m *Message) Validate(identity, pubkey string, trim bool) (string, string, error) {
	var vds *Devsig = nil
	for _, ds := range m.Sigs {
		if ds.Get("i") == identity {
			vds = &ds
		}
	}
	if vds == nil {
		return "", "", fmt.Errorf("%w: no signatures matching identity %s",
			ValidationErr, identity)
	}

	err := m.gitCanonicalize()
	if err != nil {
		return "", "", err
	}

	err = vds.SetHeaders(m.CanonHeader, "validate")
	if err != nil {
		return "", "", err
	}

	maxlen := len(m.CanonBody)
	if trim {
		maxlen, err = strconv.Atoi(vds.Get("l"))
		if err != nil {
			return "", "", err
		}
	}

	err = vds.SetBody(m.CanonBody, maxlen)
	if err != nil {
		return "", "", err
	}

	return vds.Validate(pubkey)
}

func (m *Message) Sign(algo, keyinfo, identity, selector string) error {
	// remove devsig headers
	remove := make([]string, 0, 2)
	for key := range m.Headers {
		if n(key) == n(DevkeyHdr) ||
			n(key) == n(DevsigHdr) {
			remove = append(remove, key)
		}
	}
	for _, rm := range remove {
		delete(m.Headers, rm)
	}

	err := m.gitCanonicalize()
	if err != nil {
		return err
	}

	ds := NewDevsig("")

	err = ds.SetHeaders(m.CanonHeader, "sign")
	if err != nil {
		return err
	}

	err = ds.SetBody(m.CanonBody, len(m.CanonBody))
	if err != nil {
		return err
	}

	if identity == "" {
		identity = m.CanonIdentity
	}
	ds.Set("i", identity)

	if selector != "" {
		ds.Set("s", selector)
	}

	switch algo {
	case "ed25519", "openssh":
		// FIXME: is this the right time format?
		ds.Set("t", strconv.Itoa(int(time.Now().Unix())))
		fallthrough
	case "openpgp":
		ds.Set("a", fmt.Sprintf("%s-sha256", algo))
	default:
		if algo == "" {
			algo = "(none)"
		}
		return fmt.Errorf("%w: Unsupported algorithm: %s",
			SigningErr, algo)
	}

	hv, pkinfo, err := ds.Sign(keyinfo)
	if err != nil {
		return err
	}

	// add signature header
	m.Headers[DevsigHdr] = []string{hv}

	// add key header
	idata := []string{
		"i=" + identity,
		"a=" + algo,
	}
	prefix := ""
	switch algo {
	case "openpgp", "openssh":
		prefix = "fpr="
	default:
		prefix = "pk="
	}
	idata = append(idata, prefix+pkinfo)
	m.Headers[DevkeyHdr] = []string{strings.Join(idata, "; ")}

	return nil
}

const maxlen = 78

func (m *Message) HeaderOrder() []string {
	order := make([]string, 0)
	scanner := bufio.NewScanner(bytes.NewReader(m.RawMessage))
	for scanner.Scan() {
		l := scanner.Text()
		if strings.TrimSpace(l) == "" {
			break
		}
		if strings.HasPrefix(l, " ") {
			continue
		}
		i := strings.Index(l, ":")
		if i < 0 {
			continue
		}
		order = append(order, textproto.CanonicalMIMEHeaderKey(l[:i]))
	}
	return append(order, DevsigHdr, DevkeyHdr)
}

func (m *Message) Bytes() []byte {
	msg := make([]string, 0)
	// format header and break long lines (see RFC 5322 section 2.2.3)
	for _, k := range m.HeaderOrder() {
		s := fmt.Sprintf("%s: %s", k, m.Headers.Get(k))
		for len(s) > 0 {
			sp := ""
			i := len(s)
			if i > maxlen {
				i = strings.LastIndex(s[:maxlen], " ")
				if i <= 0 {
					i = maxlen
				}
				if s[i] != ' ' {
					sp = " "
				}
			}
			msg = append(msg, s[:i])
			s = sp + s[i:]
		}
	}

	// add blank line between headers and body
	msg = append(msg, "")

	scanner := bufio.NewScanner(bytes.NewReader(m.Body))

	for scanner.Scan() {
		msg = append(msg, scanner.Text())
	}

	return []byte(strings.Join(msg, lf))
}
