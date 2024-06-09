package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"time"

	"github.com/emersion/go-mbox"
	"github.com/konimarti/go-patatt"
	"github.com/spf13/cobra"
)

func newSignCmd() *cobra.Command {
	run := func(cmd *cobra.Command, args []string) {
		err := Process(args, doSign)
		if err != nil {
			handleErr(err)
		}
	}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Cryptographically attest a RFC2822 message",
		Run:   run,
	}

	return cmd
}

func doSign(j Job) error {

	buf := new(bytes.Buffer)
	writer := mbox.NewWriter(buf)
	defer writer.Close()

	mr := mbox.NewReader(j.Reader())
	for {
		r, err := mr.NextMessage()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}

		m, err := patatt.NewMessage(r)
		if err != nil {
			return err
		}

		// TODO: read and parse config from git?
		// config := patatt.Config{
		// 	Identity:   os.Getenv("PATATT_IDENT"),
		// 	SigningKey: os.Getenv("PATATT_SKEY"),
		// }
		config := patatt.NewConfig(Section)

		signed, err := patatt.Sign(m, config)
		if err != nil {
			return err
		}

		signedReader := bytes.NewReader(signed)

		mw, err := writer.CreateMessage(j.JobName(), time.Time{})
		if err != nil {
			return err
		}
		io.Copy(mw, signedReader)

		patatt.Criticalf("SIGN | %s\n", j.Base())
	}

	writer.Close()

	var w io.Writer
	if j.UseStdin() {
		w = os.Stdout
	} else {
		f, err := os.Create(j.FileName())
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	io.Copy(w, buf)

	return nil
}
