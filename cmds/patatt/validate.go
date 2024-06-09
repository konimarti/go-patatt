package main

import (
	"errors"
	"io"
	"os"

	"github.com/emersion/go-mbox"
	"github.com/konimarti/go-patatt"
	"github.com/spf13/cobra"
)

func newValidateCmd() *cobra.Command {
	run := func(cmd *cobra.Command, args []string) {
		err := Process(args, doValidate)
		if err != nil {
			handleErr(err)
		}
	}

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a devsig-signed message",
		Run:   run,
	}

	return cmd
}

func doValidate(j Job) error {

	c := patatt.NewConfig(Section)

	var totalResult patatt.Result

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

		attestations := patatt.Validate(m, c)

		fn := j.FileName()
		for _, a := range attestations {
			switch a.Result {
			case patatt.Valid:
				patatt.Criticalf("  PASS | %s, %s\n", a.Identity, fn)
				if a.KeySrc != "" {
					patatt.Infof("       | key: %s\n", a.KeySrc)
				} else {
					patatt.Infof("       | key: default GnuPG keyring\n")
				}
			case patatt.NoSignature:
				patatt.Criticalf(" NOSIG | %s\n", fn)
				if a.Err != nil {
					patatt.Criticalf("       | %v\n", a.Err)
				}
			case patatt.NoKey:
				patatt.Criticalf(" NOKEY | %s, %s\n", a.Identity, fn)
				if a.Err != nil {
					patatt.Criticalf("       | %v\n", a.Err)
				}
			case patatt.Error:
				patatt.Criticalf(" ERROR | %s, %s\n", a.Identity, fn)
				if a.Err != nil {
					patatt.Criticalf("       | %v\n", a.Err)
				}
			default:
				patatt.Criticalf(" BADSIG | %s, %s\n", a.Identity, fn)
				if a.Err != nil {
					patatt.Criticalf("        | %v\n", a.Err)
				}
			}
			if totalResult < a.Result {
				totalResult = a.Result
			}
		}
	}

	if totalResult > patatt.Valid {
		os.Exit(int(totalResult))
	}

	return nil
}
