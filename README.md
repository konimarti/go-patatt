# Cryptographic Patch Attestation for the masses in Go

Patch attestation clone in Golang of [patatt](https://github.com/mricon/patatt).

### Installation

`go install github.com/konimarti/go-patatt@latest`

### Usage

Supports the same option set as [patatt](https://github.com/mricon/patatt).

#### Using OpenPGP/GPG

If you already have a PGP key, you can simply start using it to sign patches. Add the following to your ~/.gitconfig:

```git
[patatt]
    signingkey = openpgp:KEYID
```

Replace `KEYID` with the fingerprint ID of your PGP key.

#### Signing patches

To start singing patches:

```sh
$ git format-patch -1 --stdout | patatt sign > /tmp/test
```

If you didn't get an error message, then the process was successful.
You can review /tmp/test to see that X-Developer-Signature and X-Developer-Key headers were successfully added.

#### Validate signed patches

You can now validate your own message:

```sh
$ patatt validate /tmp/test
```

### Status

Implemented crypto algorithms:

-   [x] OpenPGP (uses `gpg` under the hood).
-   [ ] OpenSSH
-   [ ] ed25519

Implemented functionality:

-   [x] `sign` patches (provided on stdin or as file in RFC822 or mbox format).
-   [x] `validate` signed messages
-   [ ] `genkey` generates a new ed25519 key pair
-   [ ] `install-hook` intalls a sendmail-validate hook.

### Concepts and FAQ

Please see [patatt](https://github.com/mricon/patatt).
