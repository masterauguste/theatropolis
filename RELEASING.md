# Release signing

The release workflow requires an RSA private key in the `RELEASE_SIGNING_PRIVATE_KEY` GitHub Actions environment secret. Configure that secret on a protected environment named `release-signing`, require a reviewer, and restrict deployment to release tags. Do not store the private key in the repository or as a repository-wide secret.

The corresponding embedded public-key SHA-256 fingerprint is:

```text
ff2f69ff282be2a5f885e01ccaa458dcabe2ee02a789235989f2b81d50689fb2
```

Routine release creation does not require the private key on the developer's
machine: pushing a release tag starts GitHub Actions, which reads the key from
the protected `release-signing` environment. Keep a separate recovery copy in
a password manager or secrets manager so that the environment secret can be
restored without rotating the signing identity.

Before adding or replacing the secret, derive the candidate public key and confirm its DER fingerprint:

```sh
openssl pkey -in release-signing-private.pem -pubout -outform DER |
  openssl dgst -sha256
```

The workflow produces `checksums.txt.sig` with RSA-PSS/SHA-256 and refuses to replace an existing GitHub release. Rotating the key requires changing the public key in both `internal/agentupdate/update.go` and `install.sh` in a release signed by the old key. Retain the old private key until that transition release is deployed everywhere.
