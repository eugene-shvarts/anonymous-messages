# Anonymous Q&A

A web app for letting anyone leave anonymous messages that can only be read by their intended recipient.

The app uses a hybrid encryption scheme. Each recipient has an `X25519` keypair and a password; the password can decrypt the private key. Messages are encrypted against the pubkey via key exchange, and so can be decrypted via the private key. Key derivation uses `bcrypt`, key and message encryption use `AESGCM`.

Originally implemented as a means for a group of people to leave reflections for each other.

## Usage

To set up your own instance, first set up a Python virtualenv with the dependencies:
```
pip install -r app/requirements.txt
```

You'll need a MySQL instance to point to.

### Usage with 1PW op CLI (recommended)
`op` is the 1Password CLI tool. Point the env values in `app/op.dev.env` to the appropriate Secret References. For a first-time initialization, run
```
op run --env-file app/op.dev.env -- python scripts/db-initialization.py
```
to initialize from an empty MySQL db, and add a test user. Then you can run locally with
```
op run --env-file app/op.dev.env -- flask --app app/app.py --debug run
```

### Usage without 1PW
Copy `app/op.dev.env` to a new file `app/secrets.env`, and fill in the values with the plaintext for the appropriate secrets (be careful!). For a first-time initialization, run
```
(set -a; source app/secrets.env; set +a; python scripts/db-initialization.py)
```
to initialize from an empty MySQL db, and add a test user. Then you can run locally with
```
(set -a; source app/secrets.env; set +a; flask --app app/app.py --debug run)
```

In either case, you can then start playing with the app by visiting `127.0.0.1:5000` in your browser (assuming default Flask settings).
