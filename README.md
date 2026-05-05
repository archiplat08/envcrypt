# envcrypt

> Lightweight utility to encrypt and manage `.env` files using [age](https://github.com/FiloSottile/age) encryption for team secrets sharing.

---

## Installation

```bash
pip install envcrypt
```

Requires [`age`](https://github.com/FiloSottile/age#installation) to be installed on your system.

---

## Usage

**Encrypt a `.env` file:**

```bash
envcrypt encrypt .env --recipients recipients.txt --output .env.age
```

**Decrypt a `.env` file:**

```bash
envcrypt decrypt .env.age --identity ~/.age/key.txt --output .env
```

**Generate a new age key pair:**

```bash
envcrypt keygen
```

**Python API:**

```python
from envcrypt import encrypt_env, decrypt_env

encrypt_env(".env", recipients=["age1ql3z7hjy..."], output=".env.age")
decrypt_env(".env.age", identity="~/.age/key.txt", output=".env")
```

---

## Workflow

1. Each team member generates an age key pair with `envcrypt keygen`
2. Add public keys to a shared `recipients.txt`
3. Encrypt your `.env` and commit `.env.age` to version control
4. Team members decrypt locally using their private key

> ⚠️ Never commit your `.env` or private key. Add them to `.gitignore`.

---

## Contributing

Pull requests are welcome. Please open an issue first to discuss any major changes.

---

## License

[MIT](LICENSE)