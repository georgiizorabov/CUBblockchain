# Document signature with RSA

using [open source python lib](https://github.com/sybrenstuvel/python-rsa)

## Usage
```> python3 main.py gen-keys private_key.pem public_key.pem```

```> python3 main.py sign private_key.pem hello_world.txt signed_file```

```> python3 main.py verify public_key.pem hello_world.txt signed_filem```