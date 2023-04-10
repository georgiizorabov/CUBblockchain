import rsa
import argparse

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='RSA key generation and signature verification')

    subparsers = parser.add_subparsers(help='sub-command help')

    gen_keys_parser = subparsers.add_parser('gen-keys', help='generate RSA key pair')
    gen_keys_parser.set_defaults(command='gen-keys')

    gen_keys_parser.add_argument('privateKeyfile', help='filename for the generated private key')
    gen_keys_parser.add_argument('publicKeyfile', help='filename for the generated public key')
    gen_keys_parser.add_argument('-s', '--key-size', type=int, default=2048,
                                 help='size of the RSA key in bits (default: 2048)')
    gen_keys_parser.set_defaults(command='gen_keys')

    sign_parser = subparsers.add_parser('sign', help='sign a file with an RSA private key')
    sign_parser.add_argument('keyfile', help='filename of the RSA private key to use for signing')
    sign_parser.add_argument('input_file', help='filename of the input file to sign')
    sign_parser.add_argument('output_file', help='filename for the signed output file')
    sign_parser.set_defaults(command='sign')

    verify_parser = subparsers.add_parser('verify',
                                          help='verify the signature of a file with an RSA public key')
    verify_parser.add_argument('keyfile', help='filename of the RSA public key to use for signature verification')
    verify_parser.add_argument('input_file', help='filename of the input file to verify')
    verify_parser.add_argument('signature_file', help='filename of the signature to verify')
    verify_parser.set_defaults(command='verify')

    args = parser.parse_args()
    print(getattr(args, 'command', None))
    if getattr(args, 'command', None) == 'gen_keys':
        print(
            f'Generating RSA key pair with key size {args.key_size} bits and saving to {args.privateKeyfile} and {args.publicKeyfile}...')
        (public_key, private_key) = rsa.newkeys(2048)

        with open(args.privateKeyfile, 'wb') as f:
            f.write(private_key.save_pkcs1())

        with open(args.publicKeyfile, 'wb') as f:
            f.write(public_key.save_pkcs1())

    elif getattr(args, 'command', None) == 'sign':
        print(f'Signing {args.input_file} with RSA private key {args.keyfile} and saving to {args.output_file}...')

        with open(args.input_file, 'rb') as f:
            text = f.read()

        with open(args.keyfile, 'rb') as private_key_file:
            private_key_data = rsa.PrivateKey.load_pkcs1(private_key_file.read())

        signature = rsa.sign(text, private_key_data, 'SHA-256')

        with open(args.output_file, 'wb') as f:
            f.write(signature)

    elif getattr(args, 'command', None) == 'verify':
        print(
            f'Verifying the signature of {args.input_file} using RSA public key {args.keyfile} and signature file {args.signature_file}...')
        with open(args.keyfile, mode='rb') as public_key_file:
            public_key_data = public_key_file.read()

        public_key = rsa.PublicKey.load_pkcs1(public_key_data)

        with open(args.signature_file, mode='rb') as signature_file:
            signature = signature_file.read()

        with open(args.input_file, mode='rb') as data_file:
            data = data_file.read()

        try:
            rsa.verify(data, signature, public_key)
            print('Signature is valid')
        except rsa.VerificationError:
            print('Signature is invalid')
    if not hasattr(args, 'command'):
        parser.print_help()
