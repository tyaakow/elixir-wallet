# ElixirWallet

# Creation of mnemonic phrase
The mnemonic phrase is created following the [BIP-0039](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

```elixir
indexes = GenerateIndexes.generate_indexes()
Mnemonic.generate_phrase(indexes)
```
<img src="https://raw.githubusercontent.com/bitcoinbook/bitcoinbook/second_edition/images/mbc2_0506.png" width="400" height="400"/>

Further info in the [bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/second_edition/ch05.asciidoc#mnemonic-code-words-bip-39)


# Creation of master public and private key

## From Mnemonic to seed


First we create a seed from the already generated mnemonic phrase

```elixir
seed = KeyGenerator.generate(mnemonic, pass_phrase, opts) 
``` 
where for options we add the following: [iterations: 2048, digest: :sha512]

A user may decide to protect their mnemonic with a passphrase. If a passphrase is not present, an empty string "" is used instead.

To create a binary seed from the mnemonic, we use the PBKDF2 function with a mnemonic sentence (in UTF-8 NFKD) used as the password and the string 		"mnemonic" + passphrase (again in UTF-8 NFKD) used as the salt. The iteration count is set to 2048 and HMAC-SHA512 is used as the pseudo-random 	function. The length of the derived key is 512 bits (= 64 bytes).

This seed is later used to generate deterministic wallets using [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

Further info in the [bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/second_edition/ch05.asciidoc#from-mnemonic-to-seed)

  
## Creating HD Wallet from the Seed
Following the [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)


HD wallets are created from a single root seed, which is a 128-, 256-, or 512-bit random number. Most commonly, this seed is generated from a mnemonic as detailed in the previous section.

Every key in the HD wallet is deterministically derived from this root seed, which makes it possible to re-create the entire HD wallet from that seed in any compatible HD wallet. This makes it easy to back up, restore, export, and import HD wallets containing thousands or even millions of keys by simply transferring only the mnemonic that the root seed is derived from.

Further info in the [bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/second_edition/ch05.asciidoc#creating-an-hd-wallet-from-the-seed)


### Creating master private key and chain code from a root seed


Generate a seed byte sequence S of a chosen length (between 128 and 512 bits; 256 bits is advised) from a (P)RNG.
Calculate I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
Split I into two 32-byte sequences, IL and IR.
Use parse256(IL) as master secret key, and IR as master chain code.

In case IL is 0 or ≥ n, the master key is invalid (where 'n' is Integers modulo the order of the curve)

n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141) check the [Secp256k1](https://en.bitcoin.it/wiki/Secp256k1)

The private key is generated using the crypto module from [erlang crypto module](http://erlang.org/doc/man/crypto.html#hmac-3)
```erlang
:crypto.hmac(Type, Key, Data) -> Mac
```

* As Type we use :sha512
* As Key we use "Bitcoin seed"
* As Data we use the seed

To generate the Master Private key use the following function:
```elixir
master_private_key = KeyPair.generate_master_private_key(seed)
```


### Creating master Public key

	
The public key is generated using the crypto module from [erlang crypto module](http://erlang.org/doc/man/crypto.html#generate_key-2)
```erlang
:crypto.generate_key(Type, Params, PrivKeyIn) -> {PublicKey, PrivKeyOut}
```

* As Type we use :ecdh
* As Params we use :secp256k1
* As PrivKeyIn we use the decimal value of the Master Private key

To generate the Master Public key we use the following function:
```elixir
master_public_key = KeyPair.generate_master_public_key(master_private_key)
```

Further info in the [bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/second_edition/ch04.asciidoc#public-keys)


### Creating the Address


Shows how to convert Public key into Address

<img src="https://en.bitcoin.it/w/images/en/9/9b/PubKeyToAddr.png" width="400" height="500"/>

Further in the [bitcoinwiki](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses) and in the [bitcoinbook](https://github.com/bitcoinbook/bitcoinbook/blob/second_edition/ch04.asciidoc#bitcoin-addresses)


## Installation


If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `elixir_wallet` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:elixir_wallet, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/elixir_wallet](https://hexdocs.pm/elixir_wallet).

