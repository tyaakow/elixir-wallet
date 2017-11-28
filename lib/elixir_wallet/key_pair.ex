defmodule KeyPair do
  @moduledoc """
  Module for generating master public and private key
  """


  alias Structs.Bip32PubKey
  alias Structs.Bip32PrivKey


  # Constant for generating the private_key / chain_code
  @bitcoin_const "Bitcoin seed"

  # Integers modulo the order of the curve (referred to as n)
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # Mersenne number / TODO: type what it is used for
  @mersenne_prime 2147483647

  @doc """
  Generating a root seed from given mnemonic phrase
  to further ensure uniqueness of master keys.
  ## Example
      iex> KeyPair.generate_root_seed("mnemonic", "pass")

      %{"6C055755B1F6E97DFFC1C40C1BD4919C48938B211139C12C3F04A7F011D8DD20",
      "03C6D13F979E118C97029A3F210AA207CA6695908BA814271472ED1775E4FFBC75",
      <<18, 216, 49, 31, 0, 27, 92, 61, 81, 76, 17, 212, 106, 24, 176, 124, 144, 111,
      182, 17, 157, 236, 54, 168, 91, 92, 99, 234, 76, 232, 20, 169>>
      }
  """
  @spec generate_root_seed(String.t(), String.t(), List.t()) :: Map.t()
  def generate_root_seed(mnemonic, password \\ "", opts \\ []) do
    ## FIX
  end

  def generate_seed(mnemonic, pass_phrase \\ "", opts \\ []) do
    SeedGenerator.generate(mnemonic, pass_phrase, opts)
  end

  def generate_master_key(:seed, seed) do
    generate_master_key(:public, :crypto.hmac(:sha512, @bitcoin_const, seed))
  end

  def generate_master_key(:private, <<priv_key::binary-32, chain_code::binary>>) do
    key = Bip32PrivKey.create(:mainnet)
    key = %{key | key: priv_key, chain_code: chain_code}

    #KeyPair.derive(pub_key, "m/0")
    #KeyPair.format_key(key)
  end
  def generate_master_key(:public, seed) do
    priv_key = KeyPair.generate_master_key(:private, seed)
    pub_key = KeyPair.generate_pub_key(priv_key)
    key = Bip32PubKey.create(:mainnet)
    key = %{key | key: pub_key, chain_code: priv_key.chain_code}

    #IO.inspect key
    KeyPair.derive(key, "m/0")
    #KeyPair.format_key(key)
  end

  def generate_pub_key(%Bip32PrivKey{key: priv_key} = key) do
    {pub_key, _priv_key} = :crypto.generate_key(:ecdh, :secp256k1, priv_key)
    pub_key
  end
  def generate_pub_key(%Bip32PrivKey{key: priv_key} = key, :compressed) do
    KeyPair.generate_pub_key(key)
    |> KeyPair.compress()
    |> Base.decode16!()
  end

  def fingerprint(%Bip32PrivKey{key: priv_key} = key) do
    KeyPair.fingerprint(KeyPair.generate_pub_key(key, :compressed))
  end
  def fingerprint(%Bip32PubKey{key: pub_key} = key) do
    KeyPair.fingerprint(pub_key |> KeyPair.compress() |> Base.decode16!())
  end
  def fingerprint(pub_key) do
    <<f_print::binary-4, _rest::binary>> =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key))
    f_print
  end

  defp serialize(%Bip32PubKey{key: pub_key} = key) do
    compressed_pub_key =
      pub_key
      |> KeyPair.compress()
      |> Base.decode16!()
    {<<key.version::size(32)>>, <<key.depth::size(8), key.f_print::binary-4,
     key.child_num::size(32), key.chain_code::binary, compressed_pub_key::binary>>}
  end
  defp serialize(%Bip32PrivKey{} = key) do
    {<<key.version::size(32)>>, <<key.depth::size(8), key.f_print::binary-4,
     key.child_num::size(32), key.chain_code::binary, <<0::size(8)>>, key.key::binary>>}
  end

  def format_key(key) when is_map(key) do
    IO.inspect key
    {prefix, data} = serialize(key)
    Base58Check.encode58check(prefix, data)
  end

  def derive(key, <<"m/", path::binary>>) do
    KeyPair.derive_pathlist(key, :lists.map(fn(e) ->
      case String.reverse(e) do
        <<"'", hardened::binary>> ->
          {num, _rest} = Integer.parse(String.reverse(hardened))
          final = num + @mersenne_prime + 1
          final
        _ ->
          {num, _rest} = Integer.parse(e)
          num
      end
    end, :binary.split(path, <<"/">>, [:global])))
  end

  def derive_pathlist(key, []) do
    KeyPair.format_key(key)
  end
  def derive_pathlist(key, pathlist) do
    [index | rest] = pathlist
    IO.inspect key
    IO.inspect index
    KeyPair.derive_pathlist(derive_key(key, index), rest)
  end


  def derive_key(%Bip32PrivKey{depth: d} = key, index) when index <= @mersenne_prime do
    # Normal derivation
    {child_key, child_chain} = KeyPair.child_key(key, index)
    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%Bip32PrivKey{depth: d} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    {child_key, child_chain} = KeyPair.child_key(key, index)
    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%Bip32PubKey{depth: d} = key, index) when index <= @mersenne_prime do
    # Normal derivation
    IO.inspect "Parent key"
    IO.inspect key.key
    {child_key, child_chain} = KeyPair.child_key(key, index)
    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(%Bip32PubKey{depth: d} = key, index) when index > @mersenne_prime do
    # Hardned derivation
    {child_key, child_chain} = KeyPair.child_key(key, index)
    KeyPair.derive_key(key, child_key, child_chain, index)
  end

  def derive_key(key, child_key, child_chain, index) when is_map(key) do
    key = %{key |
            key: child_key,
            chain_code: child_chain,
            depth: key.depth+1,
            f_print: KeyPair.fingerprint(key),
            child_num: index}
  end


  def child_key(%Bip32PrivKey{key: parent_key, chain_code: parent_chain_code} = key, index) do
    <<derived_key::size(256), child_chain_code::binary>> =
    if index > @mersenne_prime do # Hardned child
      :crypto.hmac(:sha512,
        parent_chain_code,
        <<0::size(8), parent_key::binary, index::size(32)>>)
    else # Normal child
      compressed_pub_key =
        KeyPair.generate_pub_key(key, :compressed)

      :crypto.hmac(:sha512,
        parent_chain_code,
        <<compressed_pub_key::binary, index::size(32)>>)
    end

    <<parent_key_int::size(256)>> = parent_key
    child_key = rem(derived_key + parent_key_int, @n)

    {<<child_key::size(256)>>, child_chain_code}
  end




  def child_key(%Bip32PubKey{key: parent_key, chain_code: parent_chain_code} = key, index) do
    serialized_public_key =
      parent_key
      |> KeyPair.compress()
      |> Base.decode16!()

    <<derived_key::size(256), child_chain_code::binary>> =
    if index >= :math.pow(2, 31) do # Hardned child
      raise("Hardened child")
    else # Normal child
      :crypto.hmac(:sha512,
        parent_chain_code,
        <<serialized_public_key::binary, index::size(32)>>)
    end

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, derived_key)

    # Convert to integer value
    point_int =
      point
      |> Bits.to_binary_list()
      |> Enum.join()
      |> Integer.parse(2)
      |> elem(0)

    # Convert to integer value Refactor this!!!!!!!!!!!!!!!!!!!!!!!
    parent_key_int =
      parent_key
      |> Bits.to_binary_list()
      |> Enum.join()
      |> Integer.parse(2)
      |> elem(0)

    child_pub_key =  point_int + parent_key_int
    {:binary.encode_unsigned(child_pub_key), child_chain_code}
  end

  @doc """
  Generates wallet address from a given public key
  ## Example
      iex> KeyPair.generate_wallet_address("03AE1B3F8386C6F8B08745E290DA4F7B1B6EBD2287C2505567A2A311BA09EE53F3")
      '1C7RcPXiqwnaJgfvLmoicS3AaBGYyKbiW8'
  """
  @spec generate_wallet_address(String.t()) :: String.t()
  def generate_wallet_address(public_key) do
    public_sha256 = :crypto.hash(:sha256, Base.decode16!(public_key))

    public_ripemd160 = :crypto.hash(:ripemd160, public_sha256)

    # Network ID bytes:
    # Main Network = "0x00"
    # Test Network = "0x6F"
    # Namecoin Net = "0x34"
    public_add_netbytes = <<0x00::size(8), public_ripemd160::binary>>

    checksum = :crypto.hash(:sha256,
      :crypto.hash(:sha256, public_add_netbytes))

    checksum_32bits = <<checksum::binary-4>>

    public_add_netbytes <> checksum_32bits
    |> Base58Check.encode58()
  end

  def compress(point) do
    first_half =
      point
      |> Base.encode16()
      |> String.slice(2, 128)
      |> String.slice(0, 64)

    second_half =
      point
      |> Base.encode16()
      |> String.slice(2, 128)
      |> String.slice(64, 64)

    {last_digit_int, _} =
      second_half
      |> String.slice(63, 63)
      |> Integer.parse(16)

    case rem(last_digit_int, 2) do
      0 ->
        "02" <> first_half
      _ ->
        "03" <> first_half
    end
  end
end
