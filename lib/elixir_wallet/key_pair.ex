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

  # Network versions
  @mainnet_ext_priv_key_version 0x0488ADE4
  @mainnet_ext_pub_key_version  0x0488B21E
  @testnet_ext_priv_key_version 0x04358394
  @testnet_ext_pub_key_version  0x043587CF

  # Default depth, child_num and fingerprint values, needed for extended keys
  @depth 0
  @child_num 0
  @fingerprint 0

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
    generate_master_keys(SeedGenerator.generate(mnemonic, password, opts))
  end

  def generate_master_keys(seed) do
    private_key_bin = generate_master_private_key(seed)
    public_key_bin = generate_master_public_key(private_key_bin)
    chain_code = generate_chain_code(seed)

    private_key_hex = private_key_bin |> Base.encode16()
    public_key_hex = public_key_bin |> Base.encode16()

    {private_key_hex, public_key_hex, chain_code}
  end





  def generate_seed(mnemonic, pass_phrase \\ "", opts \\ []) do
    SeedGenerator.generate(mnemonic, pass_phrase, opts)
  end

  def generate_master_key(:seed, seed) do
    generate_master_key(:private, :crypto.hmac(:sha512, @bitcoin_const, seed))
  end

  def generate_master_key(:private, <<priv_key::binary-32, chain_code::binary>>) do
    key = Bip32PrivKey.create(:mainnet)
    key = %{key | key: priv_key, chain_code: chain_code}
    KeyPair.derive(key, "m/0'/1")
  end

  def derive(key, <<"m/", path::binary>>) do
    derive_pathlist(key, :lists.map(fn(e) ->
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
    concat(
      key.version,
      key.depth,
      key.f_print,
      key.child_num,
      key.chain_code,
      <<0::8, key.key::binary>>)
  end
  def derive_pathlist(key, pathlist) do
    [index | rest] = pathlist
    derive_pathlist(derive_key(key, index), rest)
  end

  def derive_key(%Bip32PrivKey{key: priv_key, chain_code: c, depth: d} = key, index) when index > @mersenne_prime do
    {child_key, child_chain} =
      KeyPair.child_private_key_derivation(priv_key, c, index)
    f_print =
      priv_key
      |> KeyPair.generate_master_public_key()
      |> KeyPair.serialize()
      |> Base.decode16!()
      |> KeyPair.fingerprint()
    key = %{key |
            key: child_key,
            chain_code: child_chain,
            depth: d+1,
            f_print: f_print,
            child_num: index}
  end

  def derive_key(%Bip32PrivKey{key: priv_key, chain_code: c, depth: d} = key, index) when index <= @mersenne_prime do

    IO.inspect priv_key
    {child_key, child_chain} =
      KeyPair.child_private_key_derivation(priv_key, c, index)
    f_print =
      priv_key
      |> KeyPair.generate_master_public_key()
      |> KeyPair.serialize()
      |> Base.decode16!()
      |> KeyPair.fingerprint()


    IO.inspect child_key
    IO.inspect child_chain

    key = %{key |
            key: child_key,
            chain_code: child_chain,
            depth: d+1,
            f_print: f_print,
            child_num: index}
  end

































  @doc """
  Generates Master Private key from a given seed
  ## Example
      iex> KeyPair.generate_master_private_key(seed)
      <<151, 43, 128, 234, 7, 64, 2, 5, 246, 177, 61, 95, 255, 74, 81, 153, 86, 29,
      239, 10, 108, 166, 204, 112, 64, 109, 229, 173, 36, 71, 148, 12>>
  """
  @spec generate_master_private_key(String.t()) :: Binary.t()
  def generate_master_private_key(seed) do
    <<private_key::binary-32, _::binary>> =
      :crypto.hmac(:sha512, @bitcoin_const, seed)

    if private_key != 0 or private_key >= @n do
      private_key
    else
      raise("Key Generation error")
    end
  end

  @doc """
  Generates Master chain_code from a given seed
  ## Example
     iex> KeyPair.generate_chain_code(seed)
     <<67, 167, 253, 44, 27, 74, 166, 183, 104, 36, 28, 188, 67, 240, 121, 58, 216,
     119, 74, 55, 209, 147, 185, 140, 59, 235, 107, 66, 128, 219, 120, 99>>
  """
  @spec generate_chain_code(String.t()) :: Binary.t()
  def generate_chain_code(seed) do
    <<_::binary-32, chain_code::binary>> =
      :crypto.hmac(:sha512, @bitcoin_const, seed)
    chain_code
  end


  @doc """
  Generates Master Public key from a given private key
  ## Example
      iex>> KeyPair.generate_master_public_key(private_key_bin)
      <<4, 65, 105, 235, 146, 231, 187, 34, 143, 142, 44, 32, 142, 66, 87, 92, 38, 30,
      180, 56, 200, 2, 237, 56, 42, 88, 77, 74, 0, 77, 235, 17, 217, 199, 70, 191,
      237, 30, 191, 249, 56, 198, 25, 138, 229, 249, 62, 16, 88, 210, ...>>
  """
  def generate_master_public_key(private_key_bin) do
    {public_key, _} =
      :crypto.generate_key(:ecdh, :secp256k1, private_key_bin)
    public_key
  end

  @doc """
  Derives an Extended Public key from a given seed and network
  If a network is not specified, :mainnet will be used
  ## Example
      iex> KeyPair.derive_extend_pub_key(seed)
      "xpub661MyMwAqRbcEicePgnmzt4kZxe4LSejJB5hN2xzQb3BVgBQXCnSDe869u2C66h97g3QiSmoPL2XfhLQ7ro9rjGncqrvzuimLY6T3Rrco2s"

      iex> KeyPair.derive_extend_pub_key(seed, :testnet)
      "tpubD6NzVbkrYhZ4WWoVqsmsCoQ7u5jiKq9nqofzib28kVo5Exr7bRdXN5nvPw6ycbeNuaaKL2HfvRraMsq1WiePkAj5gScEgSNzvVgroTkVymv"
  """
  @spec derive_extend_pub_key(integer(), integer(), integer(), binary(), binary(), tuple()) :: String.t()
  def derive_extend_pub_key(depth,  f_print, c_num, pub_key_ser, chain_code, network \\ :mainnet) do
    #seed_bin = Base.decode16!(seed_hex, case: :mixed)
    #pub_key_ser =
    #  generate_master_private_key(seed_bin)
    #  |> generate_master_public_key()
    #  |> serialize()
    #  |> Base.decode16!()
    key = %{network: network,
            depth: depth,
            f_print: f_print,
            child_num: c_num,
            chain_code: chain_code,
            key_ser: pub_key_ser,
            key_type: :public}
    build_ext_key(key)
  end

  @doc """
  Derives an Extended Private key from a given seed and network
  If a network is not specified, :mainnet will be used
  ## Example
      iex> KeyPair.derive_extend_priv_key(seed)
      "xprv9s21ZrQH143K2EYBHfFmdk821voZvyvsvxA6ZeZNrFWCcsrFyfUBfqocJdfZJYiSJxUQNVhjm36JXscMc4QcHhQsgBFq44zubmcoT9q4ptD"

      iex> KeyPair.derive_extend_priv_key(seed, :testnet)
      "tprv8ZgxMBicQKsPd3mhxE7GoPk1L4DnAVxtGW5DS4yqLDzgQUbLy2owBbB4DoqDJv6kgQ1BNbKVvPg6zjA6jGkZ6kgUCpU8iRixWsNDtmesuag"
  """
  @spec derive_extend_priv_key(integer(), integer(), integer(), binary(), binary(), tuple()) :: String.t()
  def derive_extend_priv_key(depth,  f_print, c_num, priv_key, chain_code, network \\ :mainnet) do
    #seed_bin = Base.decode16!(seed_hex, case: :mixed)
    #priv_key_ser = <<0x00::size(8), generate_master_private_key(seed_bin)::binary>>

    priv_key_ser =
      case is_integer(priv_key) do
       true -> <<0::8, priv_key::size(256)>>
       false -> <<0::8, priv_key::binary>>
      end
    key = %{network: network,
            depth: depth,
            f_print: f_print,
            child_num: c_num,
            chain_code: chain_code,
            key_ser: priv_key_ser,
            key_type: :private}
    build_ext_key(key)
  end

  defp build_ext_key(%{network: :mainnet, key_type: :private} = key) do
    build_ext_key(key, @mainnet_ext_priv_key_version)
  end
  defp build_ext_key(%{network: :mainnet, key_type: :public} = key) do
    build_ext_key(key, @mainnet_ext_pub_key_version)
  end
  defp build_ext_key(%{network: :testnet, key_type: :private} = key) do
    build_ext_key(key, @testnet_ext_priv_key_version)
  end
  defp build_ext_key(%{network: :testnet, key_type: :public} = key) do
    build_ext_key(key, @testnet_ext_pub_key_version)
  end
  defp build_ext_key(key, version) do
    concat(
      version,
      key.depth,
      key.f_print,
      key.child_num,
      key.chain_code,
      key.key_ser)
  end

  defp concat(version, depth, f_print, c_num, chain_code, key) do
    #add_checksum(
    #  <<version    :: size(32),
    #    depth      :: size(8),
    #    f_print    :: size(32),
    #    c_num      :: size(32),
    #    chain_code :: binary,
    #    key        :: binary>>)

    {<<version    :: size(32),
       depth      :: size(8),
       f_print    :: binary-4,
       c_num      :: size(32),
       chain_code :: binary,
       key        :: binary>>,
     Base58Check.encode58check(
       <<version    :: size(32)>>,
       <<depth      :: size(8),
         f_print    :: binary-4,
         c_num      :: size(32),
         chain_code :: binary,
         key        :: binary>>)}
  end

  defp add_checksum(struct_bin) do
    double_hash = :crypto.hash(:sha256, :crypto.hash(:sha256, struct_bin))
    checksum = <<double_hash::binary-4>>
    extended_key = <<struct_bin::binary, checksum::binary>>
    Base58Check.encode58(extended_key)
  end

  def fingerprint(pub_key_bin) do
    <<fingerprint::binary-4, _rest::binary>> =
      :crypto.hash(:ripemd160, :crypto.hash(:sha256, pub_key_bin))
    fingerprint
  end


  @doc """
  Derives a Child private key from the Parent private key,
  the Parent chain code and an Index.
  Each child key has an index:
  - The normal child keys use indices 0 through 2^31-1.
  - The hardened child keys use indices 2^31 through 2^32-1.

  ## Example
      iex> KeyPair.child_private_key_derivation(parent_private_key, parent_chain_code, index)
      {:ok,
      61797785181236811324249699338969637019663168756836175393579080078724476532284,
      <<86, 58, 152, 23, 56, 221, 230, 127, 46, 28, 224, 1, 196, 29, 147, 26, 60, 87,
      154, 143, 242, 166, 99, 249, 89, 18, 116, 169, 175, 233, 182, 13>>}
  """
  @spec child_private_key_derivation(integer(), binary(), integer()) :: tuple()
  def child_private_key_derivation(parent_private_key, parent_chain_code, index) do
    <<child_type::binary-32, child_chain_code::binary>> =
    if index > @mersenne_prime do
      # Hardned child
      # Note: The 0x00 pads the private key to make it 33 bytes long
      :crypto.hmac(:sha512,
        parent_chain_code,
        <<0::8, parent_private_key::binary, index::size(32)>>)
    else
      # Normal child
      compressed_pub_key =
        generate_master_public_key(parent_private_key)
        |> serialize()
        |> Base.decode16!()

      IO.inspect compressed_pub_key

      :crypto.hmac(:sha512,
        parent_chain_code,
        <<compressed_pub_key::binary, index::size(32)>>)
    end

    IO.inspect child_type

    <<child_type_int::size(256)>> = child_type
    <<private_key_int::size(256)>> = parent_private_key
    child_private_key = child_type_int + rem(private_key_int, @n)

    {<<child_private_key::size(256)>>, child_chain_code}
  end

  @doc """
  Derives a Child public key from the Parent public key,
  the Parent chain code and an Index. Each child key has an index
  The normal child keys use indices 0 through 2^31-1.
  The hardened child keys use indices 2^31 through 2^32-1.

  ## Example
      iex> KeyPair.child_public_key_derivation(parent_public_key, parent_chain_code, index)
      {:ok,
      127652518182151425556078170022681412997553383754584782294509495601321664751124755532434492424716420923497491690018425271974096974768674940535524619008798327,
      <<86, 58, 152, 23, 56, 221, 230, 127, 46, 28, 224, 1, 196, 29, 147, 26, 60, 87,
      154, 143, 242, 166, 99, 249, 89, 18, 116, 169, 175, 233, 182, 13>>}

  """
  @spec child_public_key_derivation(binary(), binary(), integer())
  :: {:ok, child_public_key :: integer(), child_chain_code :: binary()}
  def child_public_key_derivation(parent_public_key, parent_chain_code, index) do
    serialized_index = <<index::size(32)>>
    serialized_public_key =
      parent_public_key
      |> serialize()
      |> Base.decode16!()

    <<child_type::size(256), child_chain_code::binary>> =
    if index >= :math.pow(2, 31) do
      # Hardned child
      raise("Hardened child")
    else
      # Normal child
        :crypto.hmac(:sha512,
          parent_chain_code,
          serialized_public_key  <> serialized_index)
    end

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, child_type)

    # Convert to integer value
    point_int =
      point
      |> Bits.to_binary_list()
      |> Enum.join()
      |> Integer.parse(2)
      |> elem(0)

    # Convert to integer value
    pub_int =
      parent_public_key
      |> Bits.to_binary_list()
      |> Enum.join()
      |> Integer.parse(2)
      |> elem(0)

    child_public_key =  point_int + pub_int

    {child_public_key, child_chain_code}
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

  def serialize(point) do
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
