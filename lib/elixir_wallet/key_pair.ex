defmodule KeyPair do
  @moduledoc """
  Module for generating master public and private key
  """

  # Integers modulo the order of the curve (referred to as n)
  @n 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

  # Network versions
  @mainnet_ext_priv_key_version 0x0488ADE4
  @mainnet_ext_pub_key_version  0x0488B21E
  @testnet_ext_priv_key_version 0x04358394
  @testnet_ext_pub_key_version  0x043587CF

  # Mersenne number / TODO: type what it is used for
  @mersenne_prime 2147483647

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
    private_key_dec = generate_master_private_key(seed)
    public_key_bin = generate_master_public_key(private_key_dec)
    chain_code = generate_chain_code(seed)

    private_key_bin = <<private_key_dec::size(256)>>

    #child_private_key_derivation(private_key_int, chain_code, 1)
    #child_public_key_derivation(public_key_bin, chain_code, 1)

    private_key_hex = private_key_bin |> Base.encode16()
    public_key_hex = public_key_bin |> Base.encode16()

    {private_key_hex, public_key_hex, chain_code}
  end

  def generate_master_private_key(seed) do
    <<private_key::size(256), _::binary>> =
      :crypto.hmac(:sha512, "Bitcoin seed", seed)

    if private_key != 0 or private_key >= @n do
      private_key
    else
      raise("Key Generation error")
    end
  end

  def generate_chain_code(seed) do
    <<_::size(256), chain_code::binary>> =
      :crypto.hmac(:sha512, "Bitcoin seed", seed)
    chain_code
  end

  def generate_master_public_key(private_key_dec) do
    {public_key, _} =
      :crypto.generate_key(:ecdh, :secp256k1, private_key_dec)
    public_key
  end

  def derive_extend_pub_key(seed, network \\ :mainnet) do
    pub_key_ser =
      generate_master_private_key(seed)
      |> generate_master_public_key()
      |> Base.encode16()
      |> serialize()
    key = %{network: network,
            key_type: :public,
            key_ser: pub_key_ser,
            chain_code: generate_chain_code(seed),
            depth: @depth,
            child_num: @child_num,
            f_print: @fingerprint}
    build_ext_key(key)
  end

  def derive_extend_priv_key(seed, network \\ :mainnet) do
    priv_key_ser = <<0x00::size(8),  generate_master_private_key(seed)::size(256)>>
    key = %{network: network,
            key_type: :private,
            key_ser: priv_key_ser,
            chain_code: generate_chain_code(seed),
            depth: @depth,
            child_num: @child_num,
            f_print: @fingerprint}
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
    build_ext_key(version,
      key.depth,
      key.f_print,
      key.child_num,
      key.chain_code,
      key.key_ser)
  end
  defp build_ext_key(@mainnet_ext_priv_key_version, depth, f_print, c_num, chain_code, key) do
    concat(@mainnet_ext_priv_key_version, depth, f_print, c_num, chain_code, key)
  end
  defp build_ext_key(@mainnet_ext_pub_key_version, depth, f_print, c_num, chain_code, key) do
    concat(@mainnet_ext_pub_key_version, depth, f_print, c_num, chain_code, key)
  end
  defp build_ext_key(@testnet_ext_priv_key_version, depth, f_print, c_num, chain_code, key) do
    concat(@testnet_ext_priv_key_version, depth, f_print, c_num, chain_code, key)
  end
  defp build_ext_key(@testnet_ext_pub_key_version, depth, f_print, c_num, chain_code, key) do
    concat(@testnet_ext_pub_key_version, depth, f_print, c_num, chain_code, key)
  end

  defp concat(version, depth, f_print, c_num, chain_code, key) do
    add_checksum(<<version::size(32),
      depth::size(8),
      f_print::size(32),
      c_num::size(32),
      chain_code::binary,
      key::binary>>)
  end

  defp add_checksum(data_bin) do
    {double_sha256_dec, _} =
      :crypto.hash(:sha256, :crypto.hash(:sha256, data_bin))
      |> Base.encode16()
      |> Integer.parse(16)

    checksum = <<double_sha256_dec::size(32)>>

    extended_key = data_bin <> checksum
    encode(extended_key)
  end

  def encode(hex) do
    Base58Check.encode58(hex)
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
  @spec child_private_key_derivation(Integer.t(), Binary.t(), Integer.t()) :: Tuple.t()
  def child_private_key_derivation(parent_private_key, parent_chain_code, index) do
    serialized_private_key = <<parent_private_key::size(256)>>
    serialized_index = <<index::size(32)>>

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, serialized_private_key)
    serialized_point =
      point
      |> serialize()
      |> Base.decode16()
      |> elem(1)

    <<child_type::size(256), child_chain_code::binary>> =
    if index >= :math.pow(2, 31) do
      # Hardned child
      # Note: The 0x00 pads the private key to make it 33 bytes long
      :crypto.hmac(:sha512,
        parent_chain_code,
        <<0x00>> <> serialized_private_key <> serialized_index)
    else
      # Normal child
      :crypto.hmac(:sha512,
        parent_chain_code,
        serialized_point <> serialized_index)
    end

    child_private_key =  child_type + rem(parent_private_key, @n)

    {:ok, child_private_key, child_chain_code}
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
  @spec child_public_key_derivation(Binary.t(), Binary.t(), Integer.t())
  :: {:ok, child_public_key :: Integer.t(), child_chain_code :: Binary.t()}
  def child_public_key_derivation(parent_public_key, parent_chain_code, index) do
    serialized_index = <<index::size(32)>>
    serialized_public_key =
      parent_public_key
      |> serialize()
      |> Base.decode16()
      |> elem(1)

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

    {:ok, child_public_key, child_chain_code}
  end

  @doc """
  Generates wallet address from a given public key
  ## Example
      iex> KeyPair.generate_wallet_address("03AE1B3F8386C6F8B08745E290DA4F7B1B6EBD2287C2505567A2A311BA09EE53F3")
      '1C7RcPXiqwnaJgfvLmoicS3AaBGYyKbiW8'
  """
  @spec generate_wallet_address(String.t()) :: char
  def generate_wallet_address(public_key) do
    public_sha256 = :crypto.hash(:sha256,
      public_key
      |> Base.decode16()
      |> elem(1))

    public_ripemd160 =
      :crypto.hash(:ripemd160, public_sha256)
      |> Base.encode16()

    # Network ID bytes:
    # Main Network = "0x00"
    # Test Network = "0x6F"
    # Namecoin Net = "0x34"
    public_add_netbytes = "00" <> public_ripemd160

    checksum = :crypto.hash(:sha256,
      :crypto.hash(:sha256,
        public_add_netbytes
        |> Base.decode16()
        |> elem(1)))

    slice_four_bytes =
      checksum
      |> Base.encode16()
      |> String.slice(0..7)

    public_add_netbytes <> slice_four_bytes
    |> Base.decode16()
    |> elem(1)
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
