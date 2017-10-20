defmodule KeyPair do
  @moduledoc """
  Module for generating master public and private key
  """

  @doc """
  Generating a root seed from given mnemonic phrase
  to further ensure uniqueness of master keys.
  ## Example
      iex> KeyPair.generate_root_seed("mnemonic", "pass", [iterations: 2048, digest: :sha512])

      %{address: '177Phoj5VzFGNH7JUPLKD7pVauJEUzwEky',
      private_key: "CF92B127F1A8F2931261830CE8AA79E6E35AA2AB6E97A5FED2D5EB459744A762",
      public: "02A87C141516843F07C37EE3AE4F1C6A56E5A212076F4756F85122AE42B2FD8062"}
  """
  @spec generate_root_seed(String.t(), String.t(), List.t()) :: Map.t()
  def generate_root_seed(mnemonic, password, opts \\ []) do
    generate_master_keys(KeyGenerator.generate(mnemonic, password, opts))
  end

  def generate_master_keys(seed) do
    <<private_int::size(256), chain_code::binary>> = seed
    private_key = <<private_int::256>> |> Base.encode16()

    {public_bin, _} = :crypto.generate_key(:ecdh, :secp256k1, private_int)
    public_short = public_bin |> serialize()

    child_private_key_derivation(private_int, chain_code, 1)
    child_public_key_derivation(public_bin, chain_code, 1)

    {private_key, public_short, chain_code}
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
  @spec child_private_key_derivation(Integer.t(), Binary.t(), Integer.t())
  :: {:ok, child_private_key :: Integer.t(), child_chain_code :: Binary.t()}
  def child_private_key_derivation(parent_private_key, parent_chain_code, index) do
    serialized_private_key = <<parent_private_key::size(256)>>
    serialized_index = <<index::size(32)>>

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, serialized_private_key)
    serialized_point =
      point
      |> serialize()
      |> Base.decode16()
      |> elem(1)

    child_type = if index >= :math.pow(2, 31) do
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

    # Split into two 32-byte sequances and take the left one
    <<i_left::size(256), child_chain_code::binary>> = child_type

    base = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    child_private_key =  i_left + rem(parent_private_key, base)

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

    child_type = if index >= :math.pow(2, 31) do
      # Hardned child
      raise("Hardened child")
    else
      # Normal child
        :crypto.hmac(:sha512,
          parent_chain_code,
          serialized_public_key  <> serialized_index)
    end

    # Split into two 32-byte sequances and take the left one
    <<i_left::size(256), child_chain_code::binary>> = child_type

    {point, _} = :crypto.generate_key(:ecdh, :secp256k1, i_left)

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
  Generates wallet address from a given piblic key
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

    public_add_netbytes = "00" <> public_ripemd160

    public_sha256_netbytes = :crypto.hash(:sha256,
      public_add_netbytes
      |> Base.decode16()
      |> elem(1))

    public_sha256_netbytes_2 = :crypto.hash(:sha256, public_sha256_netbytes)

    slice_four_bytes =
      public_sha256_netbytes_2
      |> Base.encode16()
      |> String.slice(0..7)

    public_add_netbytes <> slice_four_bytes
    |> Base.decode16()
    |> elem(1)
    |> :base58.binary_to_base58
  end

  defp serialize(point) do
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
