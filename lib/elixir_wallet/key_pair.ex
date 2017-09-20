defmodule KeyPair do

  def keypair() do
    private_key_file = "ec_private_key.pem"
    public_key_file = "ec_public_key.pem"

    {private_key, public_key} = generate_keypair()
    address = generate_wallet_address(public_key)
    overwrite__keypair_file(private_key_file, public_key_file)

    {private_key, public_key, address}
  end

  defp generate_wallet_address(public_key) do
      public_sha256 = :crypto.hash(:sha256, public_key) |> Base.encode16()
      public_ripemd160 = :crypto.hash(:ripemd160, public_sha256) |> Base.encode16()
      public_add_netbytes = "00" <> public_ripemd160
      public_sha256_netbytes = :crypto.hash(:sha256, public_add_netbytes) |> Base.encode16()
      public_sha256_netbytes_2 = :crypto.hash(:sha256, public_sha256_netbytes) |> Base.encode16()
      slice_four_bytes = public_sha256_netbytes_2 |> to_string() |> String.slice(0..7)
      append_four_bytes_to_netbytes = public_add_netbytes <> slice_four_bytes
      Base.decode16(append_four_bytes_to_netbytes) |> elem(1) |> :base58.binary_to_base58
  end

  defp generate_keypair() do
    :os.cmd('openssl ecparam -genkey -name secp256k1 -noout -out ec_private_key.pem')
    :os.cmd('openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem')
    private_key = :os.cmd('openssl ec -in ec_private_key.pem -outform DER|tail -c +8|head -c 32|xxd -p -c 32')
    public_key = :os.cmd('openssl ec -in ec_private_key.pem -pubout -outform DER|tail -c 65|xxd -p -c 65')
    parse_keypair_file(private_key, public_key)
  end

  defp parse_keypair_file(private_key, public_key) do
    private_key = private_key |> to_string() |> String.split("\n") |> Enum.at(2) |> String.upcase
    public_key = public_key |> to_string() |> String.split("\n") |> Enum.at(2) |> String.upcase
    {private_key, public_key}
  end

  defp overwrite__keypair_file(private_key_file, public_key_file) do
    # Overwrite with random to ensure non-retrieval of keys
    {:ok, priv} = File.read(private_key_file)
    {:ok, pub} = File.read(public_key_file)

    File.copy("/dev/random", private_key_file, byte_size(priv))
    File.copy("/dev/random", public_key_file, byte_size(pub))

    {_, 0} = System.cmd "rm", ["-f", private_key_file]
    {_, 0} = System.cmd "rm", ["-f", public_key_file]
  end

end
