defmodule Wallet do

  def create_wallet(password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open file, [:write]
    {private, public} = KeyPair.keypair()
    address = generate_wallet_address(public)
    data = %{private_key: private, public: public, address: address}
    phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    IO.puts("Use the following phrase as additional authentication when accessing your wallet:\n#{phrase}")
    encrypted = WalletCrypto.encrypt_wallet(data, password,phrase |> to_string)

    IO.binwrite(file, encrypted)
    File.close(file)
  end

  defp generate_wallet_address(public) do
    pub_sha256_1 = :crypto.hash(:sha256, public) |> Base.encode16()
    pub_ripemd160 = :crypto.hash(:ripemd160, pub_sha256_1) |> Base.encode16()
    pub_netbytes = "00" <> pub_ripemd160
    pub_sha256_netbytes = :crypto.hash(:sha256, pub_netbytes) |> Base.encode16()
    pub_sha256_netbytes_2 = :crypto.hash(:sha256, pub_sha256_netbytes) |> Base.encode16()
    slice_four_bytes = pub_sha256_netbytes_2 |> to_string() |> String.slice(0..7)
    append_four_bytes_to_netbytes = pub_netbytes <> slice_four_bytes
    Base.decode16(append_four_bytes_to_netbytes) |> elem(1) |> :base58.binary_to_base58
  end

end
