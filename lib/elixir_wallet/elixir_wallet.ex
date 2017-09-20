defmodule Wallet do

  def create_wallet(password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open file, [:write]
    {private, public, address} = KeyPair.keypair()
    data = %{private_key: private, public: public, address: address}
    phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    IO.puts("Use the following phrase as additional authentication when accessing your wallet:\n#{phrase}")
    encrypted = WalletCrypto.encrypt_wallet(data, password,phrase |> to_string)

    IO.binwrite(file, encrypted)
    File.close(file)
  end

end
