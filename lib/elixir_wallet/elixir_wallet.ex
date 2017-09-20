defmodule Wallet do

  def create_wallet(password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open file, [:write]
    {private, public, address} = KeyPair.keypair()
    data = %{private_key: private, public: public, address: address}
    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    seed = Mnemonic.generate_root_seed(mnemonic_phrase, "mnemonic" <> password, iterations: 2048, digest: :sha512)
    IO.inspect(seed)
    IO.puts("Use the following phrase as additional authentication when accessing your wallet:\n#{mnemonic_phrase}")
    encrypted = WalletCrypto.encrypt_wallet(data, password, mnemonic_phrase |> to_string)

    IO.binwrite(file, encrypted)
    File.close(file)
  end

end
