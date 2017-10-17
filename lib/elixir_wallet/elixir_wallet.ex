defmodule Wallet do
  @moduledoc """
  This module is used for creation of the Wallet file. To inspect it use
  WalletCrypto.decrypt_wallet("wallet_file_name", "password", "mnemonic_phrase")
  """

  @doc """
  Creates a wallet file
  ## Examples
      iex> Wallet.create_wallet("pass")
      Use the following phrase as additional authentication
      when accessing you wallet:

      whisper edit clump violin blame few ancient casual
      sand trip update spring
  """
  @spec create_wallet(String.t()) :: String.t()
  def create_wallet(password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open(file, [:write])

    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)

    {private, public, _} = KeyPair.generate_root_seed(mnemonic_phrase,
                              "mnemonic" <> password,
                              iterations: 2048, digest: :sha512)

    address =  KeyPair.generate_wallet_address(public)

    IO.puts("Use the following phrase as additional authentication when accessing your wallet:
      \n#{mnemonic_phrase}")

    data = %{private_key: private, public: public, address: address}
    encrypted = WalletCrypto.encrypt_wallet(data, password, to_string(mnemonic_phrase))

    IO.binwrite(file, encrypted)
    File.close(file)
  end
end
