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

    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    create_wallet_file(mnemonic_phrase, password)

    IO.puts("Your wallet was created.
      \nUse the following phrase as additional authentication when accessing your wallet:
      \n#{mnemonic_phrase}")
  end

  @doc """
  Creates a wallet file from an existing mnemonic_phrase and password
  """
  @spec import_wallet(String.t(), String.t()) :: String.t()
  def import_wallet(mnemonic_phrase, password) do

    create_wallet_file(mnemonic_phrase, password)
    IO.puts("You have successfully imported a wallet")
  end

  defp create_wallet_file(mnemonic_phrase, password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open(file, [:write])

    {private, public, _} =
      KeyPair.generate_root_seed(mnemonic_phrase,
        "mnemonic" <> password,
        [iterations: 2048, digest: :sha512])

    address = KeyPair.generate_wallet_address(public)
    data = %{private_key: private, public: public, address: address}
    encrypted = WalletCrypto.encrypt_wallet(data, password, to_string(mnemonic_phrase))
    IO.binwrite(file, encrypted)
    File.close(file)
  end
end
