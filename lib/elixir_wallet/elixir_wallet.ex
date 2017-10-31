defmodule Wallet do
  require Logger

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
  def create_wallet(password \\ "") do

    mnemonic_phrase = Mnemonic.generate_phrase(GenerateIndexes.generate_indexes)
    save_wallet_file(mnemonic_phrase, password)

    Logger.info("Your wallet was created.")
    Logger.info("Use the following phrase as additional authentication when accessing your wallet:")
    Logger.info(mnemonic_phrase)
	IO.inspect mnemonic_phrase
  end

  @doc """
  Creates a wallet file from an existing mnemonic_phrase and password
  If the wallet was not password protected, just pass the mnemonic_phrase
  """
  @spec import_wallet(String.t(), String.t()) :: String.t()
  def import_wallet(mnemonic_phrase, password \\ "") do

    save_wallet_file(mnemonic_phrase, password)
    Logger.info("You have successfully imported a wallet")
  end

  def load_wallet_file(file_path, password) do
    case File.read(file_path) do
      {:ok, encrypted_data} ->
        mnemonic = Cypher.decrypt(encrypted_data, password)
        {:ok, "Your mnemonic phrase is: #{mnemonic}"}
      {:error, :enoent} ->
        {:error, "The file does not exist."}
      {:error, :eaccess} ->
        {:error, "Missing permision for reading the file,
        or for searching one of the parent directories."}
      {:error, :eisdir} ->
        {:error, "The named file is a directory."}
      {:error, :enotdir} ->
        {:error, "A component of the file name is not a directory."}
      {:error, :enomem} ->
        {:error, "There is not enough memory for the contents of the file."}
    end
  end

  defp save_wallet_file(mnemonic_phrase, password) do
    {{year, month, day}, {hours, minutes, seconds}} = :calendar.local_time()
    file = "wallet--#{year}-#{month}-#{day}-#{hours}-#{minutes}-#{seconds}"
    {:ok, file} = File.open(file, [:write])

    ## TODO: Get the password from the user
    encrypted = Cypher.encrypt(mnemonic_phrase, "password")
    IO.binwrite(file, encrypted)
    File.close(file)
  end

  def get_public_key(file_path, password) do
   {_, mnemonic_string} = load_wallet_file(file_path, password)
  
   [_,mnemonic] = String.split(mnemonic_string, ": ")
    
   KeyPair.generate_root_seed(mnemonic)
   |>
   elem(1)
  end  
  
  def get_address(file_path, password) do
   get_public_key(file_path, password)
   |>
   KeyPair.generate_wallet_address() 
  end
end